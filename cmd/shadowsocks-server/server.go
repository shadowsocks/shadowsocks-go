package main

import (
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"time"
)

var udp bool
var Logger = ss.Logger
var UDPTimeout time.Duration

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

func handleConnection(conn *ss.Conn) {
	var host ss.Addr

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		Logger.Infof("Number of client connections reaches %d", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	Logger.Infof("new client %s->%s", conn.RemoteAddr().String(), conn.LocalAddr())
	closed := false
	defer func() {
		Logger.Infof("closed pipe %s<->%s", conn.RemoteAddr(), host)
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	host, err := ss.ReadAddr(conn)
	if err != nil {
		ss.Logger.Println("socks read addr error:", err)
		return
	}

	Logger.Info("connecting ", host)
	remote, err := net.Dial("tcp", host.String())
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Logger.Fields(ss.LogFields{
				"host": host,
				"err": err,
			}).Error("dial error")
		} else {
			Logger.Fields(ss.LogFields{
				"host": host,
				"err": err,
			}).Error("error connecting")
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	Logger.Infof("piping %s<->%s", conn.RemoteAddr(), host)

	ss.PipeStream(conn, remote, conn.Buffer)

	return
}

type PortListener struct {
	password string
	listener net.Listener
}

type UDPListener struct {
	password string
	listener net.PacketConn
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener net.PacketConn) {
	pm.Lock()
	pm.udpListener[port] = &UDPListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) getUDP(port string) (pl *UDPListener, ok bool) {
	pm.Lock()
	pl, ok = pm.udpListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	if udp {
		upl, ok := pm.getUDP(port)
		if !ok {
			return
		}
		upl.listener.Close()
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		Logger.Fields(ss.LogFields{"port": port}).Warn("new port added")
	} else {
		if pl.password == password {
			return
		}
		Logger.Warnf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password)
	if udp {
		pl, _ := pm.getUDP(port)
		pl.listener.Close()
		go runUDP(port, password)
	}
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}, udpListener: map[string]*UDPListener{}}

func updatePasswd() {
	Logger.Info("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		Logger.Fields(ss.LogFields{
			"configFile": configFile,
			"err": err,
		}).Error("error parsing config file to update password")
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port := range oldconfig.PortPassword {
		Logger.Infof("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	Logger.Info("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			Logger.Warnf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		Logger.Fields(ss.LogFields{
			"port": port,
			"err": err,
		}).Error("error listening port")
		os.Exit(1)
	}
	passwdManager.add(port, password, ln)
	var cipher ss.Cipher
	ss.Logger.Printf("listening tcp port %v", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			Logger.Fields(ss.LogFields{"err": err}).Error("accept error")
			// listener maybe closed to update password
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			Logger.Info("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				Logger.Fields(ss.LogFields{
					"port": port,
					"err": err,
				}).Error("Error generating cipher for port")
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher))
	}
}

func runUDP(port, password string) {
	var cipher ss.Cipher
	port_i, _ := strconv.Atoi(port)
	addr := &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	}
	ss.Logger.Printf("listening udp port %v", port)
	c, err := net.ListenPacket("udp", addr.String())
	passwdManager.addUDP(port, password, c)
	if err != nil {
		ss.Logger.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer c.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		ss.Logger.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		c.Close()
	}
	SecurePacketConn := ss.NewSecurePacketConn(c, cipher)

	nm := ss.NewNATmap(UDPTimeout)
	buf := SecurePacketConn.Buffer
	for {
		n, raddr, err := SecurePacketConn.ReadFrom(buf)
		if err != nil {
			ss.Logger.Warnf("UDP remote read error: %v", err)
			continue
		}

		tgtAddr := ss.SplitAddr(buf[:n])
		if tgtAddr == nil {
			ss.Logger.Warnf("failed to split target address from packet: %q", buf[:n])
			continue
		}

		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			ss.Logger.Warnf("failed to resolve target UDP address: %v", err)
			continue
		}

		payload := buf[len(tgtAddr):n]

		pc := nm.Get(raddr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				ss.Logger.Warnf("UDP remote listen error: %v", err)
				continue
			}

			nm.Add(raddr, SecurePacketConn, pc, true)
		}

		_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
		if err != nil {
			ss.Logger.Warnf("UDP remote write error: %v", err)
			continue
		}
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			ss.Logger.Fatal("must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			ss.Logger.Fatal("given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config

func main() {
	//log.SetOutput(os.Stdout)

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar(&udp, "udp", false, "UDP Relay")
	flag.BoolVar((*bool)(&ss.DebugLog), "debug", false, "print debug message")
	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		ss.Logger.Errorf("error reading %s: %v\n", configFile, err)
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
		ss.Logger.Warn("use aes-256-cfb method, cause not specify method")
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		//fmt.Fprintln(os.Stderr, err)
		ss.Logger.Fields(ss.LogFields{
			"method": config.Method,
			"err": err,
		}).Error("check cipher method error")
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		go run(port, password)
		if udp {
			go runUDP(port, password)
		}
	}

	waitSignal()
}
