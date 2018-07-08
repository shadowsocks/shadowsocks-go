package main

import (
	"sync"
	"net"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

type PortListener struct {
	password string
	listener net.Listener
}

type UDPListener struct {
	password string
	listener *net.UDPConn
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
	trafficStats map[string]int64
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.trafficStats[port] = 0
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener *net.UDPConn) {
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
	delete(pm.trafficStats, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

func (pm *PasswdManager) addTraffic(port string, n int) {
	pm.Lock()
	pm.trafficStats[port] = pm.trafficStats[port] + int64(n)
	pm.Unlock()
	return
}

func (pm *PasswdManager) getTrafficStats() map[string]int64 {
	pm.Lock()
	traffics := make(map[string]int64)
	for k, v := range pm.trafficStats {
		traffics[k] = v
	}
	pm.Unlock()
	return traffics
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	go run(&passwdManager, port, password)
	if udp {
		pl, ok := pm.getUDP(port)
		if !ok {
			log.Printf("new udp port %s added\n", port)
		} else {
			if pl.password == password {
				return
			}
			log.Printf("closing udp port %s to update password\n", port)
			pl.listener.Close()
		}
		go runUDP(pm, port, password)
	}
}

func (pm *PasswdManager) updatePasswd(config *ss.Config, configFile string) {
	log.Println("updating password")
	newConfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldConfig := config
	config = newConfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		pm.updatePortPasswd(port, passwd)
		if oldConfig.PortPassword != nil {
			delete(oldConfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port := range oldConfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		pm.del(port)
	}
	log.Println("password updated")
}

func run(pm *PasswdManager, port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	pm.add(port, password, ln)
	var cipher *ss.Cipher
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(pm, ss.NewConn(conn, cipher.Copy()), port)
	}
}

func runUDP(pm *PasswdManager, port, password string) {
	var cipher *ss.Cipher
	portInt, _ := strconv.Atoi(port)
	log.Printf("listening udp port %v\n", port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: portInt,
	})
	pm.addUDP(port, password, conn)
	if err != nil {
		log.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer conn.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}
	SecurePacketConn := ss.NewSecurePacketConn(conn, cipher.Copy())
	for {
		if err := ss.ReadAndHandleUDPReq(SecurePacketConn, func(traffic int) {
			pm.addTraffic(port, traffic)
		}); err != nil {
			debug.Printf("udp read error: %v\n", err)
			return
		}
	}
}

func handleConnection(pm *PasswdManager, conn *ss.Conn, port string) {
	var host string

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", sanitizeAddr(conn.RemoteAddr()), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	host, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr(), err)
		closed = true
		return
	}
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	if debug {
		debug.Printf("piping %s<->%s", sanitizeAddr(conn.RemoteAddr()), host)
	}
	go func() {
		ss.PipeThenClose(conn, remote, func(Traffic int) {
			pm.addTraffic(port, Traffic)
		})
	}()

	ss.PipeThenClose(remote, conn, func(Traffic int) {
		pm.addTraffic(port, Traffic)
	})

	closed = true
	return
}
