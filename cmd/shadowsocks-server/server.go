package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

var debug ss.DebugLog

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

func handleConnection(conn net.Conn, host string, timeout int) {
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
		debug.Printf("new client %s->%s\n", conn.RemoteAddr().String(), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", conn.RemoteAddr(), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

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
		debug.Printf("piping %s<->%s ota=%v", conn.RemoteAddr(), host, conn.(*ss.SecureConn).IsOta())
	}
	go ss.PipeThenClose(conn, remote, timeout)
	ss.PipeThenClose(remote, conn, timeout)
	closed = true
	return
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {

		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func serveTCP(ln *ss.Listener, timeout int) {
	defer ln.Close()
	for {
		conn, host, err := ln.Accept()
		if err != nil {
			if err == ss.ErrPacketOtaFailed {
				continue
			}
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		go handleConnection(conn, host, timeout)
	}
}

func run(conf ss.Config) {
	addrPadd := conf.ServerAddrPasswords()
	for addr, pass := range addrPadd {
		cipher, err := encrypt.NewCipher(conf.Method(), pass)
		if err != nil {
			log.Printf("Failed create cipher: %v\n", err)
		}
		ln, err := ss.Listen("tcp", addr, cipher, conf.Timeout(), conf.OTA())
		if err != nil {
			log.Printf("error listening port %v: %v\n", addr, err)
			os.Exit(1)
		}
		log.Printf("server listening port %v ...\n", addr)
		go serveTCP(ln, conf.Timeout())
	}
}

func serveUDP(SecurePacketConn *ss.SecurePacketConn) {
	defer SecurePacketConn.Close()
	buf := make([]byte, 4096)
	for {
		n, src, err := SecurePacketConn.ReadFrom(buf)
		if err != nil {
			if err == ss.ErrPacketOtaFailed {
				continue
			}
			debug.Printf("[udp]read error: %v\n", err)
			return
		}
		host, headerLen, compatibleMode, err := ss.UDPGetRequest(buf[:n], SecurePacketConn.IsOta())
		if err != nil {
			debug.Printf("[udp]faided to decode request: %v\n", err)
			continue
		}
		if compatibleMode {
			ss.ForwardUDPConn(SecurePacketConn.ForceOTA(), src, host, buf[:n], headerLen)
		} else {
			ss.ForwardUDPConn(SecurePacketConn, src, host, buf[:n], headerLen)
		}
	}
}

func runUDP(conf ss.Config) {
	addrPadd := conf.ServerAddrPasswords()
	for addr, pass := range addrPadd {
		log.Printf("listening udp port %v\n", addr)
		cipher, err := encrypt.NewCipher(conf.Method(), pass)
		if err != nil {
			log.Printf("Failed create cipher: %v\n", err)
		}
		SecurePacketConn, err := ss.ListenPacket("udp", addr, cipher, conf.OTA())
		if err != nil {
			log.Printf("error listening packetconn %v: %v\n", addr, err)
			os.Exit(1)
		}
		go serveUDP(SecurePacketConn)
	}
}

func checkConfig(config ss.Config) error {
	addrPass := config.ServerAddrPasswords()
	for addr, pass := range addrPass {
		if _, portStr, err := net.SplitHostPort(addr); err == nil {
			if port, err := strconv.Atoi(portStr); err != nil || port == 0 || pass == "" {
				return fmt.Errorf("given config is invalid: address(%s) password(%s)", addr, pass)
			}
		} else {
			return fmt.Errorf("given config is invalid: address(%s) password(%s)", addr, pass)
		}
	}
	return nil
}

type cmdConfig struct {
	CPassword   string
	CServerPort int
	CTimeout    int
	CMethod     string
	COTA        bool
}

func (c *cmdConfig) ServerAddrPasswords() map[string]string {
	return map[string]string{":" + strconv.Itoa(c.CServerPort): c.CPassword}
}
func (c *cmdConfig) RemoteAddrPasswords() [][]string {
	return nil
}
func (c *cmdConfig) LocalAddr() string {
	return ""
}
func (c *cmdConfig) OTA() bool {
	return c.COTA
}
func (c *cmdConfig) Password() string {
	return c.Password()
}

func (c *cmdConfig) Timeout() int {
	return c.CTimeout
}

func (c *cmdConfig) Method() string {
	return c.CMethod
}

func main() {
	var printVer bool
	var core int
	var err error
	var udp bool
	var configFile string
	var config ss.Config
	log.SetOutput(os.Stdout)
	cmd := &cmdConfig{}

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmd.CPassword, "k", "", "password")
	flag.IntVar(&cmd.CServerPort, "p", 0, "server port")
	flag.IntVar(&cmd.CTimeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmd.CMethod, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.Parse()
	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}
	ss.SetDebug(debug)
	if strings.HasSuffix(cmd.CMethod, "-auth") {
		cmd.CMethod = cmd.CMethod[:len(cmd.CMethod)-5]
		cmd.COTA = true
	}
	if cmd.CMethod == "" {
		cmd.CMethod = "aes-256-cfb"
	}
	if cmd.CPassword != "" {
		fmt.Println("Using commandline para.")
		config = cmd
	} else {
		config, err = ss.ParseConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
	}
	if err = encrypt.CheckCipherMethod(config.Method()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = checkConfig(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	go run(config)
	if udp {
		go runUDP(config)
	}
	waitSignal()
}
