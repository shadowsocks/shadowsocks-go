package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

func handleConnection(conn net.Conn, host string, timeout int) {
	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		ss.Logger.Info("Number of client connections reaches ", zap.Int("count", nextLogConnCnt))
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	ss.Logger.Info("new client ", zap.Stringer("remote", conn.RemoteAddr()),
		zap.Stringer("local", conn.LocalAddr()))
	closed := false
	defer func() {
		ss.Logger.Info("close pipe:", zap.Stringer("remote", conn.RemoteAddr()),
			zap.String("host", host))
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	ss.Logger.Info("connecting", zap.String("host", host))
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			ss.Logger.Error("dial error:", zap.Error(err))
		} else {
			ss.Logger.Error("error connecting to host:", zap.String("host", host), zap.Error(err))
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	ss.Logger.Info("piping remote to host:", zap.Stringer("remote", conn.RemoteAddr()),
		zap.String("host", host), zap.Bool("OTA", conn.(*ss.SecureConn).IsOta()))
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
			ss.Logger.Info("receive the KILL -HUP")
		} else {
			// is this going to happen?
			ss.Logger.Error("Caught signal and exit", zap.String("signal", fmt.Sprint(sig)))
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
			ss.Logger.Error("serve TCP accept error", zap.Error(err))
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
			ss.Logger.Error("Failed create cipher", zap.Error(err))
		}
		ln, err := ss.Listen("tcp", addr, cipher, conf.Timeout(), conf.OTA())
		if err != nil {
			ss.Logger.Error("error listening port", zap.String("port", addr), zap.Error(err))
			os.Exit(1)
		}
		ss.Logger.Info("server listening port", zap.String("port", addr))
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
			ss.Logger.Error("[udp]read error", zap.Error(err))
			return
		}
		host, headerLen, compatibleMode, err := ss.UDPGetRequest(buf[:n], SecurePacketConn.IsOta())
		if err != nil {
			ss.Logger.Error("[udp]faided to decode request", zap.Error(err))
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
		ss.Logger.Info("listening udp", zap.String("port", addr))
		cipher, err := encrypt.NewCipher(conf.Method(), pass)
		if err != nil {
			ss.Logger.Error("Failed create cipher", zap.Error(err))
		}
		SecurePacketConn, err := ss.ListenPacket("udp", addr, cipher, conf.OTA())
		if err != nil {
			ss.Logger.Error("error listening packetconn ", zap.String("addrsee", addr), zap.Error(err))
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
				ss.Logger.Error("given config is invalid", zap.String("address", addr),
					zap.String("password", pass))
				return fmt.Errorf("given config is invalid: address(%s) password(%s)", addr, pass)
			}
		} else {
			ss.Logger.Error("given config is invalid", zap.String("address", addr),
				zap.String("password", pass))
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
	cmd := &cmdConfig{}

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmd.CPassword, "k", "", "password")
	flag.IntVar(&cmd.CServerPort, "p", 0, "server port")
	flag.IntVar(&cmd.CTimeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmd.CMethod, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.StringVar(&ss.Level, "l", "info", "given the logger level for ss to log out")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.Parse()
	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}
	ss.NewLogger()

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
