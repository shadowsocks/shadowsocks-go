package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/miekg/dns"
	"github.com/shadowsocks/shadowsocks-go/encrypt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	logCntDelta int32 = 100
)

var (
	connCnt        int32
	nextLogConnCnt = logCntDelta
	// DNSClient give out the dns client for use
	DNSClient *dns.Client
	// DNSresolver give out the dns host to request
	DNSresolver func(host string) ([]string, error)
	enableDNS   bool
)

// handleConnection forward the request to the destination
func handleConnection(conn net.Conn, timeout int) {
	// first do the decode for ss protocol
	host, err := ss.GetRequest(conn)
	if err != nil {
		ss.Logger.Error("ss server get request failed", zap.Stringer("src", conn.RemoteAddr()), zap.Error(err))
		return
	}
	ss.Logger.Info("ss server accept the ss request", zap.Stringer("src", conn.RemoteAddr()), zap.String("dst", host))

	atomic.AddInt32(&connCnt, 1)
	defer atomic.AddInt32(&connCnt, -1)
	if atomic.LoadInt32(&connCnt)-nextLogConnCnt >= 0 {
		ss.Logger.Warn("Number of client connections reaches", zap.Int32("count", nextLogConnCnt))
		nextLogConnCnt += logCntDelta
	}

	// do dns resolve
	if enableDNS {
		hostname := strings.Split(host, ":")
		answers, err := DNSresolver(hostname[0])
		if err != nil {
			ss.Logger.Error("error in resolve dns, resolver returned error", zap.Error(err))
		} else if len(hostname) != 2 || len(answers) == 0 {
			ss.Logger.Error("error in resolve dns, request illegal")
		} else {
			ss.Logger.Info("dns look up get response", zap.String("host", hostname[0]), zap.Strings("A record", answers))
			// use the first hostname to request by default
			for _, v := range answers {
				if v != "" {
					host = net.JoinHostPort(v, hostname[1])
					break
				}
			}
		}
	}

	// request the remote
	ss.Logger.Debug("connecting to the request host", zap.String("host", host))
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
	tcpremote, ok := remote.(*net.TCPConn)
	if !ok {
		//TODO
		return
	}

	tcpremote.SetKeepAlive(true)

	ss.Logger.Debug("piping remote to host:", zap.Stringer("remote", conn.RemoteAddr()), zap.String("host", host))

	defer conn.Close()
	defer remote.Close()
	// NOTICE: timeout should be setted carefully to avoid cutting the correct tcp stream
	if timeout > 0 {
		ss.Logger.Info("connection timeout setted", zap.Int("timeout", timeout))
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		remote.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}

	// close the server at the right time
	wg := sync.WaitGroup{}
	wg.Add(1)
	go ss.PipeThenClose(conn.(*ss.SecureConn), tcpremote, wg.Done)
	ss.PipeThenClose(tcpremote, conn.(*ss.SecureConn), func() {})
	wg.Wait()

	return
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for {
		s := <-sigChan
		switch s {
		case syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
			ss.Logger.Info("Caught signal , shuting down", zap.Stringer("signal", s))
			os.Exit(0)
		default:
			ss.Logger.Error("Caught meaning lease signal", zap.Stringer("signal", s))
		}
	}
}

// serveTCP accept incoming request and handle
func serveTCP(ln net.Listener, timeout int) {
	defer ln.Close()
	for {
		// accept should not be blocked, so here just return a ss warped connection
		sconn, err := ln.Accept()
		if err != nil {
			ss.Logger.Error("error in ss server accept connection", zap.Error(err))
			continue
		}
		go handleConnection(sconn, timeout)
	}
}

// start the ss remote servers listen on given ports
func run(conf *ss.Config) {
	for addr, pass := range conf.PortPassword {
		cipher, err := encrypt.PickCipher(conf.Method, pass)
		if err != nil {
			ss.Logger.Fatal("Failed create cipher", zap.Error(err))
		}
		// listen on :addr ,so makesure you have the enough priority to do this
		ln, err := ss.SecureListen("tcp", net.JoinHostPort("", addr), cipher.Copy(), conf.Timeout)
		if err != nil {
			ss.Logger.Fatal("error listening port", zap.String("port", addr), zap.Error(err))
		}
		ss.Logger.Info("server listening port", zap.String("port", addr))
		go serveTCP(ln, conf.Timeout)
	}
}

// serveUDP read from the udp listen and forward the request
// only do the forward here, the backward doing in another sequence
func serveUDP(servein net.PacketConn) {
	defer servein.Close()
	buf := make([]byte, 4096)
	for {
		n, srcAddr, err := servein.ReadFrom(buf)
		if err != nil {
			ss.Logger.Error("[udp]read from server packet listen error", zap.Error(err))
			// TODO should this be continue?
			// warning may better
			continue
		}
		// TODO handle the connection : when to close the conn
		// for loop is right?
		go ss.ForwardUDPConn(servein, srcAddr, buf[:n])
	}
}

// strat a server for each port & password
func runUDP(conf *ss.Config) {
	addrPadd := conf.PortPassword
	for addr, pass := range addrPadd {
		ss.Logger.Info("[UDP] listening udp", zap.String("port", addr))
		cipher, err := encrypt.PickCipher(conf.Method, pass)
		if err != nil {
			ss.Logger.Error("[UDP] failed create cipher", zap.Error(err))
			os.Exit(1)
		}
		SecurePacketConn, err := ss.SecureListenPacket("udp", ":"+addr, cipher, conf.Timeout)
		if err != nil {
			ss.Logger.Error("[UDP] error listening packetconn", zap.String("address", addr), zap.Error(err))
			os.Exit(1)
		}
		go serveUDP(SecurePacketConn)
	}
}

func checkConfig(config *ss.Config) error {
	//server -- server port should match
	//port -- port password should patch
	if config.Password == "" && config.PortPassword == nil {
		return errors.New("missing passwd for config")
	}
	if len(config.GetServerPortArray()) != len(config.GetPasswordArray()) {
		return errors.New("server port array and password array mismatching")
	}

	if config.DNSServer != "" {
		enableDNS = true
		ss.Logger.Info("setting the dns server", zap.String("dns", config.DNSServer))
		initializeDNSResolver(config.DNSServer)
	}
	return nil
}

func main() {
	var err error
	var udp, printVer bool
	var Timeout, core, matrixport int
	var ServerPort, configFile, Password, Method, DNSServer string

	var config *ss.Config

	flag.BoolVar(&printVer, "v", false, "print version")
	flag.StringVar(&configFile, "config", "", "specify config file")
	flag.StringVar(&Password, "passwd", "", "password")
	flag.StringVar(&ServerPort, "port", "", "server port")
	flag.IntVar(&Timeout, "timeout", 300, "timeout in seconds")
	flag.StringVar(&Method, "method", "aes-256-cfb", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.IntVar(&matrixport, "pprof", 0, "set the metrix port to Enable the pprof and matrix(TODO), keep it 0 will disable this feature")
	flag.StringVar(&ss.Level, "level", "info", "given the logger level for ss to logout info, can be set in debug info warn error")
	flag.BoolVar(&udp, "enable_udp", false, "diasbale UDP service, enable by default")
	flag.StringVar(&DNSServer, "dns", "", "set the dns server for server, default will use the system dns server in /etc/resolv.conf")
	flag.Parse()
	if !flag.Parsed() {
		flag.Usage()
		os.Exit(0)
	}
	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	// init the logger
	ss.SetLogger()
	ss.Logger.Info("Starting shadowsocks remote server")

	// set the pprof
	if matrixport > 0 {
		go http.ListenAndServe(":"+strconv.Itoa(matrixport), nil)
	}

	// set the options for the config new
	var opts []ss.ConfOption

	// choose the encrypt method then check
	if Method == "" {
		Method = "aes-256-cfb"
		opts = append(opts, ss.WithEncryptMethod("aes-256-cfb"))
	}
	if err = encrypt.CheckCipherMethod(Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	opts = append(opts, ss.WithEncryptMethod(Method))

	// set the dns server
	if DNSServer != "" {
		opts = append(opts, ss.WithDNSServer(DNSServer))
	}

	// check the passwd if not set
	if Password != "" {
		opts = append(opts, ss.WithPassword(Password))
		if ServerPort != "" {
			opts = append(opts, ss.WithServerPort(ServerPort))
			opts = append(opts, ss.WithPortPassword(ServerPort, Password))
		}
	}

	config = ss.NewConfig(opts...)

	// parse the config from the config file
	if configFile != "" {
		ss.Logger.Info("ss server loading config file", zap.String("path", configFile))
		config, err = ss.ParseConfig(configFile)
		if err != nil {
			ss.Logger.Fatal("error in reading the ss config file", zap.String("path", configFile), zap.Error(err))
		}
	}
	ss.Logger.Debug("show the ss config", zap.Stringer("config", config))

	// check the config
	if err = checkConfig(config); err != nil {
		ss.Logger.Error("error in chack config", zap.Error(err))
		os.Exit(1)
	}

	// if core is defined ,then set the max proecssor
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}

	// start the shadowsocks server
	go run(config)
	if udp { //enable udp if diable_udp not set
		go runUDP(config)
	}

	// wait for the ctrl-c signal
	waitSignal()
}

func initializeDNSResolver(server string) {
	if server == "" {
		ss.Logger.Fatal("error in set dns resolver, server is nil")
		return
	}

	c := dns.Client{}
	m := dns.Msg{}

	DNSresolver = func(host string) ([]string, error) {
		ansers := make([]string, 1, 4)

		m.SetQuestion(host+".", dns.TypeA)
		r, t, err := c.Exchange(&m, server+":53")
		if err != nil {
			return nil, err
		}
		ss.Logger.Debug("DNS lookup domain cost", zap.Stringer("time", t))
		if len(r.Answer) == 0 {
			return nil, errors.New("No results returned")
		}
		for _, ans := range r.Answer {
			if ans.Header().Rrtype == dns.TypeA {
				ansers = append(ansers, ans.(*dns.A).A.String())
			}
		}
		return ansers, nil
	}
}
