package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"os/signal"
	"syscall"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	// lenHmacSha1 = 10
)

var debug ss.DebugLog
var sanitizeIps bool
var udp bool
var managerAddr string

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

var passwdManager = PasswdManager{
	portListener: map[string]*PortListener{},
	udpListener:  map[string]*UDPListener{},
	trafficStats: map[string]int64{},
}

var configFile string
var config *ss.Config

func main() {
	log.SetOutput(os.Stdout)

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
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar((*bool)(&sanitizeIps), "A", false, "anonymize client ip addresses in all output")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.StringVar(&managerAddr, "manager-address", "", "shadowsocks manager listening address")
	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		go run(&passwdManager, port, password)
		if udp {
			go runUDP(&passwdManager, port, password)
		}
	}

	if managerAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", managerAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't resolve address: ", err)
			os.Exit(1)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error listening:", err)
			os.Exit(1)
		}
		log.Printf("manager listening udp addr %v ...\n", managerAddr)
		defer conn.Close()
		go managerDaemon(conn)
	}

	waitSignal()
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			passwdManager.updatePasswd(config, configFile)
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}
