package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"strings"
)

var UDPTun string
var UDPTimeout time.Duration

func init() {
	rand.Seed(time.Now().Unix())
}

type ServerCipher struct {
	server string
	cipher ss.Cipher
}

var servers struct {
	srvCipher []*ServerCipher
	failCnt   []int // failed connection count
}

func parseServerConfig(config *ss.Config) {
	hasPort := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		return port != ""
	}

	if len(config.ServerPassword) == 0 {
		method := config.Method

		// only one encryption table
		cipher, err := ss.NewCipher(method, config.Password)
		if err != nil {
			ss.Logger.Fatal("Failed generating ciphers:", err)
		}
		srvPort := strconv.Itoa(config.ServerPort)
		srvArr := config.GetServerArray()
		n := len(srvArr)
		servers.srvCipher = make([]*ServerCipher, n)

		for i, s := range srvArr {
			if hasPort(s) {
				ss.Logger.Println("ignore server_port option for server", s)
				servers.srvCipher[i] = &ServerCipher{s, cipher}
			} else {
				servers.srvCipher[i] = &ServerCipher{net.JoinHostPort(s, srvPort), cipher}
			}
		}
	} else {
		// multiple servers
		n := len(config.ServerPassword)
		servers.srvCipher = make([]*ServerCipher, n)

		cipherCache := make(map[string]ss.Cipher)
		i := 0
		for _, serverInfo := range config.ServerPassword {
			if len(serverInfo) < 2 || len(serverInfo) > 3 {
				ss.Logger.Fatalf("server %v syntax error\n", serverInfo)
			}
			server := serverInfo[0]
			passwd := serverInfo[1]
			encmethod := ""
			if len(serverInfo) == 3 {
				encmethod = serverInfo[2]
			}
			if !hasPort(server) {
				ss.Logger.Fatalf("no port for server %s\n", server)
			}
			// Using "|" as delimiter is safe here, since no encryption
			// method contains it in the name.
			cacheKey := encmethod + "|" + passwd
			cipher, ok := cipherCache[cacheKey]
			if !ok {
				var err error
				cipher, err = ss.NewCipher(encmethod, passwd)
				if err != nil {
					ss.Logger.Fatal("Failed generating ciphers:", err)
				}
				cipherCache[cacheKey] = cipher
			}
			servers.srvCipher[i] = &ServerCipher{server, cipher}
			i++
		}
	}
	servers.failCnt = make([]int, len(servers.srvCipher))
	for _, se := range servers.srvCipher {
		ss.Logger.Println("available remote server", se.server)
	}
	return
}

func connectToServer(serverId int, addr ss.Addr) (remote *ss.Conn, err error) {
	se := servers.srvCipher[serverId]
	remote, err = ss.DialWithRawAddr(addr, se.server, se.cipher)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"addr": addr,
			"server": se.server,
			"err": err,
		}).Warn("error connecting to shadowsocks server")
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}
	ss.Logger.Fields(ss.LogFields{
		"addr": addr,
		"server": se.server,
	}).Info("connected to server")
	servers.failCnt[serverId] = 0
	return
}

// Connection to the server in the order specified in the config. On
// connection failure, try the next server. A failed server will be tried with
// some probability according to its fail count, so we can discover recovered
// servers.
func createServerConn(addr ss.Addr) (remote *ss.Conn, err error) {
	const baseFailCnt = 20
	n := len(servers.srvCipher)
	skipped := make([]int, 0)
	for i := 0; i < n; i++ {
		// skip failed server, but try it with some probability
		if servers.failCnt[i] > 0 && rand.Intn(servers.failCnt[i]+baseFailCnt) != 0 {
			skipped = append(skipped, i)
			continue
		}
		remote, err = connectToServer(i, addr)
		if err == nil {
			return
		}
	}
	// last resort, try skipped servers, not likely to succeed
	for _, i := range skipped {
		remote, err = connectToServer(i, addr)
		if err == nil {
			return
		}
	}
	return nil, err
}

func handleConnection(conn net.Conn) {
	ss.Logger.Info("socks connect from ", conn.RemoteAddr().String())
	closed := false
	defer func() {
		if !closed {
			ss.Logger.Info("close socks connect from ", conn.RemoteAddr().String())
			conn.Close()
		}
	}()

	var err error = nil
	addr, err := ss.Handshake(conn)
	if err != nil {
		ss.Logger.Println("socks handshake:", err)
		return
	}

	remote, err := createServerConn(addr) // connect to ss server and send request from local
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"err": err,
		}).Warn("check createServerConn error")
		if len(servers.srvCipher) > 1 {
			ss.Logger.Fields(ss.LogFields{
				"addr": addr,
				"err": err,
			}).Error("Failed connect to all avaiable shadowsocks server")
		}
		return
	}
	defer func() {
		if !closed {
			ss.Logger.Info("close socks connect from ", remote.RemoteAddr().String())
			remote.Close()
		}
	}()

	ss.PipeStream(conn, remote, remote.Buffer)
	ss.Logger.Infof("closed connection to %s", addr)
}

func run(listenAddr string) { // listening from local request
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		ss.Logger.Fatal(err)
	}
	ss.Logger.Fields(ss.LogFields{"listenAddr": listenAddr}).Info("starting local socks5 server ...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			ss.Logger.Fields(ss.LogFields{"err": err}).Warn("accept error")
			continue
		}
		go handleConnection(conn)
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.Server != nil && config.ServerPort != 0 &&
		config.LocalPort != 0 && config.Password != ""
}

func main() {
	//Logger.SetOutput(os.Stdout)

	var configFile, cmdServer, cmdLocal string
	var cmdConfig ss.Config
	var printVer bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdServer, "s", "", "server address")
	flag.StringVar(&cmdLocal, "b", "", "local address, listen only to this address if specified")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar((*bool)(&ss.DebugLog), "debug", false, "print debug message")
	//flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.StringVar(&UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.DurationVar(&UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	cmdConfig.Server = cmdServer

	exists, err := ss.IsFileExists(configFile)
	// If no config file in current directory, try search it in the binary directory
	// Note there's no portable way to detect the binary directory.
	binDir := path.Dir(os.Args[0])
	if (!exists || err != nil) && binDir != "" && binDir != "." {
		oldConfig := configFile
		configFile = path.Join(binDir, "config.json")
		ss.Logger.Printf("%s not found, try config file %s\n", oldConfig, configFile)
	}

	config, err := ss.ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if len(config.ServerPassword) == 0 {
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify server address, password and both server/local port")
			os.Exit(1)
		}
	} else {
		if config.Password != "" || config.ServerPort != 0 || config.GetServerArray() != nil {
			fmt.Fprintln(os.Stderr, "given server_password, ignore server, server_port and password option:", config)
		}
		if config.LocalPort == 0 {
			fmt.Fprintln(os.Stderr, "must specify local port")
			os.Exit(1)
		}
	}

	parseServerConfig(config)

	if UDPTun != "" {
		for _, tun := range strings.Split(UDPTun, ",") {
			p := strings.Split(tun, "=")
			go RunUDP(p[0], p[1])
		}
	}
	run(cmdLocal + ":" + strconv.Itoa(config.LocalPort))
}
//////////////////////////////////////////////////////////////////////////////////////

func RunUDP(laddr, target string) {
	var err error

	// parse target
	tgt := ss.ParseAddr(target)
	if tgt == nil {
		err = fmt.Errorf("invalid target address: %q", target)
		ss.Logger.Warnf("UDP target address error: %v", err)
		return
	}

	// local listening
	c, err := net.ListenPacket("udp", laddr)
	if err != nil {
		ss.Logger.Warnf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	// get ss server addr
	srvAddr, cipher, err := createUDPServerConn() // connect to ss server and send request from local
	if err != nil {
		if len(servers.srvCipher) > 1 {
			ss.Logger.Fields(ss.LogFields{
				"err": err,
			}).Error("Failed connect to all avaiable shadowsocks server")
		}
		return
	}
	// pack packet listener with cipher
	SecurePacketConn := ss.NewSecurePacketConn(c, cipher)

	nm := ss.NewNATmap(UDPTimeout)
	buf := SecurePacketConn.Buffer
	copy(buf, tgt)

	ss.Logger.Infof("UDP tunnel %s <-> %s <-> %s", laddr, srvAddr.String(), target)
	for {
		// read plaintext request from client
		n, raddr, err := c.ReadFrom(buf[len(tgt):])
		if err != nil {
			ss.Logger.Warnf("UDP local read error: %v", err)
			continue
		}

		// try to get data from cache
		pc := nm.Get(raddr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				ss.Logger.Warnf("UDP local listen error: %v", err)
				continue
			}

			pc = ss.NewSecurePacketConn(pc, cipher)
			nm.Add(raddr, c, pc, false)
		}

		_, err = pc.WriteTo(buf[:len(tgt)+n], srvAddr)
		if err != nil {
			ss.Logger.Warnf("UDP local write error: %v", err)
			continue
		}
	}
}

func connectToUDPServer(serverId int) (srvAddr *net.UDPAddr, err error) {
	se := servers.srvCipher[serverId]
	srvAddr, err = net.ResolveUDPAddr("udp", se.server)
	if err != nil {
		ss.Logger.Warnf("UDP server address error: %v", err)
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}

	servers.failCnt[serverId] = 0
	return
}

// Connection to the server in the order specified in the config. On
// connection failure, try the next server. A failed server will be tried with
// some probability according to its fail count, so we can discover recovered
// servers.
func createUDPServerConn() (srvAddr *net.UDPAddr, cipher ss.Cipher, err error) {
	const baseFailCnt = 20
	n := len(servers.srvCipher)
	skipped := make([]int, 0)
	for i := 0; i < n; i++ {
		// skip failed server, but try it with some probability
		if servers.failCnt[i] > 0 && rand.Intn(servers.failCnt[i]+baseFailCnt) != 0 {
			skipped = append(skipped, i)
			continue
		}

		srvAddr, err = connectToUDPServer(i)
		if err == nil {
			cipher = servers.srvCipher[i].cipher
			return
		}
	}

	return
}