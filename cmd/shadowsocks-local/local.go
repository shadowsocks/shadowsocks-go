package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"strings"
)

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)
//var leakyBuf *ss.LeakyBufType
var Logger = ss.Logger

var udp bool
var UDPTun string
var UDPTimeout time.Duration

func init() {
	rand.Seed(time.Now().Unix())
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)

	var n int
	ss.SetReadTimeout(conn)
	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	ss.SetReadTimeout(conn)
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	//if ss.DebugLog {
		switch buf[idType] {
		case typeIPv4:
			host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6:
			host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm:
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	//}

	return
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
			Logger.Fatal("Failed generating ciphers:", err)
		}
		srvPort := strconv.Itoa(config.ServerPort)
		srvArr := config.GetServerArray()
		n := len(srvArr)
		servers.srvCipher = make([]*ServerCipher, n)

		for i, s := range srvArr {
			if hasPort(s) {
				Logger.Println("ignore server_port option for server", s)
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
				Logger.Fatalf("server %v syntax error\n", serverInfo)
			}
			server := serverInfo[0]
			passwd := serverInfo[1]
			encmethod := ""
			if len(serverInfo) == 3 {
				encmethod = serverInfo[2]
			}
			if !hasPort(server) {
				Logger.Fatalf("no port for server %s\n", server)
			}
			// Using "|" as delimiter is safe here, since no encryption
			// method contains it in the name.
			cacheKey := encmethod + "|" + passwd
			cipher, ok := cipherCache[cacheKey]
			if !ok {
				var err error
				cipher, err = ss.NewCipher(encmethod, passwd)
				if err != nil {
					Logger.Fatal("Failed generating ciphers:", err)
				}
				cipherCache[cacheKey] = cipher
			}
			servers.srvCipher[i] = &ServerCipher{server, cipher}
			i++
		}
	}
	servers.failCnt = make([]int, len(servers.srvCipher))
	for _, se := range servers.srvCipher {
		Logger.Println("available remote server", se.server)
	}
	return
}

func connectToServer(serverId int, rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	se := servers.srvCipher[serverId]
	remote, err = ss.DialWithRawAddr(rawaddr, se.server, se.cipher)
	if err != nil {
		Logger.Fields(ss.LogFields{
			"rawaddr": rawaddr,
			"rawaddr_str": string(rawaddr),
			"server": se.server,
			"err": err,
		}).Warn("error connecting to shadowsocks server")
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}
	Logger.Fields(ss.LogFields{
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
func createServerConn(rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	const baseFailCnt = 20
	n := len(servers.srvCipher)
	skipped := make([]int, 0)
	for i := 0; i < n; i++ {
		// skip failed server, but try it with some probability
		if servers.failCnt[i] > 0 && rand.Intn(servers.failCnt[i]+baseFailCnt) != 0 {
			skipped = append(skipped, i)
			continue
		}
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	// last resort, try skipped servers, not likely to succeed
	for _, i := range skipped {
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	return nil, err
}

func handleConnection(conn net.Conn) {
	Logger.Info("socks connect from ", conn.RemoteAddr().String())
	closed := false
	defer func() {
		if !closed {
			Logger.Info("close socks connect from ", conn.RemoteAddr().String())
			conn.Close()
		}
	}()

	var err error = nil
	if err = handShake(conn); err != nil {
		Logger.Println("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(conn) // get request from local, parse request to raw and host that will be provided to ss server
	if err != nil {
		Logger.Println("error getting request:", err)
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		Logger.Fields(ss.LogFields{"err": err}).Error("send connection confirmation")
		return
	}

	remote, err := createServerConn(rawaddr, addr) // connect to ss server and send request from local
	if err != nil {
		Logger.Fields(ss.LogFields{
			"err": err,
		}).Warn("check createServerConn error")
		if len(servers.srvCipher) > 1 {
			Logger.Fields(ss.LogFields{
				"rawaddr": rawaddr,
				"addr": addr,
				"err": err,
			}).Error("Failed connect to all avaiable shadowsocks server")
		}
		return
	}
	defer func() {
		if !closed {
			Logger.Info("close socks connect from ", remote.RemoteAddr().String())
			remote.Close()
		}
	}()

	ss.PipeStream(conn, remote, remote.Buffer)
	Logger.Infof("closed connection to %s", addr)
}

func run(listenAddr string) { // listening from local request
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		Logger.Fatal(err)
	}
	Logger.Fields(ss.LogFields{"listenAddr": listenAddr}).Info("starting local socks5 server ...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			Logger.Fields(ss.LogFields{"err": err}).Warn("accept error")
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
	flag.BoolVar((*bool)(&ss.DebugLog), "d", false, "print debug message")
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
		Logger.Printf("%s not found, try config file %s\n", oldConfig, configFile)
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
	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//	http.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	//	http.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	//	http.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	//	http.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	//	http.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	//}()

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
		ss.Logger.Fields(ss.LogFields{
			"buf": buf[:len(tgt)+n],
			"buf_str": string(buf[:len(tgt)+n]),
			"tgt": tgt,
		}).Info("check data begin")

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