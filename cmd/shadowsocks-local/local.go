package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

var debug ss.DebugLog

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
		idIP0   = 4 // ip address start index
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

	if debug {
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
	}

	return
}

type ServerCipher struct {
	server string
	cipher *ss.Cipher
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
		// only one encryption table
		cipher, err := ss.NewCipher(config.Method, config.Password)
		if err != nil {
			log.Fatal("Failed generating ciphers:", err)
		}
		srvPort := strconv.Itoa(config.ServerPort)
		srvArr := config.GetServerArray()
		n := len(srvArr)
		servers.srvCipher = make([]*ServerCipher, n)

		for i, s := range srvArr {
			if hasPort(s) {
				log.Println("ignore server_port option for server", s)
				servers.srvCipher[i] = &ServerCipher{s, cipher}
			} else {
				servers.srvCipher[i] = &ServerCipher{net.JoinHostPort(s, srvPort), cipher}
			}
		}
	} else {
		// multiple servers
		n := len(config.ServerPassword)
		servers.srvCipher = make([]*ServerCipher, n)

		cipherCache := make(map[string]*ss.Cipher)
		i := 0
		for _, serverInfo := range config.ServerPassword {
			if len(serverInfo) < 2 || len(serverInfo) > 3 {
				log.Fatalf("server %v syntax error\n", serverInfo)
			}
			server := serverInfo[0]
			passwd := serverInfo[1]
			encmethod := ""
			if len(serverInfo) == 3 {
				encmethod = serverInfo[2]
			}
			if !hasPort(server) {
				log.Fatalf("no port for server %s\n", server)
			}
			// Using "|" as delimiter is safe here, since no encryption
			// method contains it in the name.
			cacheKey := encmethod + "|" + passwd
			cipher, ok := cipherCache[cacheKey]
			if !ok {
				var err error
				cipher, err = ss.NewCipher(encmethod, passwd)
				if err != nil {
					log.Fatal("Failed generating ciphers:", err)
				}
				cipherCache[cacheKey] = cipher
			}
			servers.srvCipher[i] = &ServerCipher{server, cipher}
			i++
		}
	}
	servers.failCnt = make([]int, len(servers.srvCipher))
	for _, se := range servers.srvCipher {
		log.Println("available remote server", se.server)
	}
	return
}

func connectToServer(serverId int, rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	se := servers.srvCipher[serverId]
	remote, err = ss.DialWithRawAddr(rawaddr, se.server, se.cipher.Copy())
	if err != nil {
		log.Println("error connecting to shadowsocks server:", err)
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}
	debug.Printf("connected to %s via %s\n", addr, se.server)
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
	if debug {
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	var err error = nil
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}

	remote, err := createServerConn(rawaddr, addr)
	if err != nil {
		if len(servers.srvCipher) > 1 {
			log.Println("Failed connect to all available shadowsocks server")
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	go ss.PipeThenClose(conn, remote, nil)
	ss.PipeThenClose(remote, conn, nil)
	closed = true
	debug.Println("closed connection to", addr)
}

func run(listenAddr string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting local socks5 server at %v ...\n", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.Server != nil && config.ServerPort != 0 &&
		config.LocalPort != 0 && config.Password != ""
}

func parseURI(u string, cfg *ss.Config) (string, error) {
	if u == "" {
		return "", nil
	}
	invalidURI := errors.New("invalid URI")
	// ss://base64(method:password)@host:port
	// ss://base64(method:password@host:port)
	u = strings.TrimLeft(u, "ss://")
	i := strings.IndexRune(u, '@')
	var headParts, tailParts [][]byte
	if i == -1 {
		dat, err := base64.StdEncoding.DecodeString(u)
		if err != nil {
			return "", err
		}
		parts := bytes.Split(dat, []byte("@"))
		if len(parts) != 2 {
			return "", invalidURI
		}
		headParts = bytes.SplitN(parts[0], []byte(":"), 2)
		tailParts = bytes.SplitN(parts[1], []byte(":"), 2)

	} else {
		if i+1 >= len(u) {
			return "", invalidURI
		}
		tailParts = bytes.SplitN([]byte(u[i+1:]), []byte(":"), 2)
		dat, err := base64.StdEncoding.DecodeString(u[:i])
		if err != nil {
			return "", err
		}
		headParts = bytes.SplitN(dat, []byte(":"), 2)
	}
	if len(headParts) != 2 {
		return "", invalidURI
	}

	if len(tailParts) != 2 {
		return "", invalidURI
	}
	cfg.Method = string(headParts[0])
	cfg.Password = string(headParts[1])
	p, e := strconv.Atoi(string(tailParts[1]))
	if e != nil {
		return "", e
	}
	cfg.ServerPort = p
	return string(tailParts[0]), nil

}

func main() {
	log.SetOutput(os.Stdout)

	var configFile, cmdServer, cmdURI string
	var cmdConfig ss.Config
	var printVer bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdServer, "s", "", "server address")
	flag.StringVar(&cmdConfig.LocalAddress, "b", "", "local address, listen only to this address if specified")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.StringVar(&cmdURI, "u", "", "shadowsocks URI")

	flag.Parse()

	if s, e := parseURI(cmdURI, &cmdConfig); e != nil {
		log.Printf("invalid URI: %s\n", e.Error())
		flag.Usage()
		os.Exit(1)
	} else if s != "" {
		cmdServer = s
	}

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	cmdConfig.Server = cmdServer
	ss.SetDebug(debug)

	exists, err := ss.IsFileExists(configFile)
	// If no config file in current directory, try search it in the binary directory
	// Note there's no portable way to detect the binary directory.
	binDir := path.Dir(os.Args[0])
	if (!exists || err != nil) && binDir != "" && binDir != "." {
		oldConfig := configFile
		configFile = path.Join(binDir, "config.json")
		log.Printf("%s not found, try config file %s\n", oldConfig, configFile)
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
	run(config.LocalAddress + ":" + strconv.Itoa(config.LocalPort))
}
