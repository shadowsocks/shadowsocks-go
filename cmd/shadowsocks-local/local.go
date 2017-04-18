package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

var (
	ErrAddrType          = errors.New("socks addr type not supported")
	ErrVer               = errors.New("socks version not supported")
	ErrMethod            = errors.New("socks only support 1 method now")
	ErrAuthExtraData     = errors.New("socks authentication get extra data")
	ErrReqExtraData      = errors.New("socks request get extra data")
	ErrCmd               = errors.New("socks command not supported")
	ErrServerInfoIllegal = errors.New("shadowsocks server address illegal or server port illigal")
	ErrInvalidArguments  = errors.New("arguments illega")
	ErrInvalidPassword   = errors.New("password illegal")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

func init() {
	rand.Seed(time.Now().Unix())
}

// handle the accepted connection ad socks5
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

	// TODO if needed
	//ss.SetReadTimeout(conn)

	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	// check the version
	if buf[idVer] != socksVer5 {
		return ErrVer
	}

	//nmethods: The NMETHODS field contains the number of method identifier
	// octets that appear in the METHODS field.
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		conn.Write([]byte{socksVer5, 0xFF})
		return ErrAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

// getRequest return the socks5 request from the client
// return the type+addr+port as rawaddr as the request payload
func getRequest(conn net.Conn) (rawaddr []byte, err error) {
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

	// TODO if needed
	//ss.SetReadTimeout(conn)

	// first of all we read the socks5 request
	// read till we get possible domain length
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = ErrVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = ErrCmd
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
		err = ErrAddrType
		return
	}

	if n == reqLen {
		// common case cause we have read all the info (host + port), do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = ErrReqExtraData
		return
	}

	// only contain the host + port
	rawaddr = buf[idType:reqLen]

	//switch buf[idType] {
	//case typeIPv4:
	//	host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	//case typeIPv6:
	//	host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	//case typeDm:
	//	host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	//}
	//port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	//host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

type ServerCipher struct {
	server string
	cipher *encrypt.Cipher
}

// Connection to the servers set in the config servers connection
func prepareToConnect(c *ss.Config) (map[string]*encrypt.Cipher, error) {
	// connect to server will establish all the server connection with given server address and port
	cips := make(map[string]*encrypt.Cipher, len(c.GetServerArray()))
	for server, passwd := range c.ServerPassword {
		cipher, err := encrypt.NewCipher(c.Method, passwd)
		if err != nil {
			return nil, err
		}
		cips[server] = cipher
	}
	return cips, nil
}

// dial the server establish the ss connection
func connectToServer(addr string, ciph *encrypt.Cipher, ota bool, timeout int) (*ss.SecureConn, error) {
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := ss.NewSecureConn(nc, ciph, ota, timeout, false)
	ss.Logger.Debug("ss local connecting to server", zap.String("server", addr), zap.Bool("ota", ota), zap.Int("timeout", timeout))
	return conn, nil
}

// handle the local socks5 connection and request remote server
func handleConnection(server string, conn net.Conn, ota bool, timeout int) {
	ss.Logger.Debug("handle socks5 connect", zap.Stringer("source", conn.LocalAddr()), zap.Stringer("remote", conn.RemoteAddr()))

	var err error
	var closed bool
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	// Hand shake happened when accept the socks5 negotiation request
	// ss server will accept the negotiation or ask client to reset the connection
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}

	// After handshake ss will read the requset fron client to establish the proxy connection
	// rawaddr is the socks5 request addr+port
	rawaddr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}

	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.

	// Notice that the server response bind addr & port could be ignore by the socks5 client
	// 0x00 0x00 0x00 0x00 0x10 0x10 is meaning less
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10})
	if err != nil {
		ss.Logger.Error("send connection confirmation", zap.Error(err))
		return
	}

	// after socks5 hand shake, we'd get a ss server connection
	// new server config for new server

	// get server connection
	cip := ciphers[server]

	ssconn, err := connectToServer(server, cip, ota, timeout)
	if err != nil {
		return
	}
	defer func() {
		if !closed {
			ssconn.Close()
		}
	}()

	// FIXME!!!
	ssconn.Write(rawaddr)

	// ask the request with rawaddr & payload
	// then read the connection and write back
	go ss.PipeThenClose(conn, ssconn, timeout)
	ss.PipeThenClose(ssconn, conn, timeout)

	closed = true
	ss.Logger.Debug("closed server connection", zap.Stringer("serverlocal", ssconn.LocalAddr()), zap.Stringer("serverremote", ssconn.RemoteAddr()))
}

var ciphers map[string]*encrypt.Cipher

func run(config *ss.Config) {
	laddr := config.Local + strconv.Itoa(config.LocalPort)
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		ss.Logger.Fatal("error in shadwsocks local server listen", zap.Error(err))
	}
	ss.Logger.Info("starting local socks5 server", zap.String("listenAddr", laddr))

	// prepare connect to the server ciphers
	cps, err := prepareToConnect(config)
	if err != nil {
		ss.Logger.Fatal("error in shadwsocks local server listen", zap.Error(err))
	}
	ciphers = cps
	servers := config.GetServerArray()
	serverlen := len(servers)
	// get a connection to connect the server
	for {
		server := servers[rand.Int()%serverlen]
		conn, err := ln.Accept()
		if err != nil {
			ss.Logger.Error("error in local server accept", zap.Error(err))
		} else {
			go handleConnection(server, conn, config.OTA, config.Timeout)
		}
	}
}

// main locical about the local server
func main() {
	var configFile, ServerAddr, LocalAddr, Password, Method string
	var ServerPort, Timeout, LocalPort int
	var printVer bool
	var config *ss.Config

	flag.BoolVar(&printVer, "v", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&LocalAddr, "addr", "127.0.0.1", "local socks5 proxy serve address")
	flag.IntVar(&LocalPort, "port", 0, "local socks5 proxy port")
	flag.StringVar(&ServerAddr, "saddr", "", "server address")
	flag.IntVar(&ServerPort, "sport", 0, "server port")
	flag.StringVar(&Password, "k", "", "server password")
	flag.IntVar(&Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&Method, "m", "aes-256-cfb-auth", "encryption method, default: aes-256-cfb. end with -auth mean enable OTA")
	flag.StringVar(&ss.Level, "l", "info", "given the logger level for ss to logout info, can be set in debug info warn error panic")

	// show the help info when parse flags failed
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
	ss.Logger.Debug("Starting the local server")

	var err error
	// set the options for the config new
	var opts []ss.ConfOption

	// choose the encrypt method then check
	if Method == "" {
		Method = "aes-256-cfb"
		opts = append(opts, ss.WithEncryptMethod("aes-256-cfb"))
	}

	// handle the auth optnion when method is
	if strings.HasSuffix(Method, "-auth") {
		Method = Method[:len(Method)-5]
		opts = append(opts, ss.WithOTA())
	}
	if err = encrypt.CheckCipherMethod(Method); err != nil {
		ss.Logger.Error("error in check the cipher method", zap.String("method", Method), zap.Error(err))
		os.Exit(1)
	}
	opts = append(opts, ss.WithEncryptMethod(Method))

	// add the passwd
	if Password != "" {
		opts = append(opts, ss.WithPassword(Password))
	}

	config = ss.NewConfig(opts...)

	// parse the config from the config file
	if configFile != "" {
		if config, err = ss.ParseConfig(configFile); err != nil {
			ss.Logger.Error("error in read the config file", zap.String("config file", configFile), zap.Error(err))
			os.Exit(1)
		}
	}

	// check the config
	if err = checkConfig(config); err != nil {
		ss.Logger.Error("error in check the config for the local shadowsocks server", zap.Error(err))
		os.Exit(1)
	}

	go run(config)
	waitSignal()
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for {
		s := <-sigChan
		switch s {
		case syscall.SIGHUP:
			ss.Logger.Warn("receive the KILL -HUP rebooting")
			fallthrough
			// TODO add the reboot for the ss local
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
			ss.Logger.Info("Caught signal , shuting down", zap.Stringer("signal", s))
			os.Exit(0)
		default:
			ss.Logger.Error("Caught meaning lease signal", zap.Stringer("signal", s))
		}
	}
}

func checkConfig(config *ss.Config) error {
	// server addr port
	// passwd
	// local port
	if config.Local == "" || config.LocalPort < 0 {
		return ErrServerInfoIllegal
	}

	if config.ServerPassword == nil {
		if config.Server == "" || config.ServerPort == "" {
			return ErrServerInfoIllegal
		}

		if config.Password == "" {
			return ErrInvalidPassword
		}
	}

	hasPort := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		return port != ""
	}

	for addr, pwd := range config.ServerPassword {
		if !hasPort(addr) {
			delete(config.ServerPassword, addr)
		}
		if pwd == "" {
			ss.Logger.Fatal("Failed generating ciphers", zap.String("address", addr))
		}
	}

	return nil
}
