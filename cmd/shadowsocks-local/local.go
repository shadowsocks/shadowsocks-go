package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
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
	ErrReadUnexpectEOF   = errors.New("unexpect EOF occoured")
)

const (
	UDPMaxSize = 65507 // max udp packet size

	idVer     = 0 // socks version index
	idNmethod = 1
	idCmd     = 1
	idFrag    = 3 // UDP client request for FRAG
	idType    = 3 // address type index
	idIP0     = 4 // ip addres start index
	idDmLen   = 4 // domain address length index
	idDm0     = 5 // domain address start index

	socksVer5             = 0x05 // socks5 version
	socksCmdConnect       = 0x01 // socks5 connection command connect
	socksCmdUDPAssocation = 0x03 // socks5 connection command UDP association
	typeIPv4              = 0x01 // type is ipv4 address
	typeDm                = 0x03 // type is domain address
	typeIPv6              = 0x04 // type is ipv6 address

	lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)

var (
	// HandShakeTimeout give out the socks5 handshake time out
	HandShakeTimeout = 15
	// ErrNilCipher give out the illegal cipher
	ErrNilCipher = errors.New("error nil cipher")
)

// handle the accepted connection ad socks5
// NOTICE the ss-local wont require any authentication and return 0x05 0x00 to client
// intend for no auth required
func handShake(conn net.Conn) (err error) {
	var n int
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice
	buf := make([]byte, 258)

	// set the handshake time out
	conn.SetDeadline(time.Now().Add(time.Second * time.Duration(HandShakeTimeout)))

	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		if n == 0 {
			return
		}
	}

	// check the version
	if buf[idVer] != socksVer5 {
		return ErrVer
	}

	//nmethods: The NMETHODS field contains the number of method identifier
	// octets that appear in the METHODS field.
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2 // ver + nmethod = 2
	if n == msgLen {
		// handshake done, normal case
		// do nothing
		// send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else {
		// tell client reset connection
		// should not get extra data
		conn.Write([]byte{socksVer5, 0xFF})
		return ErrAuthExtraData
	}

	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0x00})
	return
}

// getRequest return the socks5 request from the client
// return the type+addr+port as rawaddr as the request payload
func getRequest(conn net.Conn) (rawaddr []byte, err error) {
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int

	// first of all we read the socks5 request
	// read till we get possible domain length
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer]&0xff != socksVer5 {
		err = ErrVer
		return
	}
	if buf[idCmd]&0xff != socksCmdConnect {
		err = ErrCmd
		return
	}

	reqLen := -1
	switch buf[idType] & 0xff {
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
		ss.Logger.Warn("error in read the request arddr, less than expect")
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = ErrReqExtraData
		return
	}

	// only contain the host + port
	rawaddr = buf[idType:reqLen]

	var host string
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

	ss.Logger.Debug("get request addr", zap.String("host", host))
	return
}

// UDP request will associate the address pair for socks5 client & server communication
// this implementation will not support the UDP fregements
func udpAssociate(conn net.Conn) (int, int, net.PacketConn, error) {
	// return (clientbindport, serverbindport, serverlisten, error)

	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	var err error

	// first of all we read the socks5 request
	// read till we get possible domain length
	if n, err = io.ReadAtLeast(conn, buf, lenIPv4); err != nil {
		return -1, -1, nil, err
	}
	// check version and cmd
	if buf[idVer]&0xff != socksVer5 {
		err = ErrVer
		ss.Logger.Error("[UDP] error in udp association socks version", zap.Error(err))
		return -1, -1, nil, err
	}
	if buf[idCmd]&0xff != socksCmdUDPAssocation {
		err = ErrCmd
		ss.Logger.Error("[UDP] error in udp association association skiped", zap.Error(err))
		return -1, -1, nil, err
	}

	// UDP assocation only allow the ip type bind for the socks server
	// TODO should combine the both udp and tcp handshake together
	if buf[idType]&0xff != typeIPv4 {
		err = ErrAddrType
		ss.Logger.Error("[UDP] error in udp association address not supported",
			zap.Int16("ATYPE", int16(buf[idType])), zap.Error(err))
		return -1, -1, nil, err
	}

	if n == lenIPv4 {
		// common case cause we have read all the info (host + port), do nothing
	} else if n < lenIPv4 { // rare case
		ss.Logger.Warn("error in read the request arddr, less than expect")
		if _, err = io.ReadFull(conn, buf[n:lenIPv4]); err != nil {
			return -1, -1, nil, err
		}
	} else {
		err = ErrReqExtraData
		ss.Logger.Error("[UDP] error in udp association read field", zap.Error(err))
		return -1, -1, nil, err
	}

	// now get the ip and port from the request which indecate the port that socks5
	// client will use to contect with socks5 server
	var clietnBindPort int16
	rawClientBindPort := bytes.NewBuffer(buf[lenIPv4-2 : lenIPv4])
	err = binary.Read(rawClientBindPort, binary.BigEndian, &clietnBindPort)
	if err != nil {
		ss.Logger.Error("[UDP] error in read client bind port", zap.Error(err))
		return -1, -1, nil, err
	}

	// now we'd generate a server bind address used only communication with
	// client bind address and replay to the client
	serverBindListen, err := net.ListenPacket("udp", "")
	if err != nil {
		// optional reply
		// 05 01 00 ... for generate ip field
		ss.Logger.Error("[UDP] error in start listen udp for client udp association", zap.Error(err))
		return -1, -1, nil, err
	}

	serverBindAddr, err := net.ResolveUDPAddr("udp", serverBindListen.LocalAddr().String())
	replay := []byte{0x05, 0x00, 0x00, 0x01} // header of server relpy association
	rawServerBindAddr := bytes.NewBuffer([]byte{0x0, 0x0, 0x0, 0x0})
	if err = binary.Write(rawServerBindAddr, binary.BigEndian, int16(serverBindAddr.Port)); err != nil {
		ss.Logger.Error("[UDP] error in combine address to reply", zap.Error(err))
		return -1, -1, nil, err
	}
	replay = append(replay, rawServerBindAddr.Bytes()[:6]...)
	if _, err = conn.Write(replay); err != nil {
		ss.Logger.Error("[UDP] error in reply for client association", zap.Error(err))
		return -1, -1, nil, err
	}

	// keep the tcp connection alive until the socks5 should be closed
	conn.(*net.TCPConn).SetKeepAlive(true)

	return int(clietnBindPort), serverBindAddr.Port, serverBindListen, nil
}

type ServerCipher struct {
	server string
	cipher *encrypt.Cipher
}

// prepare the infomation for connection to the servers set in the config
func prepareToConnect(c *ss.Config) (map[string]*encrypt.Cipher, error) {
	// connect to server will establish all the server connection with given server address and port
	cips := make(map[string]*encrypt.Cipher, len(c.GetServerArray()))

	if c.Server != "" && c.ServerPort != "" {
		ss := c.Server + ":" + c.ServerPort
		cipher, err := encrypt.NewCipher(c.Method, c.Password)
		if err != nil {
			return nil, err
		}
		cips[ss] = cipher
	}

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
func connectToServer(addr string, ciph *encrypt.Cipher, timeout int) (*ss.SecureConn, error) {
	if ciph == nil {
		return nil, ErrNilCipher
	}
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := ss.NewSecureConn(nc, ciph.Copy(), timeout)
	ss.Logger.Debug("ss local connecting to server with TCP", zap.String("server", addr), zap.Int("timeout", timeout))
	return conn, nil
}

// dial the server establish the ss connection
func connectToServerUDP(ciph *encrypt.Cipher, timeout int) (*ss.SecurePacketConn, error) {
	if ciph == nil {
		return nil, ErrNilCipher
	}

	sconn, err := ss.ListenPacket("udp", "", ciph.Copy(), timeout)
	if err != nil {
		return nil, err
	}
	ss.Logger.Debug("ss local connecting to server with UDP", zap.Int("timeout", timeout))
	return sconn, nil
}

// handle the local socks5 connection and request remote server
func handleConnection(server string, conn net.Conn, timeout int) {
	ss.Logger.Debug("handle socks5 connect", zap.Stringer("source", conn.LocalAddr()), zap.Stringer("remote", conn.RemoteAddr()))
	var err error
	var closed bool
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	// Hand shake happened when accept the socks5 negotiation request
	// ss local will accept the negotiation or ask client to reset the connection when unexpect error occours
	if err = handShake(conn); err != nil {
		// error occoured and close the connection immediately
		ss.Logger.Error("error in socks5 handShake", zap.Stringer("socks5client", conn.LocalAddr()), zap.Error(err))
		return
	}

	// After handshake ss will read the requset fron client to establish the proxy connection
	// target is the socks5 request addr+port
	target, err := getRequest(conn)
	if err != nil {
		ss.Logger.Error("error in getting socks5 request", zap.Error(err))
		return
	}

	// Sending connection established message immediately to client.
	// This cost some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	//
	// Notice that the server response bind addr & port could be ignore by the socks5 client
	// 0x00 0x00 0x00 0x00 0x10 0x10 is meaning less for bind addr block.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10})
	if err != nil {
		ss.Logger.Error("send connection confirmation", zap.Error(err))
		return
	}

	// after socks5 hand shake, we'd get a ss server connection
	// cipher should be copied pass

	ssconn, err := connectToServer(server, ciphers[server], timeout)
	if err != nil {
		ss.Logger.Error("erro in connect to ss server", zap.String("server", server), zap.Error(err))
		return
	}
	defer func() {
		if !closed {
			ssconn.Close()
		}
	}()

	if _, err := ssconn.Write(target); err != nil {
		ss.Logger.Error("request ss remote failed", zap.Stringer("serverlocal", ssconn.LocalAddr()),
			zap.Stringer("serverremote", ssconn.RemoteAddr()), zap.ByteString("target", target))
		return
	}

	// ask the request with payload
	// then read the connection and write back
	// close the server at the right time
	wg := sync.WaitGroup{}
	wg.Add(1)
	go ss.PipeThenClose(conn, ssconn, timeout, func() {
		wg.Done()
		conn.Close()
	})
	ss.PipeThenClose(ssconn, conn, timeout, func() { ssconn.Close() })
	wg.Wait()

	closed = true
	ss.Logger.Debug("closed server connection", zap.Stringer("serverlocal", ssconn.LocalAddr()), zap.Stringer("serverremote", ssconn.RemoteAddr()))
	return
}

// handle the local socks5 connection and request remote server
func handleUDPConnection(server string, conn net.Conn, timeout int) {
	// handshake
	// get req
	// for loop read and forward (go)
	// make up NAT
	ss.Logger.Debug("handle socks5 connect", zap.Stringer("source", conn.LocalAddr()), zap.Stringer("remote", conn.RemoteAddr()))
	var err error
	var closed bool
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	// resolve udp address
	serverUDPaddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		ss.Logger.Error("[UDP] error in resolve server address into udp", zap.Error(err))
		return
	}

	// Hand shake happened when accept the socks5 negotiation request
	// ss local will accept the negotiation or ask client to reset the connection when unexpect error occours
	if err = handShake(conn); err != nil {
		ss.Logger.Error("error in socks5 handShake", zap.Stringer("socks5client", conn.LocalAddr()), zap.Error(err))
		return
	}

	// After handshake ss will read the requset fron client to establish the proxy connection
	// target is the socks5 request addr+port
	clientPort, serverPort, serverListener, err := udpAssociate(conn)
	if err != nil {
		ss.Logger.Error("error in getting socks5 request", zap.Error(err))
		return
	}
	ss.Logger.Debug("[UDP] after udp associate", zap.Int("cliBindPort", clientPort), zap.Int("servBindPort", serverPort))

	// gen ss packet connection via server listener
	ssPacketConn := ss.NewSecurePacketConn(serverListener, ciphers[server].Copy(), timeout)

	cliReq := make([]byte, UDPMaxSize)
	for {
		// TODO FIXME need to determine when close the TCP connection
		// server read the first packet from associated address, get the client destination address
		// ss-local will not support the fragments about udp, we will forward and log a WARNING
		// if the FRAG is not 0
		n, raddr, err := serverListener.ReadFrom(cliReq)
		if err != nil {
			ss.Logger.Error("[UDP] error in read packet from client UDP", zap.Error(err))
			continue
		}
		cliReq = cliReq[:n]
		getAddr, err := net.ResolveUDPAddr("udp", raddr.String())
		if getAddr.Port != clientPort {
			ss.Logger.Warn("[UDP] read a illegal source packet, droped")
			continue
		}

		// if frag != 0 should get a warning
		if cliReq[idFrag]&0xff != 0x00 {
			ss.Logger.Warn("[UDP] warrning get the fragnent packet")
		}

		// here we get the request need to encrypte and forward to ss remote
		//var rawData []byte = cliReq[idType:]

		// write to the ss-remote, this data will be encrypted with the choosen server
		_, err = ssPacketConn.WriteTo(cliReq[idType:], serverUDPaddr)
		if err != nil {
			ss.Logger.Error("[UDP]write to server error", zap.Stringer("ss-local", ssPacketConn.LocalAddr()),
				zap.String("server", server), zap.Error(err))
			return
		}
	}

	closed = true
	ss.Logger.Debug("closed server connection", zap.Stringer("ss-local", ssPacketConn.LocalAddr()), zap.String("server", server))
	return
}

var ciphers map[string]*encrypt.Cipher

func run(config *ss.Config, enableUDP bool) {
	laddr := net.JoinHostPort(config.Local, strconv.Itoa(config.LocalPort))
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		ss.Logger.Fatal("error in shadwsocks local server listen", zap.Error(err))
	}
	ss.Logger.Info("starting local socks5 server", zap.String("listenAddr", laddr))

	// prepare connect to the server ciphers
	cps, err := prepareToConnect(config)
	if err != nil {
		ss.Logger.Fatal("error in shadwsocks local server prepaer the cipher", zap.Error(err))
	}

	ciphers = cps
	servers := config.GetServerArray()
	ports := config.GetServerPortArray()
	for i, _ := range servers {
		servers[i] = net.JoinHostPort(servers[i], ports[i])
	}

	// TODO we need a strategy auto ping each server
	// and sort to choose the best server in use
	// this should be done in background every hours
	// go detectServer()

	// main loop for socks5 accept incoming request
	for {
		server := servers[0]
		conn, err := ln.Accept()
		if err != nil {
			ss.Logger.Error("error in local server accept socks5", zap.Error(err))
		}
		if enableUDP {
			go handleUDPConnection(server, conn, config.Timeout)
		} else {
			go handleConnection(server, conn, config.Timeout)
		}
	}
}

var LocalAddr string

// main locical about the local server
func main() {
	var configFile, ServerAddr, Password, Method string
	var ServerPort, Timeout, LocalPort int
	var printVer, UDP bool
	var config *ss.Config
	var err error

	flag.BoolVar(&printVer, "v", false, "print version")
	flag.StringVar(&configFile, "c", "", "specify config file")
	flag.StringVar(&LocalAddr, "addr", "127.0.0.1", "local socks5 proxy serve address")
	flag.IntVar(&LocalPort, "port", 0, "local socks5 proxy port")
	flag.StringVar(&ServerAddr, "saddr", "", "server address")
	flag.IntVar(&ServerPort, "sport", 0, "server port")
	flag.StringVar(&Password, "k", "", "server password")
	flag.IntVar(&Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&Method, "m", "aes-256-cfb", "encryption method, default: aes-256-cfb. end with -auth mean enable OTA")
	flag.StringVar(&ss.Level, "l", "info", "given the logger level for ss to logout info, can be set in debug info warn error panic")
	flag.BoolVar(&UDP, "udp", false, "use the udp to serve")

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

	// set the options for the config new
	var opts []ss.ConfOption

	// choose the encrypt method then check
	if Method == "" {
		Method = "aes-256-cfb"
		opts = append(opts, ss.WithEncryptMethod("aes-256-cfb"))
	}

	if err = encrypt.CheckCipherMethod(Method); err != nil {
		ss.Logger.Fatal("error in check the cipher method", zap.String("method", Method), zap.Error(err))
	}
	opts = append(opts, ss.WithEncryptMethod(Method))

	if ServerAddr != "" {
		opts = append(opts, ss.WithServer(ServerAddr))
	}
	if ServerPort > 0 {
		opts = append(opts, ss.WithServerPort(strconv.Itoa(ServerPort)))
	}
	if Password != "" {
		opts = append(opts, ss.WithPassword(Password))
	}
	if LocalAddr != "" {
		opts = append(opts, ss.WithLocalAddr(LocalAddr))
	}
	if LocalPort != 0 {
		opts = append(opts, ss.WithLocalPort(LocalPort))
	}

	config = ss.NewConfig(opts...)

	// parse the config from the config file
	if configFile != "" {
		if config, err = ss.ParseConfig(configFile); err != nil {
			ss.Logger.Fatal("error in read the config file", zap.String("config file", configFile), zap.Error(err))
		}
	}

	// check the config
	if err = checkConfig(config); err != nil {
		ss.Logger.Fatal("error in check the config for the local shadowsocks server", zap.Error(err))
	}

	ss.Logger.Debug("show the ss config", zap.Stringer("config", config))
	// start the socks5 server
	go run(config, UDP)

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
			return ErrInvalidPassword
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
