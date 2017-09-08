package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
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

// Error defined the common errors
var (
	ErrAddrType          = errors.New("socks addr type not supported")
	ErrVer               = errors.New("socks version not supported")
	ErrMethod            = errors.New("socks only support 1 method now")
	ErrAuthExtraData     = errors.New("socks authentication get extra data")
	ErrReqExtraData      = errors.New("socks request get extra data")
	ErrBadHandshake      = errors.New("error bad handshake in socks5")
	ErrCmd               = errors.New("socks command not supported")
	ErrServerInfoIllegal = errors.New("shadowsocks server address illegal or server port illegal")
	ErrInvalidArguments  = errors.New("arguments illegal")
	ErrInvalidPassword   = errors.New("password illegal")
	ErrReadUnexpectEOF   = errors.New("unexpect EOF occoured")
	ErrConvertTCPConn    = errors.New("error in convert into tcp connection")
	ErrNilCipher         = errors.New("error nil cipher")
)

const (
	// HandShakeTimeout give out the socks5 handshake time out
	HandShakeTimeout = 15
	// UDPMaxSize give out max udp packet size
	UDPMaxSize = 65507

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

// natinfo keep the udp nat info for each socks5 association pair
type natTableInfo struct {
	ClientBindPort int
	ServerBindPort int
	ServerPacketln net.PacketConn
	SSPacketln     net.PacketConn
}

// NatTable keept the connection both client and server side, for route
type natTable map[string]*natTableInfo

// NatInfo used to locate the natTable from server port
var NatInfo map[int]natTable = make(map[int]natTable)

// handle the accepted connection ad socks5
// NOTICE the ss-local wont require any authentication and return 0x05 0x00 to client
// intend for no auth required
func handShake(conn net.Conn) (cmdtype int, err error) {
	var n int
	// version identification and method selection message in theory can have
	// at most 255 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice
	buf := make([]byte, 258)

	// set the handshake timeout
	conn.SetDeadline(time.Now().Add(time.Second * time.Duration(HandShakeTimeout)))

	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		if err != io.EOF {
			return -1, err
		}
		if n == 0 {
			conn.Write([]byte{socksVer5, 0xff})
			return -1, ErrBadHandshake
		}
	}

	// check the version
	if buf[idVer] != socksVer5 {
		return -1, ErrVer
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
		conn.Write([]byte{socksVer5, 0xff})
		return -1, ErrAuthExtraData
	}

	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0x00})
	if err != nil {
		ss.Logger.Error("error in socks5 request ack", zap.Error(err))
		return -1, err
	}

	bufrq := make([]byte, 3)
	if n, err = conn.Read(bufrq); err != nil || n < 3 {
		ss.Logger.Error("error in get request", zap.Error(err))
		return -1, err
	}
	return int(bufrq[idCmd]), nil
}

// getRequest return the socks5 request from the client
// return the type+addr+port as rawaddr as the request payload
func getRequest(conn net.Conn) (rawaddr []byte, err error) {
	var n int
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)

	// [ver* cmd* resv* type dmlen]
	// first of all we read the socks5 request
	// read till we get possible domain length
	if n, err = io.ReadAtLeast(conn, buf[3:], idDm0); err != nil {
		if err != io.EOF {
			return
		}
		if n == 0 {
			err = ErrReqExtraData
			return
		}
	}

	// cause we have read the first 3 byte (ver cmd reserve), the offset shoule be add here
	// first 3 byte is meaningless
	n += 3

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
		ss.Logger.Warn("error in read the request arddr, less than expect", zap.Int("recv", n), zap.Int("req", reqLen))
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			if err != io.EOF {
				return
			}
			if n == 0 {
				err = ErrReqExtraData
				return
			}
		}
	} else {
		err = ErrReqExtraData
		return
	}

	// only contain the type + host + port
	rawaddr = buf[idType:n]

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
	return rawaddr, nil
}

// UDP request will associate the address pair for socks5 client & server communication
// this implementation will not support the UDP fregements
func udpAssociate(conn net.Conn) (int, int, net.PacketConn, error) {
	// return (clientbindport, serverbindport, serverlisten, error)

	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 259)
	var n int
	var err error

	// first of all we read the socks5 request
	// read till we get possible domain length
	if n, err = io.ReadAtLeast(conn, buf, lenIPv4-3); err != nil {
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
	// TODO IPV4 + IPV6, need the ipv6 support
	if buf[idType-3]&0xff != typeIPv4 {
		err = ErrAddrType
		ss.Logger.Error("[UDP] error in udp association address not supported",
			zap.Int16("ATYPE", int16(buf[idType])), zap.Error(err))
		return -1, -1, nil, err
	}

	if n == lenIPv4-3 {
		// common case cause we have read all the info (host + port), do nothing
	} else if n < lenIPv4-3 { // rare case
		ss.Logger.Warn("[UDP] error in read the request arddr, less than expect")
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
	rawClientBindPort := bytes.NewBuffer(buf[lenIPv4-5 : lenIPv4-3])
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

// ServerCipher difined the server and cipher suit
type ServerCipher struct {
	server string
	cipher *encrypt.Cipher
}

// prepare the information for connection to the servers set in the config
func prepareToConnect(c *ss.Config) (map[string]encrypt.Cipher, error) {
	// connect to server will establish all the server connection with given server address and port
	cips := make(map[string]encrypt.Cipher, len(c.ServerList))

	if c.Server != "" && c.ServerPort != "" {
		ss := c.Server + ":" + c.ServerPort
		cipher, err := encrypt.PickCipher(c.Method, c.Password)
		if err != nil {
			return nil, err
		}
		cips[ss] = cipher
	}

	for _, v := range c.ServerList {
		cipher, err := encrypt.PickCipher(v.Method, v.Password)
		if err != nil {
			return nil, err
		}
		cips[v.Address] = cipher
	}
	return cips, nil
}

// dial the server establish the ss connection
func connectToServer(addr string, ciph encrypt.Cipher, timeout int) (net.Conn, error) {
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
func connectToServerUDP(ciph encrypt.Cipher, timeout int) (net.PacketConn, error) {
	if ciph == nil {
		return nil, ErrNilCipher
	}

	sconn, err := ss.SecureListenPacket("udp", "", ciph.Copy(), timeout)
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
	// 0x00 0x00 0x00 0x00 0x00 0x00 is meaning less for bind addr block.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
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

	// request the ss-remote with given host
	if _, err := ssconn.Write(target); err != nil {
		ss.Logger.Error("request ss remote failed", zap.Stringer("serverlocal", ssconn.LocalAddr()),
			zap.Stringer("serverremote", ssconn.RemoteAddr()), zap.Error(err))
		return
	}

	tcpssconn, ok := ssconn.(*ss.SecureConn)
	if !ok {
		ss.Logger.Error("error in pipthen close", zap.Error(ErrConvertTCPConn))
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		ss.Logger.Error("error in pipthen close", zap.Error(ErrConvertTCPConn))
	}

	defer conn.Close()
	defer ssconn.Close()
	wg := sync.WaitGroup{}
	wg.Add(1)

	// NOTICE: timeout should be setted carefully to avoid cutting the correct tcp stream
	if timeout > 0 {
		ss.Logger.Info("connection timeout setted", zap.Int("timeout", timeout))
		tcpConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		ssconn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}

	// do the pipe between clicnet & server
	go ss.PipeThenClose(tcpConn, tcpssconn, wg.Done)
	ss.PipeThenClose(tcpssconn, tcpConn, func() {})
	wg.Wait()

	ss.Logger.Debug("closed server connection", zap.String("conn info", fmt.Sprintf("incoming conn: %v <---> %v, outting conn: %v <---> %v", conn.LocalAddr().String(), conn.RemoteAddr().String(), ssconn.LocalAddr().String(), ssconn.RemoteAddr().String())))
	return
}

// handle the local socks5 connection and request remote server
func handleUDPConnection(server string, conn net.Conn, timeout int) {
	ss.Logger.Debug("handle socks5 connect", zap.Stringer("source", conn.LocalAddr()),
		zap.Stringer("remote", conn.RemoteAddr()))
	var err error

	// resolve udp address
	serverUDPaddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		ss.Logger.Error("error in resolve server address into udp", zap.Error(err))
		return
	}

	// After handshake ss will read the requset fron client to establish the proxy connection
	// target is the socks5 request addr+port
	clientPort, serverPort, serverListener, err := udpAssociate(conn)
	if err != nil {
		ss.Logger.Error("error in getting socks5 request", zap.Error(err))
		return
	}
	// TODO FIXME
	clientAddr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(clientPort))
	if err != nil {
		ss.Logger.Error("[UDP]error in resulove client bind address")
		return
	}
	ss.Logger.Debug("[UDP] after udp associate", zap.Int("cliBindPort", clientPort), zap.Int("servBindPort", serverPort))

	// gen ss packet connection via server listener
	ssPacketConn := ss.NewSecurePacketConn(serverListener, ciphers[server].Copy(), timeout)

	// FIXME need to close this goroutine
	go func() {
		readBuf := make([]byte, UDPMaxSize)
		for {
			// read from the ss packet connection and decrypted
			n, _, err := ssPacketConn.ReadFrom(readBuf)
			if err != nil {
				continue
				// return??
			}

			// resolve the request header, trim it and backward
			_, length, err := ss.GetUDPRequest(readBuf)
			if err != nil {
				//handle error
			}

			// backward the payload(without address header) to the client bind udp client
			_, err = serverListener.WriteTo(readBuf[length:n], clientAddr)
			if err != nil {
				return
			}
		}
	}()
	defer serverListener.Close()
	defer ssPacketConn.Close()

	cliReq := make([]byte, UDPMaxSize)
	for {
		// TODO FIXME need to determine when close the TCP connection
		// server read the first packet from associated address, get the client destination address
		// ss-local will not support the fragments about udp, we will forward and log a WARNING
		// if the FRAG is not 0
		n, raddr, err := serverListener.ReadFrom(cliReq)
		if err != nil {
			ss.Logger.Error("[UDP] error in read packet from client UDP", zap.Error(err))
			return
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
		// write them into the Nat table
		var reqAddrLen int
		switch cliReq[idType] & 0xff {
		case typeIPv4:
			reqAddrLen = lenIPv4
		case typeIPv6:
			reqAddrLen = lenIPv6
		case typeDm:
			reqAddrLen = lenDmBase + int(cliReq[idType+1])
		}
		var rawData []byte = cliReq[idType:reqAddrLen]
		if _, ok := NatInfo[serverPort]; !ok {
			NatInfo[serverPort] = make(natTable)
		}
		NatInfo[serverPort][string(rawData)] = &natTableInfo{clientPort, serverPort, serverListener, ssPacketConn}

		// write to the ss-remote, this data will be encrypted with the choosen server
		_, err = ssPacketConn.WriteTo(cliReq[idType:], serverUDPaddr)
		if err != nil {
			ss.Logger.Error("[UDP]write to server error", zap.Stringer("ss-local", ssPacketConn.LocalAddr()),
				zap.String("server", server), zap.Error(err))
			continue
		}
		ss.Logger.Debug("closed server connection", zap.Stringer("ss-local", ssPacketConn.LocalAddr()), zap.String("server", server))
	}
}

var ciphers map[string]encrypt.Cipher

func run(config *ss.Config) {
	laddr := net.JoinHostPort(config.Local, config.LocalPort)
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

	// init the ciphers map
	ciphers = cps

	// multi server mode
	var getServer func() ss.ServerEntry = config.GetServer

	switch config.MultiServerMode {
	case "fastest":
		// start the test routine for server detection
		go func() {
			if len(config.ServerList) < 2 {
				return
			}
			for {
				config.Detect()
				time.Sleep(time.Hour * 1)
			}
		}()
	case "round-robin":
		if len(config.ServerList) >= 2 {
			getServer = config.GetServerRoundRobin
		}
	}

	// XXX
	// listen the socks5 on this
	//if enableUDP {
	//	go func() {
	//		laddr := net.JoinHostPort(config.Local, strconv.Itoa(config.LocalPort))
	//		pln, err := net.ListenPacket("udp", laddr)
	//		if err != nil {
	//			ss.Logger.Fatal("error in shadwsocks local server listen udp", zap.Error(err))
	//		}
	//		ss.Logger.Info("starting local socks5 server udp", zap.String("listenAddr", laddr))

	//		// main loop for socks5 accept incoming request
	//		for {
	//			server := servers[0]
	//			conn, err := ln.Accept()
	//			if err != nil {
	//				ss.Logger.Error("error in local server accept socks5", zap.Error(err))
	//			} else {
	//				go handleUDPConnection(server, conn, config.Timeout)
	//			}
	//		}
	//	}()
	//}

	// main loop for socks5 accept incoming request
	var server string
	for {
		server = getServer().Address
		conn, err := ln.Accept()
		if err != nil {
			ss.Logger.Error("error in local server accept socks5", zap.Error(err))
		}
		conn.(*net.TCPConn).SetKeepAlive(true)

		// close the Nagle algorythm, for long fat pipe if necessary
		// conn.(*net.TCPConn).SetNoDelay(false)

		// XXX DONOT set linger -1, cause after close write each incomming packet will be rejected and post back a RST packet.
		// If so, another side of the tcp connection will return connection reset by peer error.
		//conn.(*net.TCPConn).SetLinger(-1)

		// Hand shake happened when accept the socks5 negotiation request
		// ss local will accept the negotiation or ask client to reset the connection when unexpect error occours
		go func() {
			cmd, err := handShake(conn)
			if err != nil {
				if err == ErrBadHandshake {
					ss.Logger.Warn("error in socks5 handShake", zap.Stringer("socks5client", conn.LocalAddr()), zap.Error(err))
				} else {
					ss.Logger.Error("error in socks5 handShake", zap.Stringer("socks5client", conn.LocalAddr()), zap.Error(err))
				}
				conn.Close()
				return
			}
			conn.SetDeadline(time.Time{})

			switch cmd {
			case socksCmdConnect:
				// in tcp module
				go handleConnection(server, conn, config.Timeout)
			case socksCmdUDPAssocation:
				// in udp module
				go handleUDPConnection(server, conn, config.Timeout)
			default:
				ss.Logger.Error("error in Socks5 dital request read command, ", zap.Int("command", cmd))
				return
			}
		}()
	}
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

// main locical about the local server
func main() {
	var configFile, ServerAddr, LocalPort, LocalAddr, Password, Method, MultiServerMode string
	var ServerPort, Timeout, matrixport int
	var printVer bool
	var config *ss.Config
	var err error

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "config", "", "specify config file")
	flag.StringVar(&LocalAddr, "addr", "127.0.0.1", "local socks5 proxy serve address")
	flag.StringVar(&LocalPort, "port", "1085", "local socks5 proxy port")
	flag.StringVar(&ServerAddr, "saddr", "", "server address")
	flag.IntVar(&ServerPort, "sport", 0, "server port")
	//flag.BoolVar(&UDP, "u", false, "use the udp to serve")
	flag.IntVar(&matrixport, "pprof", 0, "set the metrix port to Enable the pprof and matrix(TODO), keep it 0 will disable this feature")
	flag.StringVar(&MultiServerMode, "multiserver", "fastest", "3 modes for shadowsocks local detect ss server: \n\t\tfastest: get fastest server to request\n\t\tround-robin: get server with round-robin for request\n\t\tdissable: only request for first server")
	flag.StringVar(&Password, "passwd", "", "server password")
	flag.IntVar(&Timeout, "timeout", 300, "timeout in seconds")
	flag.StringVar(&Method, "method", "aes-256-cfb", "encryption method, default: aes-256-cfb")
	flag.StringVar(&ss.Level, "level", "info", "given the logger level for ss to logout info, can be set in debug info warn error panic")

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
	ss.Logger.Info("Starting shadowsocks local server")

	// set the pprof
	if matrixport > 0 {
		go http.ListenAndServe(":"+strconv.Itoa(matrixport), nil)
	}

	// set the options for the config new
	var opts []ss.ConfOption

	// choose the encrypt method then check
	if Method == "" {
		// TODO change into gcm AEAD
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
	if LocalPort != "" {
		opts = append(opts, ss.WithLocalPort(LocalPort))
	}
	opts = append(opts, ss.WithMultiServerMode(MultiServerMode))

	config, err = ss.NewConfig(opts...)
	if err != nil {
		ss.Logger.Fatal("error in new config", zap.Error(err))
	}

	// parse the config from the config file
	if configFile != "" {
		if config, err = ss.ParseConfig(configFile); err != nil {
			ss.Logger.Fatal("error in read the config file", zap.String("config file", configFile), zap.Error(err))
		}
	}

	ss.Logger.Debug("show the ss config", zap.Stringer("config", config))
	// start the socks5 server
	go run(config)

	waitSignal()
}
