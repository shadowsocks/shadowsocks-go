package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
	"log"
	"syscall"
)

type Conn struct {
	net.Conn
	*Cipher
}

func NewConn(cn net.Conn, cipher *Cipher) *Conn {
	return &Conn{cn, cipher}
}

type UDPConn struct {
	net.UDPConn
	*Cipher
}

func NewUDPConn(cn net.UDPConn, cipher *Cipher) *UDPConn {
	return &UDPConn{cn, cipher}
}

var udpBuf = NewLeakyBuf(nBuf, bufSize)

func (c *UDPConn) handleUDPConnection(n int, src *net.UDPAddr, receive []byte) {
	var dstIP net.IP
	var reqLen int
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	switch receive[idType] {
	case typeIPv4:
		reqLen = lenIPv4
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv4len])
	case typeIPv6:
		reqLen = lenIPv6
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv6len])
	case typeDm:
		reqLen = int(receive[idDmLen]) + lenDmBase
		dIP, err := net.ResolveIPAddr("ip" ,string(receive[idDm0 : idDm0+receive[idDmLen]]))
		if err != nil{
			fmt.Sprintf("failed to resolve domain name: %s\n", string(receive[idDm0 : idDm0+receive[idDmLen]]))
			return
		}
		dstIP = dIP.IP
	default:
		fmt.Sprintf("addr type %d not supported", receive[idType])
		return
	}
	extra := receive[reqLen:n]
	//avoid memory overlap
	//req := receive[:reqLen]
	req := make([]byte, reqLen)
	for i:=0;i<reqLen;i++ {
		req[i] = receive[i]
	}
	remote, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(receive[reqLen-2 : reqLen])),
	})
	defer remote.Close()
	if err != nil {
		return
	}
	remote.SetWriteDeadline(time.Now().Add(readTimeout))
	_, err = remote.Write(extra)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("write error:", err)
		} else {
			log.Println("error connecting to:", dstIP, err)
		}
		return
	}
	buf := udpBuf.Get()
	defer udpBuf.Put(buf)
	remote.SetReadDeadline(time.Now().Add(readTimeout))
	n, err = remote.Read(buf[0:])
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("read error:", err)
		} else {
			log.Println("error connecting to:", dstIP, err)
		}
		return
	}
	send := append(req, buf[0:n]...)
	_, err = c.WriteToUDP(send, src)
	if err != nil {
		return
	}
	return
}

func (c *UDPConn) ReadAndHandleUDPReq()  {
	buf := udpBuf.Get()
	n, src, err := c.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	defer udpBuf.Put(buf)
	go c.handleUDPConnection(n, src, buf[:n])
}


func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

//n is the size of the payload
func (c *UDPConn) ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error) {
	buf := udpBuf.Get()
	n, src, err = c.UDPConn.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	defer udpBuf.Put(buf)

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n - c.info.ivLen], buf[c.info.ivLen : n])
	n = n - c.info.ivLen
	return
}

//n = iv + payload
func (c *UDPConn) WriteToUDP(b []byte, src *net.UDPAddr) (n int, err error) {
	var cipherData []byte
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData = make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)
	
	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDPConn.WriteToUDP(cipherData, src)
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.initDecrypt(iv); err != nil {
			return
		}
	}
	cipherData := make([]byte, len(b))
	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var cipherData []byte
	dataStart := 0
	if c.enc == nil {
		var iv []byte
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		cipherData = make([]byte, len(b)+len(iv))
		copy(cipherData, iv)
		dataStart = len(iv)
	} else {
		cipherData = make([]byte, len(b))
	}
	c.encrypt(cipherData[dataStart:], b)
	n, err = c.Conn.Write(cipherData)
	return
}