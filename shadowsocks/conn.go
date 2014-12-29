package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
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

func (c *UDPConn) getRequest() (src, dst *net.UDPAddr, extra []byte, reqLen int, req []byte, err error) {
	var dstIP net.IP
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
	buf := make([]byte, 512)
	n, src, err := c.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	data := make([]byte, n - c.info.ivLen)
	c.decrypt(data, buf[c.info.ivLen:n])

	switch data[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(data[idDmLen]) + lenDmBase
	default:
		fmt.Sprintf("addr type %d not supported", data[idType])
		return
	}
	extra = data[reqLen:n - c.info.ivLen]
	switch data[idType] {
	case typeIPv4:
		dstIP = net.IP(data[idIP0 : idIP0+net.IPv4len])
	case typeIPv6:
		dstIP = net.IP(data[idIP0 : idIP0+net.IPv6len])
	case typeDm:
		dstIP = net.ParseIP(string(data[idDm0 : idDm0+data[idDmLen]]))
	}
	dst = &net.UDPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(data[reqLen-2 : reqLen])),
	}
	req = data[:reqLen]
	return
}

func (c *UDPConn) resRequest(src, dst *net.UDPAddr, extra []byte, reqLen int, req []byte) {
	var buf [512]byte
	remote, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return
	}
	_, err = remote.Write([]byte(extra))
	if err != nil {
		return
	}
	n, err := remote.Read(buf[0:])
	if err != nil {
		return
	}
	send := append(req, buf[0:n]...)
	
	var cipherData []byte
	var iv []byte
	iv, err = c.initEncrypt()
	dataStart := c.info.ivLen
	cipherData = make([]byte, n + reqLen + c.info.ivLen)
	copy(cipherData, iv)
	c.encrypt(cipherData[dataStart:], send)
	_, err = c.WriteToUDP(cipherData, src)
	if err != nil {
		return
	}
	return
}

func (c *UDPConn) HandleUDPConnection()  {
	src, dst, extra, reqLen, req, err := c.getRequest()
	if err != nil {
		return
	}
	go c.resRequest(src, dst, extra, reqLen, req)
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
