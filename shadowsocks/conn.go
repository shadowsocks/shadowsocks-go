package shadowsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

type Conn struct {
	net.Conn
	Cipher
}

func NewConn(cn net.Conn, cipher Cipher) *Conn {
	return &Conn{cn, cipher}
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("shadowsocks: address error %s %v", addr, err))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("shadowsocks: invalid port %s", addr))
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
func DialWithRawAddr(rawaddr []byte, server string, cipher Cipher) (c *Conn, err error) {
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
func Dial(addr, server string, cipher Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

func (c Conn) Read(b []byte) (n int, err error) {
	cipherData := make([]byte, len(b), len(b))
	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.Decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c Conn) Write(b []byte) (n int, err error) {
	cipherData := make([]byte, len(b), len(b))
	c.Encrypt(cipherData, b)
	n, err = c.Conn.Write(cipherData)
	return
}
