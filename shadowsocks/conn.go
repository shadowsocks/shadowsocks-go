package shadowsocks

import (
	"errors"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Conn struct {
	net.Conn
	*EncryptTable
}

func NewConn(cn net.Conn, encTbl *EncryptTable) *Conn {
	return &Conn{cn, encTbl}
}

func RawAddr(addr string) (buf []byte, err error) {
	arr := strings.Split(addr, ":")
	if len(arr) != 2 {
		return nil, errors.New(
			fmt.Sprintf("shadowsocks: malformed address %s", addr))
	}
	host, portStr := arr[0], arr[1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("shadowsocks: invalid port %s", addr))
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, encTbl *EncryptTable) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, encTbl)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, encTbl *EncryptTable) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, encTbl)
}

func (c Conn) Read(b []byte) (n int, err error) {
	buf := make([]byte, len(b), len(b))
	n, err = c.Conn.Read(buf)
	if n > 0 {
		encrypt2(c.DecTbl, buf[0:n], b[0:n])
	}
	return
}

func (c Conn) Write(b []byte) (n int, err error) {
	buf := encrypt(c.EncTbl, b)
	n, err = c.Conn.Write(buf)
	return
}
