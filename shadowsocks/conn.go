package shadowsocks

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	encTable []byte
	decTable []byte
)

type Conn struct {
	net.Conn
}

func InitTable(passwd string) {
	encTable, decTable = GetTable(passwd)
}

func addrBufFromString(addr string) (buf []byte, err error) {
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
	buf[0] = 3
	buf[1] = byte(hostLen)
	copy(buf[2:], host)
	buf[2+hostLen] = byte(port >> 8 & 0xFF)
	buf[2+hostLen+1] = byte(port) & 0xFF
	return
}

// Export this for use by local.go and server.go
func DialWithAddrBuf(addrBuf []byte, server string) (c Conn, err error) {
	if encTable == nil {
		panic("shadowsocks internal error, must call InitTable first.")
	}
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = Conn{conn}
	if _, err = c.Write(addrBuf); err != nil {
		c.Close()
		return
	}
	return
}

// addr should be in the form of host:port
func Dial(addr string, server string) (c Conn, err error) {
	addrBuf, err := addrBufFromString(addr)
	if err != nil {
		return
	}
	return DialWithAddrBuf(addrBuf, server)
}

func (c Conn) Read(b []byte) (n int, err error) {
	buf := make([]byte, len(b), len(b))
	n, err = c.Conn.Read(buf)
	if n > 0 {
		Encrypt2(decTable, buf[0:n], b[0:n])
	}
	return
}

func (c Conn) Write(b []byte) (n int, err error) {
	buf := Encrypt(encTable, b)
	n, err = c.Conn.Write(buf)
	return
}
