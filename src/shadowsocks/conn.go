package shadowsocks

import (
	"errors"
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

var initTableCalled = false

func InitTable(passwd string) {
	encTable, decTable = GetTable(passwd)
	initTableCalled = true
}

// addr should be in the form of host:port
func Dial(addr string, server string) (c Conn, err error) {
	if !initTableCalled {
		panic("shadowsocks internal error, must call InitTable first.")
	}
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}

	arr := strings.Split(addr, ":")
	if len(arr) != 2 {
		c.Close()
		return Conn{}, errors.New("shadowsocks: malformed dial address")
	}
	host, portStr := arr[0], arr[1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		return Conn{}, err
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf := make([]byte, l, l)
	buf[0] = 3
	buf[1] = byte(hostLen)
	copy(buf[2:], host)
	buf[2+hostLen] = byte(port >> 8 & 0xFF)
	buf[2+hostLen+1] = byte(port) & 0xFF

	c = Conn{conn}
	_, err = c.Write(buf)
	if err != nil {
		c.Close()
		return
	}
	return
}

func (c Conn) Read(b []byte) (n int, err error) {
	buf := make([]byte, len(b), len(b))
	n, err = c.Read(buf)
	if n > 0 {
		Encrypt2(decTable, buf[0:n], b[0:n])
	}
	return
}

func (c Conn) Write(b []byte) (n int, err error) {
	buf := Encrypt(encTable, b)
	n, err = c.Write(buf)
	return
}
