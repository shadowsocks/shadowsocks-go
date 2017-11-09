package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"github.com/qunxyz/shadowsocks-go/shadowsocks/crypto"
)

const (
	OneTimeAuthMask byte = 0x10
	AddrMask        byte = 0xf
)

type Conn struct {
	net.Conn
	*crypto.Cipher
	readBuf  []byte
	writeBuf []byte
}

func NewConn(c net.Conn, cipher *crypto.Cipher) *Conn {
	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  LeakyBuf.Get(),
		writeBuf: LeakyBuf.Get()}
}

func (c *Conn) Close() error {
	LeakyBuf.Put(c.readBuf)
	LeakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
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
func DialWithRawAddr(rawaddr []byte, server string, cipher *crypto.Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)

	if _, err = c.write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *crypto.Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.unpack(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	nn := len(b)
	headerLen := len(b) - nn

	n, err = c.write(b)
	// Make sure <= 0 <= len(b), where b is the slice passed in.
	if n >= headerLen {
		n -= headerLen
	}
	return
}
//////////////////////////////////////////////////////////////////
func (c *Conn) write(b []byte) (n int, err error) {
	cipherData, err := c.pack(b)
	if err != nil {
		return
	}

	n, err = c.Conn.Write(cipherData)
	return
}

func (c *Conn) pack(b []byte) (cipher_data []byte, err error)  {
	return c.Pack(b, c.writeBuf)
}

func (c *Conn) unpack(b []byte) (n int, err error) {
	return c.UnPack(c.Conn, b, c.readBuf)
}