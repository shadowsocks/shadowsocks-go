package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
	"io"
)

type Conn struct {
	net.Conn
	encrypted bool
	decrypted bool
	cryptor Cryptor
}

func NewConn(c net.Conn, cryptor Cryptor) (conn *Conn) {
	conn = &Conn{
		Conn:     c,
		cryptor: cryptor,
	}
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.decrypted { if err = c.cryptor.initDecrypt(c.Conn, c.Conn); err != nil { return }; c.decrypted = true }
	return c.cryptor.UnPack(b) }
func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.encrypted { if err = c.cryptor.initEncrypt(c.Conn, c.Conn); err != nil { return }; c.encrypted = true }
	return c.cryptor.Pack(b) }
func (c *Conn) Packing(r io.Reader) (n int, err error) {
	buffer, err := c.cryptor.GetBuffer(); if err != nil { return }; buf := buffer.Get(); defer buffer.Put(buf)
	if n, err = r.Read(buf); err != nil { return }; return c.Write(buf[:n]) }
func (c *Conn) UnPacking(w io.Writer) (n int, err error) {
	buffer, err := c.cryptor.GetBuffer(); if err != nil { return }
	buf := buffer.Get(); defer buffer.Put(buf)

	if n, err = c.Read(buf); err != nil { return }
	if _, err = w.Write(buf[:n]); err != nil { return }
	Logger.Fields(LogFields{
		"n": n,
		"buf_size": len(buf),
	}).Info("check size")
	if n == len(buf) {
		n, err = c.UnPacking(w); if err != nil { return }
	}

	return
}

func (c *Conn) Close() error { return c.Conn.Close() }
func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr); if err != nil { return }
	port, err := strconv.Atoi(portStr); if err != nil { return }

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return }
func DialWithRawAddr(rawaddr []byte, server string, cryptor Cryptor) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server); if err != nil { return }
	c = NewConn(conn, cryptor); if _, err = c.Write(rawaddr); err != nil { c.Close(); return }; return }
// addr should be in the form of host:port
func Dial(addr, server string, cryptor Cryptor) (c *Conn, err error) {
	ra, err := RawAddr(addr); if err != nil { return }; return DialWithRawAddr(ra, server, cryptor) }