package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Conn struct {
	net.Conn
	cipher *Cipher
	buffer *LeakyBufType
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	conn := &Conn{
		Conn:     c,
		buffer: leakyBuf,
		cipher: cipher,
	}
	return conn
}

func (c *Conn) Close() error {
	c.buffer.Put(c.buffer.Get())
	return c.Conn.Close()
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		Logger.Fields(LogFields{
			"addr": addr,
			"err": err,
		}).Warn("shadowsocks: address error")
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		Logger.Fields(LogFields{
			"portStr": portStr,
			"err": err,
		}).Warn("shadowsocks: invalid port")
		return nil, err
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
		Logger.Fields(LogFields{
			"server": server,
			"err": err,
		}).Warn("shadowsocks: Dialing to server")
		return
	}
	c = NewConn(conn, cipher)

	if _, err = c.write(rawaddr); err != nil {
		Logger.Fields(LogFields{
			"rawaddr": rawaddr,
			"err": err,
		}).Warn("shadowsocks: Writing rawaddr")
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		Logger.Fields(LogFields{
			"addr": addr,
			"err": err,
		}).Warn("shadowsocks: Parsing addr")
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	p := newPacketStream(c, Decrypt)
	p.initPacket(b)
	data, err := p.getPacket()
	n = len(data)
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	nn := len(b)
	headerLen := len(b) - nn

	n, err = c.write(b)
	if err != nil {
		Logger.Fields(LogFields{
			"b": b,
			"err": err,
		}).Warn("shadowsocks: write data to socket error")
	}
	// Make sure <= 0 <= len(b), where b is the slice passed in.
	if n >= headerLen {
		n -= headerLen
	}
	return
}

func (c *Conn) write(b []byte) (n int, err error) {
	p := newPacketStream(c, Encrypt)
	p.initPacket(b)
	data, err := p.getPacket()
	n, err = c.Conn.Write(data)

	return
}