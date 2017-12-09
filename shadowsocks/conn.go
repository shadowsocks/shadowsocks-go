package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Conn struct {
	net.Conn
	Buffer    []byte
	Encryptor StreamEnCryptor
	DeCryptor StreamDeCryptor
}

func NewConn(c net.Conn, cipher Cipher) (conn *Conn) {
	cryptor := NewStreamCryptor(cipher)
	conn = &Conn{
		Conn:      c,
		Encryptor: cryptor.initCryptor(Encrypt).(StreamEnCryptor),
		DeCryptor: cryptor.initCryptor(Decrypt).(StreamDeCryptor),
		Buffer:    cryptor.GetBuffer(),
	}

	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.DeCryptor.ReadTo(b, c.Conn)
}
func (c *Conn) Write(b []byte) (n int, err error) {
	return c.Encryptor.WriteTo(b, c.Conn)
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}
func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
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
func DialWithRawAddr(rawaddr []byte, server string, cipher Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
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
