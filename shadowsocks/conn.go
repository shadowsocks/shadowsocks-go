package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

const (
	OneTimeAuthMask byte = 0x10
	AddrMask        byte = 0xf
)

type Conn struct {
	net.Conn
	*encrypt.Cipher
	readBuf  []byte
	writeBuf []byte
	chunkId  uint32
	ota      bool
}

func NewConn(c net.Conn, cipher *encrypt.Cipher) *Conn {
	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  leakyBuf.Get(),
		writeBuf: leakyBuf.Get()}
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
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
func DialWithRawAddr(rawaddr []byte, server string, cipher *encrypt.Cipher, ota bool) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if ota {
		if c.EncInited() {
			if _, err = c.InitEncrypt(); err != nil {
				return
			}
		}
		// since we have initEncrypt, we must send iv manually
		conn.Write(c.GetIV())
		rawaddr[0] |= OneTimeAuthMask
		rawaddr = otaConnectAuth(c.GetIV(), c.GetKey(), rawaddr)
	}
	if _, err = c.write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *encrypt.Cipher, ota bool) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher, ota)
}

func (c *Conn) GetIv() (iv []byte) {
	return c.Cipher.GetIV()
}

func (c *Conn) GetKey() (key []byte) {
	return c.Cipher.GetKey()
}

func (c *Conn) IsOta() bool {
	return c.ota
}

func (c *Conn) GetAndIncrChunkId() (chunkId uint32) {
	chunkId = c.chunkId
	c.chunkId += 1
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.DecInited() {
		iv := make([]byte, c.GetIVLen())
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.InitDecrypt(iv); err != nil {
			return
		}
		if len(c.GetIV()) == 0 {
			c.SetIV(iv)
		}
	}

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.Decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	nn := len(b)
	if c.ota {
		chunkId := c.GetAndIncrChunkId()
		b = otaReqChunkAuth(c.GetIV(), chunkId, b)
	}
	headerLen := len(b) - nn

	n, err = c.write(b)
	// Make sure <= 0 <= len(b), where b is the slice passed in.
	if n >= headerLen {
		n -= headerLen
	}
	return
}

func (c *Conn) write(b []byte) (n int, err error) {
	var iv []byte
	if c.EncInited() {
		iv, err = c.InitEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	c.Encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
