package shadowsocks

import (
	"errors"
	"net"
)

type UDPConn struct {
	*net.UDPConn
	*Cipher
	readBuf []byte
	// writeBuf []byte
	// for shadowsocks-go
	natlist NATlist
}

func NewUDPConn(c *net.UDPConn, cipher *Cipher) *UDPConn {
	return &UDPConn{
		UDPConn: c,
		Cipher:  cipher,
		readBuf: leakyBuf.Get(),
		// for thread safety
		// writeBuf: leakyBuf.Get(),
		// for shadowsocks-go
		natlist: NATlist{conns: map[string]*CachedUDPConn{}},
	}
}

func (c *UDPConn) Close() error {
	leakyBuf.Put(c.readBuf)
	//leakyBuf.Put(c.writeBuf)
	return c.UDPConn.Close()
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	buf := c.readBuf
	n, err = c.UDPConn.Read(buf[0:])
	if err != nil {
		return
	}

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n-c.info.ivLen], buf[c.info.ivLen:n])
	n = n - c.info.ivLen
	return
}

func (c *UDPConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	n, src, err = c.UDPConn.ReadFrom(c.readBuf[0:])
	if err != nil {
		return
	}
	if n < c.info.ivLen {
		return 0, nil, errors.New("[udp]read error: cannot decrypt")
	}
	iv := make([]byte, c.info.ivLen)
	copy(iv, c.readBuf[:c.info.ivLen])
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n-c.info.ivLen], c.readBuf[c.info.ivLen:n])
	n = n - c.info.ivLen
	return
}

func (c *UDPConn) ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error) {
	n, src, err = c.UDPConn.ReadFromUDP(c.readBuf[0:])
	if err != nil {
		return
	}
	if n < c.info.ivLen {
		return 0, nil, errors.New("[udp]read error: cannot decrypt")
	}
	iv := make([]byte, c.info.ivLen)
	copy(iv, c.readBuf[:c.info.ivLen])
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n-c.info.ivLen], c.readBuf[c.info.ivLen:n])
	n = n - c.info.ivLen
	return
}

// Maybe some thread safe issue with Write and encryption
func (c *UDPConn) Write(b []byte) (n int, err error) {
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData := make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)

	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDPConn.Write(cipherData)
	return
}

func (c *UDPConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData := make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart := len(iv)

	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDPConn.WriteTo(cipherData, dst)
	return
}

func (c *UDPConn) WriteToUDP(b []byte, dst *net.UDPAddr) (n int, err error) {
	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData := make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart := len(iv)

	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDPConn.WriteToUDP(cipherData, dst)
	return
}
