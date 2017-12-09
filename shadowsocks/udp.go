package shadowsocks

import (
	"fmt"
	"net"
	"time"
	"sync"
)

const (
	maxPacketSize = 4096 // increase it if error occurs
)

var (
	errPacketTooSmall = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
)

type SecurePacketConn struct {
	net.PacketConn
	Buffer    []byte
	Encryptor PacketEnCryptor
	DeCryptor PacketDeCryptor
	sync.Mutex // write lock
}

func NewSecurePacketConn(c net.PacketConn, cipher Cipher) *SecurePacketConn {
	cryptor := NewCryptor(cipher, true)
	return &SecurePacketConn{
		PacketConn: c,
		Encryptor: cryptor.initCryptor(Encrypt).(PacketEnCryptor).initPacket(c),
		DeCryptor: cryptor.initCryptor(Decrypt).(PacketDeCryptor).initPacket(c),
		Buffer:    cryptor.GetBuffer(),
	}
}

func (c *SecurePacketConn) Close() error {
	return c.PacketConn.Close()
}


func (c *SecurePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()
	return c.Encryptor.WriteTo(b, addr)
}

func (c *SecurePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.DeCryptor.ReadTo(b)
}

func (c *SecurePacketConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

func (c *SecurePacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c *SecurePacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *SecurePacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}
