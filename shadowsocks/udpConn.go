package shadowsocks

import (
	"net"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

const (
	maxPacketSize = 4096 // increase it if error occurs
)

// SecurePacketConn is the implementation of
// net.PacketConn interfaces for shadowsocks UDP network connections.
type SecurePacketConn struct {
	net.PacketConn
	*encrypt.Cipher
	isClient bool
}

// ListenPacket is like net.ListenPacket() but returns an secured connection
func ListenPacket(network, laddr string, cipher *encrypt.Cipher) (*SecurePacketConn, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	conn, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewSecurePacketConn(conn, cipher), nil
}

// NewSecurePacketConn creates a secured PacketConn
func NewSecurePacketConn(c net.PacketConn, cipher *encrypt.Cipher) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
	}
}

// ReadFrom reads a packet from the connection.
func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	cipher := c.Copy()
	buf := make([]byte, 4096)
	ivLen := cipher.GetIVLen()
	// it should alway listen for packets, no timeout
	n, src, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	if n < ivLen {
		return 0, nil, errPacketTooSmall
	}

	if len(b) < n-ivLen {
		err = errBufferTooSmall // just a warning
	}

	iv := make([]byte, ivLen)
	copy(iv, buf[:ivLen])

	if err = cipher.InitDecrypt(iv); err != nil {
		return
	}

	cipher.Decrypt(b[0:], buf[ivLen:n])
	n -= ivLen

	return
}

// WriteTo writes a packet with payload b to addr.
func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	cipher := c.Copy()
	iv, err := cipher.InitEncrypt()
	if err != nil {
		return 0, err
	}
	packetLen := len(b) + len(iv)

	cipherData := make([]byte, packetLen)
	copy(cipherData, iv)

	cipher.Encrypt(cipherData[len(iv):], b)
	n, err = c.PacketConn.WriteTo(cipherData, dst)
	return
}
