package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

const (
	maxPacketSize = 4096 // increase it if error occurs
)

var (
	errPacketTooSmall  = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge  = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall  = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
	errPacketOtaFailed = fmt.Errorf("[udp]read error: received packet has invalid ota")
	errInvalidHostname = fmt.Errorf("errInvalidHostname")
)

// SecurePacketConn is the implementation of
// net.PacketConn interfaces for shadowsocks UDP network connections.
type SecurePacketConn struct {
	net.PacketConn
	*encrypt.Cipher
	ota bool
}

// ListenPacket is like net.ListenPacket() but returns an secured connection
func ListenPacket(network, laddr string, config *Config) (*SecurePacketConn, error) {
	cipher, err := encrypt.NewCipher(config.Method, config.Password)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewSecurePacketConn(conn, cipher, config.Auth), nil
}

// NewSecurePacketConn creates a secured PacketConn
func NewSecurePacketConn(c net.PacketConn, cipher *encrypt.Cipher, ota bool) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
		ota:        ota,
	}
}

// Close closes the connection.
func (c *SecurePacketConn) Close() error {
	return c.PacketConn.Close()
}

// ReadFrom reads a packet from the connection.
func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	ota := false
	cipher := c.Copy()
	buf := make([]byte, 4096)
	ivLen := cipher.GetIVLen()
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
	if b[idType]&OneTimeAuthMask > 0 {
		ota = true
	}

	if c.ota && !ota {
		return 0, src, errPacketOtaFailed
	}

	if ota {
		key := cipher.GetKey()
		actualHmacSha1Buf := HmacSha1(append(iv, key...), b[:n-lenHmacSha1])
		if !bytes.Equal(b[n-lenHmacSha1:n], actualHmacSha1Buf) {
			Debug.Printf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, b[:n])
			return 0, src, errPacketOtaFailed
		}
		n -= lenHmacSha1
	}

	return
}

// WriteTo writes a packet with payload b to addr.
func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	cipher := c.Copy()
	iv, err := cipher.InitEncrypt()
	if err != nil {
		return
	}
	packetLen := len(b) + len(iv)

	if c.ota {
		b[idType] |= OneTimeAuthMask
		packetLen += lenHmacSha1
		key := cipher.GetKey()
		actualHmacSha1Buf := HmacSha1(append(iv, key...), b)
		b = append(b, actualHmacSha1Buf...)
	}

	cipherData := make([]byte, packetLen)
	copy(cipherData, iv)

	cipher.Encrypt(cipherData[len(iv):], b)
	n, err = c.PacketConn.WriteTo(cipherData, dst)
	if c.ota {
		n -= lenHmacSha1
	}
	return
}

// LocalAddr returns the local network address.
func (c *SecurePacketConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (c *SecurePacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// If the deadline is reached, Read will fail with a timeout
// (see type Error) instead of blocking.
// A zero value for t means Read will not time out.
func (c *SecurePacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// If the deadline is reached, Write will fail with a timeout
// (see type Error) instead of blocking.
// A zero value for t means Write will not time out.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
func (c *SecurePacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

// IsOta returns true if the connection is OTA enabled
func (c *SecurePacketConn) IsOta() bool {
	return c.ota
}

// ForceOTA returns an OTA forced connection
func (c *SecurePacketConn) ForceOTA() net.PacketConn {
	return NewSecurePacketConn(c.PacketConn, c.Cipher.Copy(), true)
}
