package shadowsocks

import (
	"bytes"
	"fmt"
	"net"

	"go.uber.org/zap"

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
	ota      bool
}

// ListenPacket is like net.ListenPacket() but returns an secured connection
func ListenPacket(network, laddr string, cipher *encrypt.Cipher, ota bool) (*SecurePacketConn, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	conn, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewSecurePacketConn(conn, cipher, ota), nil
}

// NewSecurePacketConn creates a secured PacketConn
func NewSecurePacketConn(c net.PacketConn, cipher *encrypt.Cipher, ota bool) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
		ota:        ota,
	}
}

// ReadFrom reads a packet from the connection.
func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	ota := false
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
	if b[idType]&OneTimeAuthMask > 0 {
		ota = true
	}

	if c.ota && !ota {
		return 0, src, ErrPacketOtaFailed
	}

	if ota {
		key := cipher.GetKey()
		actualHmacSha1Buf := HmacSha1(append(iv, key...), b[:n-lenHmacSha1])
		if !bytes.Equal(b[n-lenHmacSha1:n], actualHmacSha1Buf) {
			Logger.Error("verify one time auth failed: ", zap.String("iv", fmt.Sprint(iv)),
				zap.String("key", fmt.Sprint(key)), zap.String("Buf", fmt.Sprint(b[:n])))
			return 0, src, ErrPacketOtaFailed
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
		return 0, err
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

// IsOta returns true if the connection is OTA enabled
func (c *SecurePacketConn) IsOta() bool {
	return c.ota
}

// ForceOTA returns an OTA forced connection
func (c *SecurePacketConn) ForceOTA() net.PacketConn {
	return NewSecurePacketConn(c.PacketConn, c.Cipher.Copy(), true)
}
