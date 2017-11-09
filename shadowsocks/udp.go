package shadowsocks

import (
	"net"
	"time"
	"github.com/qunxyz/shadowsocks-go/shadowsocks/crypto"
)

type SecurePacketConn struct {
	net.PacketConn
	*crypto.Cipher
}

func NewSecurePacketConn(c net.PacketConn, cipher *crypto.Cipher) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
	}
}

func (c *SecurePacketConn) Close() error {
	return c.PacketConn.Close()
}

func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	return c.UnPackUDP(c.PacketConn, b)
}

func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	return c.PackUDP(c, b, dst)
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
