package shadowsocks

import (
	"net"
	"time"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

// SecurePacketConn is the implementation of
// net.PacketConn interfaces for shadowsocks UDP network connections.
type SecurePacketConn struct {
	net.PacketConn
	encrypt.Cipher
	timeout  int
	readBuf  []byte
	writeBuf []byte
}

// ListenPacket is like net.ListenPacket() but returns an secured connection
func SecureListenPacket(network, laddr string, cipher encrypt.Cipher, timeout int) (net.PacketConn, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	conn, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewSecurePacketConn(conn, cipher, timeout), nil
}

// NewSecurePacketConn creates a secured PacketConn
func NewSecurePacketConn(c net.PacketConn, cipher encrypt.Cipher, timeout int) net.PacketConn {
	pkt := SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
		timeout:    timeout,
		readBuf:    readBufferPool.Get().([]byte),
	}
	if timeout > 0 {
		pkt.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}
	return &pkt
}

// ReadFrom reads a packet from the connection.
func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	// it should alway listen for packets, no timeout
	n, src, err = c.PacketConn.ReadFrom(c.readBuf)
	if err != nil {
		return
	}

	nn, err := c.Unpack(b, c.readBuf[:n])
	return nn, src, err
}

// WriteTo writes a packet with payload b to addr.
func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	n, err = c.Pack(b, c.writeBuf[0:])
	if err != nil {
		return
	}

	nn, err := c.PacketConn.WriteTo(c.writeBuf[:n], dst)
	return nn, err
}
