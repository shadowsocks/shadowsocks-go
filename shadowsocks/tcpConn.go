package shadowsocks

import (
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

const (
	BufferSize = 0x7FFF // 32K for each buffer
)

// buffer pool for cipher buffer reuse
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, BufferSize, BufferSize)
	},
}

// SecureConn is a secured connection with shadowsocks protocol
// also implements net.Conn interface
type SecureConn struct {
	net.Conn
	encrypt.Cipher
	readBuf      []byte
	writeBuf     []byte
	timeout      int
	chunkID      uint32 //
	isServerSide bool   //
}

// NewSecureConn creates a SecureConn
func NewSecureConn(c net.Conn, cipher encrypt.Cipher, timeout int) net.Conn {
	return &SecureConn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  bufferPool.Get().([]byte),
		writeBuf: bufferPool.Get().([]byte),
		timeout:  timeout,
		//ota:     ota,
		//isServerSide: isServerSide,
	}
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	defer leakyBuf.Put(c.writeBuf)
	defer leakyBuf.Put(c.readBuf)
	return c.Conn.Close()
}

func (c *SecureConn) Read(b []byte) (n int, err error) {
	// TODO
	if c.timeout > 0 {
		c.SetReadDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	n, err := c.Conn.Read(c.readBuf)
	return c.Cipher.Decrypt(b, c.readBuf)
}

func (c *SecureConn) Write(b []byte) (n int, err error) {
	n, err := c.Encrypt(b, c.writeBuf)
	if err != nil {
		// TODO
	}

	// TODO
	if c.timeout > 0 {
		c.SetWriteDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	nn, err := c.Conn.Write(c.writeBuf)
	if nn != n {
		// XXX FIXME
	}

	return nn, err
}

// Listener is like net.Listener
type Listener struct {
	net.Listener
	cipher  encrypt.Cipher
	timeout int
}

// Accept just like net.Listener.Accept()
func (ln *Listener) Accept() (conn net.Conn, err error) {
	conn, err = ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ss := NewSecureConn(conn, ln.cipher.Copy(), false, ln.timeout, true)
	if err != nil {
		ss.Close()
		return nil, err
	}
	return ss, nil
}

// Listen announces on the TCP address laddr and returns a TCP listener.
// Net must be "tcp", "tcp4", or "tcp6".
// If laddr has a port of 0, ListenTCP will choose an available port.
// The caller can use the Addr method of TCPListener to retrieve the chosen address.
func Listen(network, laddr string, cipher encrypt.Cipher, timeout int) (net.Listener, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{ln, cipher, timeout}, nil
}
