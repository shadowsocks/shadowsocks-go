package shadowsocks

import (
	"io"
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
	conn := SecureConn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  bufferPool.Get().([]byte),
		writeBuf: bufferPool.Get().([]byte),
		timeout:  timeout,
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}
	return &conn
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	defer bufferPool.Put(c.writeBuf)
	defer bufferPool.Put(c.readBuf)
	return c.Conn.Close()
}

// CloseRead closes the connection.
func (c *SecureConn) CloseRead() error {
	defer bufferPool.Put(c.readBuf)
	return c.Conn.(*net.TCPConn).CloseRead()
}

// CloseWrite closes the connection.
func (c *SecureConn) CloseWrite() error {
	defer bufferPool.Put(c.writeBuf)
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func (c *SecureConn) Read(b []byte) (n int, err error) {
	if c.DecryptorInited() {
		n, err := io.ReadFull(c.Conn, c.readBuf[:c.InitBolckSize()])
		if err != nil {
			return -1, err
		}
		if n != c.InitBolckSize() {
			return -1, ErrUnexpectedIO
		}
		err = c.InitDecryptor(c.readBuf[:c.InitBolckSize()])
		if err != nil {
			return -1, err
		}
	}

	destlen := len(b)

	n, err = c.Conn.Read(c.readBuf[:destlen])
	if err != nil {
		return n, err
	}

	nn, err := c.Cipher.Decrypt(c.readBuf[:n], b)
errAgain:
	if err != nil {
		// handle the aead cipher bug
		if err == encrypt.ErrAgain {
			nnn, errR := c.Conn.Read(c.readBuf[:nn])
			if errR != nil {
				return -1, err
			}
			if nnn != nn {
				return -1, ErrUnexpectedIO
			}
			nn, err = c.Cipher.Decrypt(c.readBuf[:nnn], b)
			n = nnn
			goto errAgain
		}
		return -1, err
	}
	return nn, nil
}

func (c *SecureConn) Write(b []byte) (n int, err error) {
	if c.EncryptorInited() {
		data, err := c.InitEncryptor()
		if err != nil {
			return -1, err
		}
		n, err = c.Conn.Write(data)
		if err != nil {
			return -1, err
		}
		if n != c.InitBolckSize() {
			return -1, ErrUnexpectedIO
		}
	}

	n, err = c.Encrypt(b, c.writeBuf)
	if err != nil {
		return -1, err
	}

	nn, err := c.Conn.Write(c.writeBuf[:n])
	if nn != n {
		return nn, ErrUnexpectedIO
	}

	return nn, err
}

// secureListener is like net.Listener
type secureListener struct {
	net.Listener
	cipher  encrypt.Cipher
	timeout int
}

// Accept just like net.Listener.Accept()
func (ln *secureListener) Accept() (conn net.Conn, err error) {
	conn, err = ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ss := NewSecureConn(conn, ln.cipher.Copy(), ln.timeout)
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
func SecureListen(network, laddr string, cipher encrypt.Cipher, timeout int) (net.Listener, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &secureListener{ln, cipher, timeout}, nil
}
