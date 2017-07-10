package shadowsocks

import (
	"errors"
	"net"
	"time"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

// SecureConn is a secured connection with shadowsocks protocol
// also implements net.Conn interface
type SecureConn struct {
	*net.TCPConn
	*encrypt.Cipher
	readBuf  []byte
	writeBuf []byte
	chunkID  uint32
	//isServerSide bool
	timeout int
}

// NewSecureConn creates a SecureConn
func NewSecureConn(c *net.TCPConn, cipher *encrypt.Cipher, timeout int) *SecureConn {
	return &SecureConn{
		TCPConn:  c,
		Cipher:   cipher,
		writeBuf: leakyBuf.Get(),
		timeout:  timeout,
	}
}

// CloseRead closes the connection.
func (c *SecureConn) CloseRead() error {
	leakyBuf.Put(c.writeBuf)
	return c.TCPConn.CloseRead()
}

// CloseWrite closes the connection.
func (c *SecureConn) CloseWrite() error {
	leakyBuf.Put(c.writeBuf)
	return c.TCPConn.CloseWrite()
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	leakyBuf.Put(c.writeBuf)
	return c.TCPConn.Close()
}

func (c *SecureConn) getAndIncrChunkID() (chunkID uint32) {
	chunkID = c.chunkID
	c.chunkID++
	return
}

// Read the data from ss connection, then decrypted
func (c *SecureConn) Read(b []byte) (n int, err error) {
	if c.timeout > 0 {
		c.TCPConn.SetReadDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}

	if c.DecInited() {
		iv := make([]byte, c.GetIVLen())
		if _, err = c.TCPConn.Read(iv); err != nil {
			return
		}
		if err = c.InitDecrypt(iv); err != nil {
			return
		}
		if len(c.GetIV()) == 0 {
			c.SetIV(iv)
		}
	}

	n, err = c.TCPConn.Read(b)
	if n > 0 {
		// decrypt the data with given cipher
		c.Decrypt(b[:n], b[:n])
	}
	return
}

func (c *SecureConn) Write(b []byte) (n int, err error) {
	var iv []byte

	if c.Cipher.EncInited() {
		iv, err = c.Cipher.InitEncrypt()
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

	if len(iv) > 0 {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
		//} else {
		//	Logger.Error("error in set the iv into cipher data", zap.Int("iv len", len(iv)))
	}

	c.Encrypt(cipherData[len(iv):], b)
	if c.timeout > 0 {
		c.TCPConn.SetWriteDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	n, err = c.TCPConn.Write(cipherData[:dataSize])
	// dec the iv lenth
	n -= len(iv)
	return
}

// Listener is like net.Listener, but a little different
type Listener struct {
	tcpln   net.Listener
	cipher  *encrypt.Cipher
	timeout int
}

// Accept just like net.Listener.Accept(), but with additional return variable host.
// It will handle the request header for you.
// BUG the Accept can be blocked by catching a not SS protocol, the acceptr could be blocked
func (ln *Listener) Accept() (sconn *SecureConn, err error) {
	conn, err := ln.tcpln.Accept()
	if err != nil {
		return nil, err
	}

	// set the tcp keep alive option
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("error in convert into tcp connection")
	}
	tcpConn.SetKeepAlive(true)
	if ln.timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(ln.timeout)))
		conn.SetWriteDeadline(time.Now().Add(time.Duration(ln.timeout)))
	}
	ss := NewSecureConn(tcpConn, ln.cipher.Copy(), ln.timeout)

	return ss, nil
}

// warped net.Listener
func (ln *Listener) Addr() net.Addr {
	return ln.tcpln.Addr()
}

// warped net.Listener
func (ln *Listener) Close() error {
	return ln.tcpln.Close()
}

// Listen announces on the TCP address laddr and returns a TCP listener.
// Net must be "tcp", "tcp4", or "tcp6".
// If laddr has a port of 0, ListenTCP will choose an available port.
// The caller can use the Addr method of TCPListener to retrieve the chosen address.
func Listen(network, laddr string, cipher *encrypt.Cipher, timeout int) (*Listener, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		tcpln:   ln,
		cipher:  cipher,
		timeout: timeout,
	}, nil
}
