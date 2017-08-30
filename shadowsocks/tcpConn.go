package shadowsocks

import (
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

var (
	BufferSize      = 0x7FFF // BufferSize define pool size for buffer. By default, 32K will give for each buffer
	writeBuffOffset = 0x7F   // make 128 for buffer read offset enhance of aead cipher decryption
	readBufferPool  = sync.Pool{
		New: func() interface{} {
			return make([]byte, BufferSize, BufferSize)
		},
	}
	writeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, BufferSize+writeBuffOffset, BufferSize+writeBuffOffset)
		},
	}
)

// SecureConn is a secured connection with shadowsocks protocol
// also implements net.Conn interface
type SecureConn struct {
	net.Conn
	encrypt.Cipher
	readBuf   []byte
	writeBuf  []byte
	dataCache []byte
	datalen   int // index for the dataCache
	timeout   int
}

// NewSecureConn creates a SecureConn with given cipher and timeout by warp the net.Conn
func NewSecureConn(c net.Conn, cipher encrypt.Cipher, timeout int) net.Conn {
	conn := SecureConn{
		Conn:      c,
		Cipher:    cipher,
		readBuf:   readBufferPool.Get().([]byte),
		writeBuf:  writeBufferPool.Get().([]byte),
		dataCache: writeBufferPool.Get().([]byte),
		timeout:   timeout,
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}
	return &conn
}

// Close closes the connection and free the buffer
func (c *SecureConn) Close() error {
	if c.readBuf != nil {
		readBufferPool.Put(c.readBuf)
	}
	if c.writeBuf != nil {
		writeBufferPool.Put(c.writeBuf)
	}
	if c.dataCache != nil {
		writeBufferPool.Put(c.dataCache)
	}
	c.readBuf, c.dataCache = nil, nil
	return c.Conn.Close()
}

// CloseRead closes the connection on read half
func (c *SecureConn) CloseRead() error {
	if c.readBuf != nil {
		readBufferPool.Put(c.readBuf)
	}
	if c.dataCache != nil {
		writeBufferPool.Put(c.dataCache)
	}
	c.readBuf, c.dataCache = nil, nil
	return c.Conn.(*net.TCPConn).CloseRead()
}

// CloseWrite closes the connection on write half
func (c *SecureConn) CloseWrite() error {
	if c.writeBuf != nil {
		writeBufferPool.Put(c.writeBuf)
	}
	c.writeBuf = nil
	return c.Conn.(*net.TCPConn).CloseWrite()
}

// Read read the data from connection and decrypted with given cipher.
// the data may be cached and return with ErrAgain, that means more data is wantted for decryption
//
// SecureConn Read will take best affort to read the data and decrypt no matter what cipher it is.
// The aead cipher data stream was encrypted data block which with the definitely length. So the cipher
// has a cache inside for tcp stream data caching, and then return the data bolck read from stream if
// the length is enough.
//
// There get a second data cache here which caching the decrypted data in case the len of buffer is less than
// the data we decrypted. The remain data will append in the front of buffer for return when next read comes.
func (c *SecureConn) Read(b []byte) (n int, err error) {
	// initializtion read the salt and init the decoder with salt and key
	if c.DecryptorInited() {
		_, err := io.ReadFull(c.Conn, c.readBuf[:c.InitBolckSize()])
		if err != nil {
			return -1, err
		}
		Logger.Debug("ss read iv", zap.Binary("iv", c.readBuf[:c.InitBolckSize()]))
		err = c.InitDecryptor(c.readBuf[:c.InitBolckSize()])
		if err != nil {
			return -1, err
		}
	}

	if c.datalen > 0 {
		// consume the data first
		ncp := copy(b, c.dataCache[:c.datalen])
		copy(c.dataCache, c.dataCache[ncp:c.datalen])
		c.datalen -= ncp
		return ncp, nil
	}

	n, err = c.Conn.Read(c.readBuf[0:])
	if err != nil {
		return -1, err
	}
	nn, err := c.Cipher.Decrypt(c.readBuf[:n], c.dataCache[c.datalen:])

errAgain:
	if err != nil {
		if err == encrypt.ErrAgain {
			// handle the aead cipher ErrAgain, read again and decrypt
			Logger.Debug("aead return errAgain, request more data", zap.Int("n", nn))
			n, errR := c.Conn.Read(c.readBuf[:nn])
			if errR != nil && errR != io.EOF {
				return -1, errR
			}
			nn, err = c.Cipher.Decrypt(c.readBuf[:n], c.dataCache[c.datalen:])
			goto errAgain
		}
		return -1, err
	}

	c.datalen += nn
	nc := copy(b, c.dataCache[:c.datalen])
	copy(c.dataCache, c.dataCache[nc:c.datalen])
	c.datalen -= nc

	return nc, nil
}

func (c *SecureConn) Write(b []byte) (n int, err error) {
	if c.EncryptorInited() {
		data, err := c.InitEncryptor()
		if err != nil {
			return -1, err
		}
		Logger.Debug("ss write iv", zap.Binary("iv", data))
		n, err = c.Conn.Write(data)
		if err != nil {
			return -1, err
		}
		if n != c.InitBolckSize() {
			return -1, ErrUnexpectedIO
		}
	}

	// FIXME TODO BUG if the datacache cannot cache extra data, here should get a bigger buffer

	n, err = c.Encrypt(b, c.writeBuf)
	if err != nil {
		return -1, err
	}

	var start, nn int
	for {
		nn, err = c.Conn.Write(c.writeBuf[start:n])
		if err != nil {
			return nn, err
		}
		if nn < n {
			start += nn
		} else {
			break
		}
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
