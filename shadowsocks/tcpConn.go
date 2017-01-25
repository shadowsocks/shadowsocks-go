package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

// SecureConn is a secured connection with shadowsocks protocol
// also implements net.Conn interface
type SecureConn struct {
	net.Conn
	*encrypt.Cipher
	readBuf      []byte
	writeBuf     []byte
	chunkID      uint32
	isServerSide bool
	timeout      int
	ota          bool
}

// NewSecureConn creates a SecureConn
func NewSecureConn(c net.Conn, cipher *encrypt.Cipher, ota bool, timeout int, isServerSide bool) *SecureConn {
	return &SecureConn{
		Conn:         c,
		Cipher:       cipher,
		writeBuf:     leakyBuf.Get(),
		isServerSide: isServerSide,
		timeout:      timeout,
		ota:          ota,
	}
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

// IsOta returns true if the connection is OTA enabled
func (c *SecureConn) IsOta() bool {
	return c.ota
}

// EnableOta enables OTA for the connection
func (c *SecureConn) EnableOta() {
	c.ota = true
}

func (c *SecureConn) getAndIncrChunkID() (chunkID uint32) {
	chunkID = c.chunkID
	c.chunkID++
	return
}

func (c *SecureConn) Read(b []byte) (n int, err error) {
	if c.ota && c.isServerSide {
		header := make([]byte, lenDataLen+lenHmacSha1)
		if n, err = readFull(c, header); err != nil {
			return 0, err
		}

		dataLen := binary.BigEndian.Uint16(header[:lenDataLen])
		expectedHmacSha1 := header[lenDataLen : lenDataLen+lenHmacSha1]

		if len(b) < int(dataLen) {
			err = errBufferTooSmall
			return 0, err
		}
		if n, err = readFull(c, b[:dataLen]); err != nil {
			return 0, err
		}
		chunkIDBytes := make([]byte, 4)
		chunkID := c.getAndIncrChunkID()
		binary.BigEndian.PutUint32(chunkIDBytes, chunkID)
		actualHmacSha1 := HmacSha1(append(c.GetIV(), chunkIDBytes...), b[:dataLen])
		if !bytes.Equal(expectedHmacSha1, actualHmacSha1) {
			return 0, ErrPacketOtaFailed
		}
		return int(dataLen), nil
	}
	return c.read(b)
}

func (c *SecureConn) read(b []byte) (n int, err error) {
	if c.DecInited() {
		iv := make([]byte, c.GetIVLen())
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.InitDecrypt(iv); err != nil {
			return
		}
		if len(c.GetIV()) == 0 {
			c.SetIV(iv)
		}
	}
	if c.timeout > 0 {
		c.SetReadDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.Decrypt(b[0:n], b[0:n])
	}
	return
}

func (c *SecureConn) Write(b []byte) (n int, err error) {
	if c.ota && !c.isServerSide {
		chunkID := c.getAndIncrChunkID()
		header := otaReqChunkAuth(c.GetIV(), chunkID, b)
		headerLen := len(header)
		n, err = c.write(append(header, b...))
		// Make sure <= 0 <= len(b), where b is the slice passed in.
		if n >= headerLen {
			n -= headerLen
		}
		return
	}
	return c.write(b)
}

func (c *SecureConn) write(b []byte) (n int, err error) {
	var iv []byte
	if c.EncInited() {
		iv, err = c.InitEncrypt()
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

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	c.Encrypt(cipherData[len(iv):], b)
	if c.timeout > 0 {
		c.SetWriteDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	n, err = c.Conn.Write(cipherData)
	return
}

// Listener is like net.Listener, but a little different
type Listener struct {
	net.Listener
	cipher  *encrypt.Cipher
	timeout int
	ota     bool
}

// Accept just like net.Listener.Accept(), but with additional return variable host.
// It will handle the request header for you.
func (ln *Listener) Accept() (conn net.Conn, host string, err error) {
	conn, err = ln.Listener.Accept()
	if err != nil {
		return nil, "", err
	}
	ss := NewSecureConn(conn, ln.cipher.Copy(), false, ln.timeout, true)
	host, err = getRequets(ss, ln.ota)
	if err != nil {
		ss.Close()
		return nil, host, err
	}
	return ss, host, nil
}

// Listen announces on the TCP address laddr and returns a TCP listener.
// Net must be "tcp", "tcp4", or "tcp6".
// If laddr has a port of 0, ListenTCP will choose an available port.
// The caller can use the Addr method of TCPListener to retrieve the chosen address.
func Listen(network, laddr string, cipher *encrypt.Cipher, timeout int, ota bool) (*Listener, error) {
	if cipher == nil {
		return nil, ErrNilCipher
	}
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{ln, cipher, timeout, ota}, nil
}
