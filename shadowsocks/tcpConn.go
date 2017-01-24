package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

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
	ota          bool
}

// NewSecureConn creates a SecureConn
func NewSecureConn(c net.Conn, cipher *encrypt.Cipher, ota bool, isServerSide bool) *SecureConn {
	return &SecureConn{
		Conn:         c,
		Cipher:       cipher,
		readBuf:      leakyBuf.Get(),
		writeBuf:     leakyBuf.Get(),
		isServerSide: isServerSide,
		ota:          ota,
	}
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	leakyBuf.Put(c.readBuf)
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
			return 0, errPacketOtaFailed
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

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.Decrypt(b[0:n], cipherData[0:n])
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
	n, err = c.Conn.Write(cipherData)
	return
}

// Listener is like net.Listener, but a little different
type Listener struct {
	net.Listener
	cipher *encrypt.Cipher
	ota    bool
}

// Accept just like net.Listener.Accept(), but with additional return variable host.
// It will handle the request header for you.
func (ln *Listener) Accept() (conn net.Conn, host string, err error) {
	conn, err = ln.Listener.Accept()
	if err != nil {
		return nil, "", err
	}
	ss := NewSecureConn(conn, ln.cipher.Copy(), false, true)
	host, err = getRequets(ss, ln.ota)
	if err != nil {
		return nil, host, err
	}
	return ss, host, nil
}

// Close stops listening on the TCP address. Already Accepted connections are not closed.
func (ln *Listener) Close() error {
	return ln.Listener.Close()
}

// Addr returns the listener's network address, a *TCPAddr.
// The Addr returned is shared by all invocations of Addr, so do not modify it.
func (ln *Listener) Addr() net.Addr {
	return ln.Listener.Addr()
}

// Listen announces on the TCP address laddr and returns a TCP listener.
// Net must be "tcp", "tcp4", or "tcp6".
// If laddr has a port of 0, ListenTCP will choose an available port.
// The caller can use the Addr method of TCPListener to retrieve the chosen address.
func Listen(network, laddr string, config *Config) (*Listener, error) {
	cipher, err := encrypt.NewCipher(config.Method, config.Password)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{ln, cipher, config.Auth}, nil
}

func readFull(c *SecureConn, b []byte) (n int, err error) {
	min := len(b)
	for n < min {
		var nn int
		nn, err = c.read(b[n:])
		n += nn
	}
	if n >= min {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func getRequets(ss *SecureConn, auth bool) (host string, err error) {
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = readFull(ss, buf[:idType+1]); err != nil {
		return
	}
	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv4-1
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv6-1
	case typeDm:
		if _, err = readFull(ss, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+headerLenDmBase-2
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&AddrMask)
		return
	}
	if _, err = readFull(ss, buf[reqStart:reqEnd]); err != nil {
		return
	}

	switch addrType & AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
		if strings.ContainsRune(host, 0x00) {
			return "", errInvalidHostname
		}
	}

	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	ota := addrType&OneTimeAuthMask > 0
	if auth {
		if !ota {
			err = errPacketOtaFailed
			return
		}
	}
	if ota {
		if _, err = readFull(ss, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := ss.GetIV()
		key := ss.GetKey()
		actualHmacSha1Buf := HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = errPacketOtaFailed
			return
		}
		ss.EnableOta()
	}
	return
}
