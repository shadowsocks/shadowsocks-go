package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
	"bytes"
)

type Conn struct {
	net.Conn
	Cipher *Cipher
	Buffer *LeakyBufType

	//////////////////
	cryptor interface{}
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	leakyBuf := NewLeakyBuf(maxNBuf, payloadSizeMask)

	var cryptor interface{}
	if cipher.CType == C_STREAM {
		cryptor = &ConnAead{
			Conn:     c,
			Buffer: leakyBuf,
			Cipher: cipher,
		}
	} else if cipher.CType == C_AEAD {
		cryptor = &ConnAead{
			Conn:     c,
			Buffer: leakyBuf,
			Cipher: cipher,
		}
	}

	conn := &Conn{
		Conn:     c,
		Buffer: leakyBuf,
		Cipher: cipher,
		cryptor: cryptor,
	}

	return conn
}

func (c *Conn) Read(b []byte) (n int, err error) {
	err = c.initDecrypt()
	if err != nil {
		return
	}

	return c.UnPack(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {

	err = c.initEncrypt()
	if err != nil {
		return
	}

	return c.Pack(b)
}

func (c *Conn) initEncrypt() (err error) {
	if c.Cipher.CType == C_STREAM {

	} else if c.Cipher.CType == C_AEAD{
		cryptor := c.cryptor.(*ConnAead)
		cryptor.data_buffer = bytes.NewBuffer(nil)

		if cryptor.CipherInst == nil || cryptor.CipherInst.Enc == nil {
			err = cryptor.initEncrypt()
			if err != nil {
				return
			}
		} else {
			cryptor.iv_offset = 2
		}
	}

	return
}

func (c *Conn) initDecrypt() (err error) {
	if c.Cipher.CType == C_STREAM {

	} else if c.Cipher.CType == C_AEAD{
		cryptor := c.cryptor.(*ConnAead)
		cryptor.data_buffer = bytes.NewBuffer(nil)

		if cryptor.CipherInst == nil || cryptor.CipherInst.Dec == nil {
			err = cryptor.initDecrypt()
			if err != nil {
				return
			}
		} else {
			cryptor.iv_offset = 0
		}

	}

	return
}

func (c *Conn) Pack(b []byte) (n int, err error) {
	if c.Cipher.CType == C_STREAM {

	} else if c.Cipher.CType == C_AEAD{
		cryptor := c.cryptor.(*ConnAead)

		err = cryptor.Pack(b)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("pack error")
			return
		}

		var buffer_len int64
		buffer_len, err = cryptor.data_buffer.(*bytes.Buffer).WriteTo(c.Conn)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("write data error")
		}
		n = int(buffer_len)

	}

	return
}

func (c *Conn) UnPack(b []byte) (n int, err error) {
	if c.Cipher.CType == C_STREAM {

	} else if c.Cipher.CType == C_AEAD{
		cryptor := c.cryptor.(*ConnAead)

		err = cryptor.UnPack()
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("unpack error")
			return
		}

		data := cryptor.data_buffer.(*bytes.Buffer).Bytes()
		n = len(data)
		copy(b, data)

	}

	return
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		Logger.Fields(LogFields{
			"addr": addr,
			"err": err,
		}).Warn("shadowsocks: address error")
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		Logger.Fields(LogFields{
			"portStr": portStr,
			"err": err,
		}).Warn("shadowsocks: invalid port")
		return nil, err
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		Logger.Fields(LogFields{
			"server": server,
			"err": err,
		}).Warn("shadowsocks: Dialing to server")
		return
	}
	c = NewConn(conn, cipher)
	_, err = c.Write(rawaddr)
	if err != nil {
		c.Close()
		return
	}

	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		Logger.Fields(LogFields{
			"addr": addr,
			"err": err,
		}).Warn("shadowsocks: Parsing addr")
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}