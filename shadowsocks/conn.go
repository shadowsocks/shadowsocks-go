package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
	"io"
	"bytes"
)

type Conn struct {
	net.Conn
	Cipher *Cipher
	readBuf  []byte
	writeBuf []byte
	//buffer *LeakyBufType

	//////////////////

	CipherInst *CipherAead
	doe DecOrEnc

	buffer [2]io.Writer

	iv_offset [2]int

	payload []byte
	payload_len int

	packet [2][]byte // [IV][encrypted payload]
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	conn := &Conn{
		Conn:     c,
		//buffer: leakyBuf,
		Cipher: cipher,
		readBuf:  leakyBuf.Get(),
		writeBuf: leakyBuf.Get(),
	}

	return conn
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.doe = Decrypt
	c.buffer[c.doe] = bytes.NewBuffer(nil)

	if c.CipherInst == nil || c.CipherInst.Dec == nil {
		err = c.initDecrypt()
		if err != nil {
			return
		}
	} else {
		c.iv_offset[c.doe] = 0
	}

	err = c.UnPack()
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("unpack error")
		return
	}

	data := c.buffer[c.doe].(*bytes.Buffer).Bytes()
	n = len(data)
	copy(b, data)
	n, b = RemoveEOF(b)

	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.doe = Encrypt
	c.buffer[c.doe] = bytes.NewBuffer(nil)

	if c.CipherInst == nil || c.CipherInst.Enc == nil {
		err = c.initEncrypt()
		if err != nil {
			return
		}
	} else {
		c.iv_offset[c.doe] = 2
	}

	err = c.Pack(b)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("pack error")
		return
	}

	var buffer_len int64
	buffer_len, err = c.buffer[c.doe].(*bytes.Buffer).WriteTo(c.Conn)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("write data error")
	}
	n = int(buffer_len)

	return
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
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