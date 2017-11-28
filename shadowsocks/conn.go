package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
	"io"
	"bytes"
)

var data_pipe chan []byte

type Conn struct {
	net.Conn
	Cipher *Cipher
	//ReadBuf  []byte
	//WriteBuf []byte
	Buffer *LeakyBufType
	//buffer []byte

	//////////////////

	CipherInst *CipherAead
	doe DecOrEnc

	data_buffer [2]io.Writer

	iv_offset [2]int

	payload []byte
	payload_len int

	packet [2][]byte // [IV][encrypted payload]
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	leakyBuf := NewLeakyBuf(maxNBuf, payloadSizeMask)
	conn := &Conn{
		Conn:     c,
		Buffer: leakyBuf,
		Cipher: cipher,
		//readBuf:  leakyBuf.Get(),
		//writeBuf: leakyBuf.Get(),
	}

	return conn
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.doe = Decrypt
	c.data_buffer[c.doe] = bytes.NewBuffer(nil)

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

	data := c.data_buffer[c.doe].(*bytes.Buffer).Bytes()
	n = len(data)
	//if n > 0 {
	//	Logger.Fields(LogFields{
	//		"data": data,
	//	}).Info("unpack data write to pipe")
	//	data_pipe <- data
	//}
	copy(b, data)
	Logger.Fields(LogFields{
		"data": data,
		"data_len": len(data),
		"b": b,
		"b_len": len(b),
		"n": n,
	}).Info("check read data")

	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.doe = Encrypt
	c.data_buffer[c.doe] = bytes.NewBuffer(nil)

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

	//data := c.buffer[c.doe].(*bytes.Buffer).Bytes()
	//n = len(data)
	//if n > 0 {
	//	Logger.Fields(LogFields{
	//		"data": data,
	//	}).Info("pack data write to pipe")
	//	//data_pipe <- data
	//	return c.Conn.Write(data)
	//}

	var buffer_len int64
	buffer_len, err = c.data_buffer[c.doe].(*bytes.Buffer).WriteTo(c.Conn)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("write data error")
	}
	n = int(buffer_len)
	//Logger.Fields(LogFields{
	//	"data": data,
	//	"data_len": len(data),
	//	"n": n,
	//}).Info("check write data")

	return
}

func (c *Conn) Close() error {
	//c.Buffer.Put(c.readBuf)
	//leakyBuf.Put(c.writeBuf)
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