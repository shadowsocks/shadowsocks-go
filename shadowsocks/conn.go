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
	//err = c.SetData(b, Decrypt)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"err": err,
	//	}).Warn("setdata error")
	//	return
	//}
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
	//if c.r_len > 0 {
	//	n = c.r_len
	//	return
	//}

	//n, err = c.buffer[c.doe].(*bytes.Buffer).Read(b)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"b": b,
	//		"n": n,
	//		"err": err,
	//	}).Warn("read data error")
	//	return
	//}
	data := c.buffer[c.doe].(*bytes.Buffer).Bytes()
	n = len(data)
	//b = make([]byte, len(data))
	//buf := c.readBuf
	copy(b, data)
	//b = b[:n]
	n, b = RemoveEOF(b)
	//Logger.Fields(LogFields{
	//	"data_len": len(data),
	//	"b_len": len(b),
	//	"data": string(b),
	//	"iv": c.CipherInst.iv,
	//}).Info("check all data after unpack")

	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.doe = Encrypt
	c.buffer[c.doe] = bytes.NewBuffer(nil)
	//c.SetData(b, Encrypt)
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

	//b = c.writer.(*bytes.Buffer).Bytes()
	//_, b = RemoveEOF(b)
	////n = len(b)
	//Logger.Fields(LogFields{
	//	"data": b,
	//	"iv": c.CipherInst.iv,
	//}).Info("check all data after pack")
	//if c.w_len > 0 {
	//	n = c.w_len
	//	return
	//}

	var buffer_len int64
	buffer_len, err = c.buffer[c.doe].(*bytes.Buffer).WriteTo(c.Conn)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("write data error")
	}
	n = int(buffer_len)
	//n, err = c.Conn.Write(b)

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

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
//func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
//	conn, err := net.Dial("tcp", server)
//	if err != nil {
//		Logger.Fields(LogFields{
//			"server": server,
//			"err": err,
//		}).Warn("shadowsocks: Dialing to server")
//		return
//	}
//	c = NewConn(conn, cipher)
//
//	if cipher.CType == C_STREAM {
//		p := new(PacketStream)
//		p.Cipher = cipher.Inst.(*CipherStream)
//		p.Init(c, bytes.NewReader(rawaddr), Encrypt)
//		p.Pack()
//	} else if cipher.CType == C_AEAD {
//		p := new(PacketAead)
//		p.Cipher = cipher.Inst.(*CipherAead)
//		p.Init(c, bytes.NewReader(rawaddr), Encrypt)
//		p.Pack()
//	}
//
//	return
//}

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
	//c.Init(rawaddr)
	//
	//if cipher.CType == C_STREAM {
	//	p := new(PacketStream)
	//	p.Cipher = cipher.Inst.(*CipherStream)
	//	p.Init(c, bytes.NewReader(rawaddr), Encrypt)
	//	p.Pack()
	//} else if cipher.CType == C_AEAD {
	//	p := new(PacketAead)
	//	p.Cipher = cipher.Inst.(*CipherAead)
	//	p.Init(c, bytes.NewReader(rawaddr), Encrypt)
	//	p.Pack()
	//}

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