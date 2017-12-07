package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Conn struct {
	net.Conn
	encrypted bool
	decrypted bool
	cryptor   Cryptor
	Buffer    []byte
	Encryptor EnCryptor
	DeCryptor DeCryptor
}

func NewConn(c net.Conn, cryptor Cryptor) (conn *Conn) {
	conn = &Conn{
		Conn:    c,
		cryptor: cryptor,
		Encryptor: cryptor.initCryptor(Encrypt).(EnCryptor),
		DeCryptor: cryptor.initCryptor(Decrypt).(DeCryptor),
		Buffer:  cryptor.GetBuffer(),
	}
	//Logger.Fields(LogFields{
	//	"LocalAddr": c.LocalAddr(),
	//	"RemoteAddr": c.RemoteAddr(),
	//}).Info("new a connection")
	//conn.cryptor.InitEncrypt(c)
	//conn.encrypted = true
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.DeCryptor.ReadTo(b, c.Conn)
}
func (c *Conn) Write(b []byte) (n int, err error) {
	return c.Encryptor.WriteTo(b, c.Conn)
}

/*
func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.decrypted {
		if err = c.cryptor.InitDecrypt(c.Conn); err != nil {
			return
		}
		c.decrypted = true
	}

	return c.cryptor.UnPack(b, c.Conn)
}
func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.encrypted {
		if err = c.cryptor.InitEncrypt(c.Conn); err != nil {
			return
		}
		c.encrypted = true
	}

	return c.cryptor.Pack(b, c.Conn)
}
*/

//func (c *Conn) Packing(r io.Reader) (n int, err error) {
//	//buffer, err := c.cryptor.GetBuffer(); if err != nil { return }; buf := buffer.Get(); defer buffer.Put(buf)
//	//buf := make([]byte, 32*1024)
//	buf := c.buffer
//	//////////////////////////////////////////
//	//for {
//	//	n, err = r.Read(buf); if err != nil { return }
//	//	if n > 0 { if _, err = c.Write(buf[:n]); err != nil { return } }
//	//
//	//}
//	//////////////////////////////////////////
//	if n, err = r.Read(buf); err != nil { return }
//	if n > 0 { return c.Write(buf[:n]) }
//	return
//}
//func (c *Conn) UnPacking(w io.Writer) (n int, err error) {
//	//buffer, err := c.cryptor.GetBuffer(); if err != nil { return }
//	//buf := buffer.Get()
//	//buf := make([]byte, 32*1024)
//	buf := c.buffer
//	//defer buffer.Put(buf)
//	//Logger.Fields(LogFields{
//	//	"buf": buf,
//	//}).Info("check buffer")
//	//
//	//Logger.Warn("begin################")
//	//for {
//	//	//if n, err = c.Read(buf); err != nil { return }
//	//	n, err = c.Read(buf); if err != nil { return }
//	//	//Logger.Fields(LogFields{
//	//	//	"n": n,
//	//	//	"buf_str": string(buf[:n]),
//	//	//	"buf_size": len(buf),
//	//	//}).Info("check buffer")
//	//	if n > 0 {
//	//		if _, err = w.Write(buf[:n]); err != nil { return }
//	//	}
//	//}
//	//Logger.Warn("get out")
//	////////////////////////////////////////////////
//	//Logger.Warn("begin read data")
//	if n, err = c.Read(buf); err != nil {
//		//buf = nil
//		Logger.Fields(LogFields{
//			"n": n,
//			"buf": buf,
//			"buf_str": string(buf),
//			"err": err,
//		}).Warn("unpack data error")
//		return
//		}
//	//Logger.Warn("done read data")
//	if n > 0 {
//		//Logger.Fields(LogFields{
//		//	"buf": buf[:n],
//		//	"buf_str": string(buf[:n]),
//		//	"n": n,
//		//	"buf_size": len(buf),
//		//}).Info("check buffer")
//		if _, err = w.Write(buf[:n]); err != nil { return }
//		if n < len(buf) { err = errors.New("done"); return }
//		//n, err = c.UnPacking(w); if err != nil { return }
//
//	}
//
//	return
//}

func (c *Conn) Close() error {
	return c.Conn.Close()
}
func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
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
func DialWithRawAddr(rawaddr []byte, server string, cryptor Cryptor) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cryptor)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cryptor Cryptor) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cryptor)
}
