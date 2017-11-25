package shadowsocks

import (
	"net"
	"io"
	"bytes"
	"errors"
)

type PipeStream struct {
	Pipe
	Cipher *CipherStream
	data []byte
}

func (this *PipeStream) Init(c net.Conn, buf []byte) (err error) {
	// set iv or get iv and split payload from packet data
	SetReadTimeout(c)
	n, err := c.Read(buf)
	if err != nil {
		return
	}

	if n > 0 {
		this.data = buf[:n]
		return
	}

	err = errors.New("no data from connection")

	return
}

func (this *PipeStream) getIV() (iv []byte, err error) {
	iv = make([]byte, this.Cipher.Info.ivLen)
	if _, err = io.ReadFull(bytes.NewReader(this.data), iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *PipeStream) Pack(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		err := this.Init(src, buf)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("init ss connection error")
			return
		}

		p := new(PacketStream)
		p.Cipher = this.Cipher
		p.Init(dst, this.data, Encrypt)
		p.Pack()
	}
}

func (this *PipeStream) UnPack(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		err := this.Init(src, buf)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("init ss connection error")
			return
		}

		p := new(PacketStream)
		p.Cipher = this.Cipher
		p.Init(dst, this.data, Decrypt)
		p.UnPack()
	}
}