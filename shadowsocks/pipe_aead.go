package shadowsocks

import (
	"net"
	"errors"
)

type PipeAead struct {
	Pipe
	Cipher *CipherAead
	data []byte
}

func (this *PipeAead) Init(c net.Conn, buf []byte) (err error) {
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

func (this *PipeAead) Pack(src, dst net.Conn) {
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

		p := new(PacketAead)
		p.Cipher = this.Cipher
		p.Init(dst, this.data, Encrypt)
		p.Pack()
	}
}

func (this *PipeAead) UnPack(src, dst net.Conn) {
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

		p := new(PacketAead)
		p.Cipher = this.Cipher
		p.Init(dst, this.data, Decrypt)
		p.UnPack()
	}
}