package shadowsocks

import (
	"net"
)

type PipeStream struct {
	Pipe
	Cipher *CipherStream
	data []byte
}

func (this *PipeStream) Pack(src, dst net.Conn) {
	var err error
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		p := new(PacketStream)
		p.Cipher = this.Cipher
		err = p.Init(dst, src, Encrypt)
		if err != nil {
			return
		}
		err = p.Pack()
		if err != nil {
			return
		}
	}
}

func (this *PipeStream) UnPack(src, dst net.Conn) {
	var err error
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		p := new(PacketStream)
		p.Cipher = this.Cipher
		err = p.Init(dst, src, Decrypt)
		if err != nil {
			return
		}
		err = p.UnPack()
		if err != nil {
			return
		}
	}
}