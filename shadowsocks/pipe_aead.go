package shadowsocks

import (
	"net"
)

type PipeAead struct {
	Pipe
	Cipher *CipherAead
	data []byte
}

func (this *PipeAead) Pack(src, dst net.Conn) {
	var err error
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		p := new(PacketAead)
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

func (this *PipeAead) UnPack(src, dst net.Conn) {
	var err error
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		p := new(PacketAead)
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