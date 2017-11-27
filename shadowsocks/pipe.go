package shadowsocks

import (
	"net"
)

type Pipe interface {
	Pack(src, dst net.Conn)
	UnPack(src, dst net.Conn)
}

func Piping(local, remote net.Conn, cipher *Cipher) {
	if cipher.CType == C_STREAM {
		p := &PipeStream{Cipher: cipher.Inst.(*CipherStream)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	} else if cipher.CType == C_AEAD {
		p := &PipeAead{Cipher: cipher.Inst.(*CipherAead)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	}
}