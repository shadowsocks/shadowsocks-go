package shadowsocks

import (
	"net"
	"reflect"
)

type Pipe interface {
	Pack(src, dst net.Conn)
	UnPack(src, dst net.Conn)
}

func Piping(local, remote net.Conn, cipher interface{}) {
	if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherStream" {
		p := &PipeStream{Cipher: cipher.(*CipherStream)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	} else if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherAead" {
		p := &PipeAead{Cipher: cipher.(*CipherAead)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	}
}