package shadowsocks

import (
	"net"
	"reflect"
)

type Pipe interface {
	Pack(src, dst net.Conn, cipher interface{})
	UnPack(src, dst net.Conn, cipher interface{})
}

func PipeHandling(local, remote net.Conn, cipher interface{}) {
	if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherStream" {
		p := new(PipeStream)
		go p.Pack(local, remote, cipher)
		p.UnPack(remote, local,  cipher)
	} else if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherAead" {
		p := new(PipeAead)
		go p.Pack(local, remote, cipher)
		p.UnPack(remote, local,  cipher)
	}
}