package shadowsocks

import (
	"net"
)

type Pipe interface {
	Pack(src, dst net.Conn)
	UnPack(src, dst net.Conn)
}

//func PipeHandling(local, remote net.Conn, cipher interface{}) {
//	if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherStream" {
//		p := new(PipeStream)
//		p.cipher = cipher.(*CipherStream)
//		go p.Pack(local, remote)
//		p.UnPack(remote, local)
//	} else if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherAead" {
//		p := new(PipeAead)
//		p.cipher = cipher.(*CipherAead)
//		go p.Pack(local, remote)
//		p.UnPack(remote, local)
//	}
//}