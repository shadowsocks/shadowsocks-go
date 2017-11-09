package crypto

import (
	"github.com/qunxyz/shadowsocks-go/shadowsocks/crypto/stream"
	"net"
)

type Cipher struct {
	stream.Stream
}

// Copy creates a new cipher at it's initial state.
func (this *Cipher) Copy() *Cipher {
	return this.Copy()
}

func (this *Cipher) Pack(b []byte, d []byte) (cipher_data []byte, err error) {
	return this.Pack(b, d)
}

func (this *Cipher) UnPack(c net.Conn, b []byte, cipher_data []byte) (n int, err error) {
	return this.UnPack(c, b, cipher_data)
}