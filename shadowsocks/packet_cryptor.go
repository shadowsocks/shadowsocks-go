package shadowsocks

import (
	"net"
)

type PacketEnCryptor interface {
	Init(c Cipher, b []byte) PacketEnCryptor
	initPacket(p net.PacketConn) PacketEnCryptor
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

type PacketDeCryptor interface {
	Init(c Cipher, b []byte) PacketDeCryptor
	initPacket(p net.PacketConn) PacketDeCryptor
	ReadTo(b []byte) (n int, addr net.Addr, err error)
}

func NewPacketCryptor(cipher Cipher) (c Cryptor) {
	if cipher.isStream() {
		c = new(PacketCryptorStream).init(cipher)
	} else {
		c = new(PacketCryptorAead).init(cipher)
	}
	return
}