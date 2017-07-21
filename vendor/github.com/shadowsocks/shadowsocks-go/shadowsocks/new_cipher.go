package shadowsocks

import (
	"crypto/cipher"
	"net"
)

// two cipher interface distingush the AEAD and Stream cipher
type AEADCipher interface {
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}
type StreamCipher interface {
	KeySize() int
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

// two connection oriented encryptor interface
// both the packet and stream secure connection should implement this
// this should be
type ConnectionCoder interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}
type PacketCoder interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
}

// then we can get this

type AEADConnectionCipher interface {
	AEADCipher
	ConnectionCoder
}
type AEADPacketCipher interface {
	AEADCipher
	PacketCoder
}
type StreamConnectionCipher interface {
	StreamCipher
	ConnectionCoder
}
type StreamPacketCipher interface {
	StreamCipher
	PacketCoder
}

func NewCipher(cip string) interface{} {
	return nil
}
