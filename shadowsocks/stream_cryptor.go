package shadowsocks

import "io"

type StreamEnCryptor interface {
	Init(c Cipher, b []byte) StreamEnCryptor
	WriteTo(b []byte, w io.Writer) (n int, err error)
}

type StreamDeCryptor interface {
	Init(c Cipher, b []byte) StreamDeCryptor
	ReadTo(b []byte, r io.Reader) (n int, err error)
}

func NewStreamCryptor(cipher Cipher) (c Cryptor) {
	if cipher.isStream() {
		c = new(StreamCryptorStream).init(cipher)
	} else {
		c = new(StreamCryptorAead).init(cipher)
	}
	return
}