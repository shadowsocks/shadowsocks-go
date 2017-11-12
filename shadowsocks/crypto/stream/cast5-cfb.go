package stream

import (
	"crypto/cipher"
	"golang.org/x/crypto/cast5"
)

type Cast5 struct {
	Stream
}

func (this *Cast5) new(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return this.newStream(block, err, key, iv, doe)
}