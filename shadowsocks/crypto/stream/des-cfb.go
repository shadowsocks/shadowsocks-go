package stream

import (
	"crypto/cipher"
	"crypto/des"
)

type DES struct {
	Stream
}

func (this *DES) new(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return this.newStream(block, err, key, iv, doe)
}