package stream

import (
	"crypto/cipher"
	"crypto/aes"
)

type AESCFB struct {
	Stream
}

func (this *AESCFB) new(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return this.newStream(block, err, key, iv, doe)
}