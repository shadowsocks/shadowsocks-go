package stream

import (
	"crypto/cipher"
	"golang.org/x/crypto/blowfish"
)

type BlowFish struct {
	Stream
}

func (this *BlowFish) new(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	return this.newStream(block, err, key, iv, doe)
}