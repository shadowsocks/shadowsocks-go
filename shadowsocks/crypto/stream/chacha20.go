package stream

import (
	"crypto/cipher"
	"github.com/Yawning/chacha20"
)

type ChaCha20 struct {
	Stream
}

func (this *ChaCha20) new(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	c, err := chacha20.NewCipher(key, iv)
	return c, err
}