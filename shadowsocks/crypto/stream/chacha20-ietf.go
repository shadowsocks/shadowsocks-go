package stream

import (
	"crypto/cipher"
	"github.com/Yawning/chacha20"
)

type ChaCha20IETF struct {
	Stream
}

func (this *ChaCha20IETF) new(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	c, err := chacha20.NewCipher(key, iv)
	return c, err
}