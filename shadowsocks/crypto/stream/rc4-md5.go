package stream

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
)

type RC4MD5 struct {
	Stream
}

func (this *DES) new(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	c, err := rc4.NewCipher(rc4key)

	return c, err
}