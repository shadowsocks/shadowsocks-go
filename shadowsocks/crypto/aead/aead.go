package aead

import (
	"crypto/cipher"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
	maxPacketSize = 4096 // increase it if error occurs
)

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newAead func(d []byte) (cipher.AEAD, error)
}

type Aead struct {
	enc  cipher.AEAD
	dec  cipher.AEAD
	key  []byte
	info *cipherInfo
	iv   []byte
}

/////////////////////////////////////////////////////////////////////////////
func (this *Aead) newAead(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (cipher.AEAD, error) {
	return this.info.newAead(key)
}

/////////////////////////////////////////////////////////////////////////////