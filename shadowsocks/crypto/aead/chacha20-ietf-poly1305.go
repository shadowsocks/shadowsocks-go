package aead

import (
	"crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"
)

type ChaCha20IETFPoly1305 struct {
	Aead
}

func (this *ChaCha20IETFPoly1305) newAead(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}