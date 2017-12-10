package shadowsocks

import (
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/cipher"
	"golang.org/x/crypto/hkdf"
	"crypto/sha1"
	"io"
	"crypto/rand"
	"crypto/aes"
)

type CipherAead struct {
	Cipher
	Info      *cipherInfo
	key       []byte
	ivSize    int
	keySize   int
}

func (this *CipherAead) isStream() bool { return false }
func (this *CipherAead) Init(iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	subkey := make([]byte, this.KeySize())
	hkdfSHA1(this.key, iv, []byte("ss-subkey"), subkey)

	cryptor, err = this.Info.makeCryptor(subkey, iv, doe)

	return
}
func (this *CipherAead) SetKey(key []byte)        { this.key = key }
func (this *CipherAead) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherAead) NewIV() (iv []byte, err error) {
	iv = make([]byte, this.IVSize())
	_, err = io.ReadFull(rand.Reader, iv)
	return
}
func (this *CipherAead) KeySize() int               { return this.Info.KeySize }
func (this *CipherAead) IVSize() int {
	if ks := this.KeySize(); ks > this.Info.IVSize {
		return ks
	}
	return this.Info.IVSize
}

func newAesGCMAead(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func newChaCha20IETFPoly1305Aead(key, iv []byte, doe DecOrEnc) (interface{}, error) { return chacha20poly1305.New(key) }
func newAead(password string, info *cipherInfo) (c Cipher, err error) {
	key := info.makeKey(password, info.KeySize)
	c = new(CipherAead)
	c.SetKey(key)
	c.SetInfo(info)
	return
}

func hkdfSHA1(secret, iv, info, outkey []byte) (err error) {
	r := hkdf.New(sha1.New, secret, iv, info)
	_, err = io.ReadFull(r, outkey)
	return
}

