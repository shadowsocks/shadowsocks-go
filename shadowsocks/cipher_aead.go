package shadowsocks

import (
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/cipher"
	"golang.org/x/crypto/hkdf"
	"crypto/sha1"
	"io"
	"crypto/rand"
)

type CipherAead struct {
	Cipher
	EnCryptor cipher.AEAD
	DeCryptor cipher.AEAD
	Info      *cipherInfo
	iv        [2][]byte
	key       []byte
	nonce     [2][]byte
	ivSize    int
	keySize   int
}

func (this *CipherAead) isStream() bool { return false }
func (this *CipherAead) Init(iv []byte, doe DecOrEnc) (err error) {
	this.nonce[doe] = nil

	subkey := make([]byte, this.KeySize())
	hkdfSHA1(this.key, iv, []byte("ss-subkey"), subkey)

	var cryptor interface{}
	if cryptor, err = this.Info.makeCryptor(subkey, iv, doe); err != nil {
		return
	}
	this.iv[doe] = iv
	this.SetCryptor(cryptor, doe)

	return
}
func (this *CipherAead) SetKey(key []byte)        { this.key = key }
func (this *CipherAead) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherAead) SetCryptor(cryptor interface{}, doe DecOrEnc) {
	if doe == Decrypt {
		this.DeCryptor = cryptor.(cipher.AEAD)
	} else {
		this.EnCryptor = cryptor.(cipher.AEAD)
	}
}
func (this *CipherAead) GetCryptor(doe DecOrEnc) interface{} {
	if doe == Decrypt {
		return this.DeCryptor
	} else {
		return this.EnCryptor
	}
}
func (this *CipherAead) NewIV() (iv []byte, err error) {
	iv = make([]byte, this.IVSize())
	_, err = io.ReadFull(rand.Reader, iv)
	return
}
func (this *CipherAead) Key() []byte                { return this.key }
func (this *CipherAead) IV(doe DecOrEnc) []byte { return this.iv[doe] }
func (this *CipherAead) KeySize() int               { return this.Info.KeySize }
func (this *CipherAead) IVSize() int {
	if ks := this.KeySize(); ks > this.Info.IVSize {
		return ks
	}
	return this.Info.IVSize
}
func (this *CipherAead) Encrypt(dst, src []byte) (err error) {
	this.EnCryptor.Seal(dst[:0], this.Nonce(Encrypt), src, nil)
	this.SetNonce(Encrypt, true)
	return
}
func (this *CipherAead) Decrypt(dst, src []byte) (err error) {
	_, err = this.DeCryptor.Open(dst[:0], this.Nonce(Decrypt), src, nil)
	if err != nil {
		return
	}
	this.SetNonce(Decrypt, true)
	return
}
func (this *CipherAead) Nonce(doe DecOrEnc) []byte {
	if this.nonce[doe] == nil {
		this.SetNonce(doe, false)
	};
	return this.nonce[doe]
}
func (this *CipherAead) SetNonce(doe DecOrEnc, increment bool) {
	var size int
	if doe == Decrypt {
		size = this.DeCryptor.NonceSize()
	} else {
		size = this.EnCryptor.NonceSize()
	}
	if !increment {
		this.nonce[doe] = make([]byte, size)
		return
	}
	for i := range this.nonce {
		this.nonce[doe][i]++
		if this.nonce[doe][i] != 0 {
			return
		}
	}
	return
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

