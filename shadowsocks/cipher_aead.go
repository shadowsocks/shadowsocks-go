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

type CryptorAead struct {
	CryptorCipher
	cipher.AEAD

	nonce []byte
}

func (this *CryptorAead) init(cryptor interface{}) {
	this.AEAD = cryptor.(cipher.AEAD)
}

func (this *CryptorAead) getNonce() []byte {
	if this.nonce == nil {
		this.nonce = make([]byte, this.NonceSize())
	}

	return this.nonce
}

func (this *CryptorAead) incrNonce() {
	for i := range this.nonce {
		this.nonce[i]++
		if this.nonce[i] != 0 {
			return
		}
	}
}

func (this *CryptorAead) Encrypt(dst, src []byte) (err error) {
	this.Seal(dst[:0], this.getNonce(), src, nil)
	this.incrNonce()
	return
}

func (this *CryptorAead) Decrypt(dst, src []byte) (err error) {
	_, err = this.Open(dst[:0], this.getNonce(), src, nil)
	this.incrNonce()
	return
}
///////////////////////////////////////////
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

func newAesGCMAead(key, iv []byte, doe DecOrEnc) (cryptor CryptorCipher, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	cryptor = new(CryptorAead)
	cryptor.init(aead)
	return
}
func newChaCha20IETFPoly1305Aead(key, iv []byte, doe DecOrEnc) (cryptor CryptorCipher, err error) {
	var aead cipher.AEAD
	aead, err = chacha20poly1305.New(key)
	cryptor = new(CryptorAead)
	cryptor.init(aead)
	return
}
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

