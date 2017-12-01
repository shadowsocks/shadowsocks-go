package shadowsocks

import (
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/cipher"
	"golang.org/x/crypto/hkdf"
	"crypto/sha1"
	"io"
	"crypto/md5"
	"crypto/rand"
)
type CipherAead struct {
	Cipher
	Cryptor cipher.AEAD
	Info *cipherInfo

	key []byte
	iv []byte
	nonce []byte

	ivSize int
	keySize int
}

func (this *CipherAead) isStream() bool { return false }
func (this *CipherAead) setIV(iv []byte) (err error) { if iv != nil { this.iv = iv; return }; return this.newIV() }
func (this *CipherAead) Init(iv []byte, decrypt bool) (err error) {
	this.nonce = nil
	if err = this.setIV(iv); err != nil { return }

	subkey := make([]byte, this.KeySize())
	hkdfSHA1(this.key, this.iv, []byte("ss-subkey"), subkey)

	var cryptor interface{}
	if cryptor, err = this.Info.makeCryptor(subkey, this.iv, decrypt); err != nil { return }
	this.SetCryptor(cryptor)

	return
}
func (this *CipherAead) SetKey(key []byte) { this.key = key }
func (this *CipherAead) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherAead) SetCryptor(cryptor interface{}) { this.Cryptor = cryptor.(cipher.AEAD) }
func (this *CipherAead) GetCryptor() interface{} { return this.Cryptor }
func (this *CipherAead) newIV() (err error) { iv := make([]byte, this.IVSize()); if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }; this.iv = iv; return}
func (this *CipherAead) IV() []byte { return this.iv }
func (this *CipherAead) KeySize() int { return this.Info.KeySize }
func (this *CipherAead) IVSize() int { if ks := this.KeySize(); ks > this.Info.IVSize { return ks }; return this.Info.IVSize}
func (this *CipherAead) Encrypt(dst, src []byte) (err error) { this.Cryptor.Seal(dst[:0], this.Nonce(), src, nil); this.SetNonce(true); return }
func (this *CipherAead) Decrypt(dst, src []byte) (err error) { _, err = this.Cryptor.Open(dst[:0], this.Nonce(), src, nil); if err != nil { return }; this.SetNonce(true); return }
func (this *CipherAead) Nonce() []byte { if this.nonce == nil { this.SetNonce(false) }; return this.nonce }
func (this *CipherAead) SetNonce(increment bool) {
	if !increment { this.nonce = make([]byte, this.Cryptor.NonceSize()) }
	for i := range this.nonce { this.nonce[i]++; if this.nonce[i] != 0 { return } }
	return
}

func newChaCha20IETFPoly1305Aead(key, iv []byte, decrypt bool) (interface{}, error) { return chacha20poly1305.New(key) }
func newAead(password string, info *cipherInfo) (c Cipher, err error) {
	key := info.makeKey(password, info.KeySize)
	c = new(CipherAead); c.SetKey(key); c.SetInfo(info)
	return
}

func hkdfSHA1(secret, iv, info, outkey []byte) (err error) {
	r := hkdf.New(sha1.New, secret, iv, info)
	if _, err = io.ReadFull(r, outkey); err != nil { return }
	return
}
// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev); h.Write([]byte(password)); b = h.Sum(b); prev = b[len(b)-h.Size():]; h.Reset()
	}
	return b[:keyLen]
}