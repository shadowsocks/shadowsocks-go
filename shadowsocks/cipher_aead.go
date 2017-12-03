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
	EnCryptor cipher.AEAD
	DeCryptor cipher.AEAD
	Info *cipherInfo

	key []byte
	nonce [2][]byte

	ivSize int
	keySize int
}

func (this *CipherAead) isStream() bool { return false }
func (this *CipherAead) Init(iv []byte, decrypt DecOrEnc) (err error) {
	this.nonce[decrypt] = nil

	subkey := make([]byte, this.KeySize())
	hkdfSHA1(this.key, iv, []byte("ss-subkey"), subkey)

	var cryptor interface{}
	if cryptor, err = this.Info.makeCryptor(subkey, iv, decrypt); err != nil { return }
	this.SetCryptor(cryptor, decrypt)

	return
}
func (this *CipherAead) SetKey(key []byte) { this.key = key }
func (this *CipherAead) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherAead) SetCryptor(cryptor interface{}, decrypt DecOrEnc) {
	if decrypt == Decrypt { this.DeCryptor = cryptor.(cipher.AEAD) } else { this.EnCryptor = cryptor.(cipher.AEAD) } }
func (this *CipherAead) GetCryptor(decrypt DecOrEnc) interface{} {
	if decrypt == Decrypt { return this.DeCryptor } else { return this.EnCryptor } }
func (this *CipherAead) NewIV() (iv []byte, err error) {
	iv = make([]byte, this.IVSize()); if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }; return}
func (this *CipherAead) KeySize() int { return this.Info.KeySize }
func (this *CipherAead) IVSize() int { if ks := this.KeySize(); ks > this.Info.IVSize { return ks }; return this.Info.IVSize}
func (this *CipherAead) Encrypt(dst, src []byte) (err error) {
	this.EnCryptor.Seal(dst[:0], this.Nonce(Encrypt), src, nil); this.SetNonce(Encrypt, true); return }
func (this *CipherAead) Decrypt(dst, src []byte) (err error) {
	_, err = this.DeCryptor.Open(dst[:0], this.Nonce(Decrypt), src, nil); if err != nil { return }; this.SetNonce(Decrypt, true); return }
func (this *CipherAead) Nonce(decrypt DecOrEnc) []byte {
	if this.nonce[decrypt] == nil { this.SetNonce(decrypt, false) }; return this.nonce[decrypt] }
func (this *CipherAead) SetNonce(decrypt DecOrEnc, increment bool) {
	var size int
	if decrypt == Decrypt { size = this.DeCryptor.NonceSize() } else { size = this.EnCryptor.NonceSize() }
	if !increment { this.nonce[decrypt] = make([]byte, size); return }
	for i := range this.nonce { this.nonce[decrypt][i]++; if this.nonce[decrypt][i] != 0 { return } }; return
}

func newChaCha20IETFPoly1305Aead(key, iv []byte, decrypt DecOrEnc) (interface{}, error) { return chacha20poly1305.New(key) }
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