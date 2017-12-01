package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
	"github.com/Yawning/chacha20"
	"io"
	"crypto/rand"
)

var errEmptyPassword = errors.New("empty key")

type CipherStream struct {
	Cipher
	Cryptor cipher.Stream
	Info *cipherInfo

	key []byte
	iv []byte

	ivSize int
	keySize int
}
func (this *CipherStream) isStream() bool { return true }
func (this *CipherStream) setIV(iv []byte) (err error) { if iv != nil { this.iv = iv; return }; if err = this.newIV(); err != nil { return }; return }
func (this *CipherStream) Init(iv []byte, decrypt bool) (err error) {
	var cryptor interface{}; if err = this.setIV(iv); err != nil { return }
	cryptor, err = this.Info.makeCryptor(this.key, this.iv, decrypt)
	this.SetCryptor(cryptor); if err != nil { return }; return
}
func (this *CipherStream) SetKey(key []byte) { this.key = key }
func (this *CipherStream) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherStream) SetCryptor(cryptor interface{}) { this.Cryptor = cryptor.(cipher.Stream) }
func (this *CipherStream) GetCryptor() interface{} { return this.Cryptor }
func (this *CipherStream) newIV() (err error) { iv := make([]byte, this.IVSize()); if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }; this.iv = iv; return }
func (this *CipherStream) IV() []byte { return this.iv }
func (this *CipherStream) KeySize() int { return this.Info.KeySize }
func (this *CipherStream) IVSize() int { return this.Info.IVSize }
func (this *CipherStream) Encrypt(dst, src []byte) (err error) { this.Cryptor.XORKeyStream(dst, src); return }
func (this *CipherStream) Decrypt(dst, src []byte) (err error) { this.Cryptor.XORKeyStream(dst, src); return }

func newAESCFBStream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	var block cipher.Block; if block, err = aes.NewCipher(key); err != nil { return }
	if decrypt { cryptor = cipher.NewCFBDecrypter(block, iv) } else { cryptor = cipher.NewCFBEncrypter(block, iv) }
	return
}
func newAESCTRStream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	var block cipher.Block; if block, err = aes.NewCipher(key); err != nil { return }
	cryptor = cipher.NewCTR(block, iv); return
}
func newDESStream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	var block cipher.Block; if block, err = des.NewCipher(key); err != nil { return }
	if decrypt { cryptor = cipher.NewCFBDecrypter(block, iv) } else { cryptor = cipher.NewCFBEncrypter(block, iv) }
	return
}
func newBlowFishStream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	var block cipher.Block; if block, err = blowfish.NewCipher(key); err != nil { return }
	if decrypt { cryptor = cipher.NewCFBDecrypter(block, iv) } else { cryptor = cipher.NewCFBEncrypter(block, iv) }
	return
}
func newCast5Stream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	var block cipher.Block; if block, err = cast5.NewCipher(key); err != nil { return }
	if decrypt { cryptor = cipher.NewCFBDecrypter(block, iv) } else { cryptor = cipher.NewCFBEncrypter(block, iv) }
	return
}
func newRC4MD5Stream(key, iv []byte, decrypt bool) (cryptor interface{}, err error) {
	h := md5.New(); h.Write(key); h.Write(iv); rc4key := h.Sum(nil); return rc4.NewCipher(rc4key)
}
func newChaCha20Stream(key, iv []byte, decrypt bool) (interface{}, error) { return chacha20.NewCipher(key, iv) }
func newChaCha20IETFStream(key, iv []byte, decrypt bool) (interface{}, error) { return chacha20.NewCipher(key, iv) }
type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize { buf = dst[:dataSize] } else { buf = make([]byte, dataSize) }

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}
func newSalsa20Stream(key, iv []byte, decrypt bool) (interface{}, error) {
	var c salsaStreamCipher; copy(c.nonce[:], iv[:8]); copy(c.key[:], key[:32]); return &c, nil
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16; cnt := (keyLen-1)/md5Len + 1; m := make([]byte, cnt*md5Len); copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password)); start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len; copy(d, m[start-md5Len:start]); copy(d[md5Len:], password); copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func md5sum(d []byte) []byte { h := md5.New(); h.Write(d); return h.Sum(nil) }
func newStream(password string, info *cipherInfo) (c Cipher, err error) {
	key := info.makeKey(password, info.KeySize); c = new(CipherStream); c.SetKey(key); c.SetInfo(info); return
}