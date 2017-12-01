package main

import (
	"crypto/cipher"
	"crypto/aes"
	"fmt"
	"errors"
	"crypto/md5"
	"io"
	"encoding/binary"
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha1"
	"crypto/des"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"crypto/rc4"
	"github.com/Yawning/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
)

type cipherInfo struct {
	method string
	KeySize    int
	IVSize     int
	makeCipher func(password string, info *cipherInfo) (Cipher, error) // make general cipher
	makeKey func(password string, keySize int) (key []byte) // make key by password
	makeCryptor func(key []byte, iv []byte, decrypt bool) (interface{}, error) // make stream for stream cipher with key or make aead for aead cipher with subkey which is made by key and iv
}

type Cipher interface {
	/////////////////////////////////////////////////
	Init(iv []byte, decrypt bool) (err error)
	SetKey(key []byte)
	SetInfo(info *cipherInfo)
	SetCryptor(cryptor interface{})
	GetCryptor() interface{}
	newIV() (err error)
	IV() []byte
	KeySize() int
	IVSize() int
	Encrypt(dst, src []byte) error
	Decrypt(dst, src []byte) error
	/////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
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
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
type CipherStream struct {
	Cipher
	Cryptor cipher.Stream
	Info *cipherInfo

	key []byte
	iv []byte

	ivSize int
	keySize int
}

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

func NewCipher(method, password string) (c Cipher, err error) {
	if password == "" { err = errors.New("password is empty"); return }
	mi, ok := cipherMethod[method]
	if !ok { err = errors.New("Unsupported encryption method: " + method); return }
	return mi.makeCipher(password, mi)
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
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////

//var cipherMethod = map[string]*cipherInfo{
//	"aes-128-cfb":   {"aes-128-cfb", 16, 16, newStream, evpBytesToKey, newAESCFBStream},
//	"aes-192-cfb":   {"aes-192-cfb", 24, 16, newStream, evpBytesToKey, newAESCFBStream},
//	"aes-256-cfb":   {"aes-256-cfb", 32, 16, newStream, evpBytesToKey, newAESCFBStream},
//	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", 32, 32, newAead, kdf, newChaCha20IETFPoly1305Aead},
//}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {"aes-128-cfb", 16, 16, newStream, evpBytesToKey, newAESCFBStream},
	"aes-192-cfb":   {"aes-192-cfb", 24, 16, newStream, evpBytesToKey, newAESCFBStream},
	"aes-256-cfb":   {"aes-256-cfb", 32, 16, newStream, evpBytesToKey, newAESCFBStream},
	"aes-128-ctr":   {"aes-128-ctr", 16, 16, newStream, evpBytesToKey, newAESCTRStream},
	"aes-192-ctr":   {"aes-192-ctr", 24, 16, newStream, evpBytesToKey, newAESCTRStream},
	"aes-256-ctr":   {"aes-256-ctr", 32, 16, newStream, evpBytesToKey, newAESCTRStream},
	"des-cfb":       {"des-cfb", 8, 8, newStream, evpBytesToKey, newDESStream},
	"bf-cfb":        {"bf-cfb", 16, 8, newStream, evpBytesToKey, newBlowFishStream},
	"cast5-cfb":     {"cast5-cfb", 16, 8, newStream, evpBytesToKey, newCast5Stream},
	"rc4-md5":       {"rc4-md5", 16, 16, newStream, evpBytesToKey, newRC4MD5Stream},
	"chacha20":      {"chacha20", 32, 8, newStream, evpBytesToKey, newChaCha20Stream},
	"chacha20-ietf": {"chacha20-ietf", 32, 12, newStream, evpBytesToKey, newChaCha20IETFStream},
	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", 32, 32, newAead, kdf, newChaCha20IETFPoly1305Aead},
	"salsa20":       {"salsa20", 32, 8, newStream, evpBytesToKey, newSalsa20Stream},
}

func check_cipher(info *cipherInfo, src []byte) {
	c, err := NewCipher(info.method, "123456")
	if err != nil {
		fmt.Print(err)
	}
	if info.method == "chacha20-ietf-poly1305" {
		///////////////////////////////////////
		fmt.Println("----------------------------------------")
		fmt.Printf("Testing aead %s\n", info.method)
		fmt.Println("----------------------------------------")
		err = c.Init(nil, false)
		if err != nil {
			fmt.Print(err)
		}
		dst := make([]byte, c.GetCryptor().(cipher.AEAD).Overhead()+len(src))
		err = c.Encrypt(dst, src)
		if err != nil {
			fmt.Print(err)
		}
		iv := c.IV()
		fmt.Println("check data encrypted")
		fmt.Printf("data: %d(%d)\n", dst, len(dst))
		fmt.Printf("iv: %d\n", iv)
		fmt.Println("----------------------------------------")

		err = c.Init(iv, true)
		if err != nil {
			fmt.Print(err)
		}
		src = dst
		dst = make([]byte, 2+c.GetCryptor().(cipher.AEAD).Overhead()+len(src))
		err = c.Decrypt(dst, src)
		if err != nil {
			fmt.Print(err)
		}
		fmt.Println("check data decrypted")
		fmt.Printf("data: %s\n", dst)
		fmt.Printf("iv: %d\n", iv)
		fmt.Println("----------------------------------------")
	} else {
		///////////////////////////////////////
		fmt.Printf("Testing stream %s\n", info.method)
		fmt.Println("----------------------------------------")

		dst := make([]byte, len(src))
		c.Init(nil, false)
		c.Encrypt(dst, src)
		fmt.Println("check data encrypted")
		fmt.Printf("data: %d\n", dst)

		c.Init(c.IV(), true)
		err = c.Decrypt(dst, dst)
		if err != nil {
			fmt.Print(err)
		}
		fmt.Println("----------------------------------------")
		fmt.Println("check data decrypted")
		fmt.Printf("data: %s\n", dst)
		fmt.Println("----------------------------------------")
		///////////////////////////////////////
	}
}

func main() {
	src := []byte("hello")
	for _, item := range cipherMethod {
		check_cipher(item, src)
	}
	//////////////////////////////////////////////////////////////
	///////////////////////////////////////
	fmt.Println("Testing stream")
	fmt.Println("----------------------------------------")
	c, err := NewCipher("aes-128-cfb", "123456")
	if err != nil {
		fmt.Print(err)
	}
	dst := make([]byte, len(src))
	c.Init(nil, false)
	c.Encrypt(dst, src)
	fmt.Println("check data encrypted")
	fmt.Printf("data: %d\n", dst)

	c.Init(c.IV(), true)
	err = c.Decrypt(dst, dst)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println("----------------------------------------")
	fmt.Println("check data decrypted")
	fmt.Printf("data: %s\n", dst)
	fmt.Println("----------------------------------------")
	///////////////////////////////////////
	fmt.Println("----------------------------------------")
	fmt.Println("Testing aead")
	fmt.Println("----------------------------------------")
	c, err = NewCipher("chacha20-ietf-poly1305", "123456")
	if err != nil {
		fmt.Print(err)
	}
	err = c.Init(nil, false)
	if err != nil {
		fmt.Print(err)
	}
	dst = make([]byte, c.GetCryptor().(cipher.AEAD).Overhead()+len(src))
	err = c.Encrypt(dst, src)
	if err != nil {
		fmt.Print(err)
	}
	iv := c.IV()
	fmt.Println("check data encrypted")
	fmt.Printf("data: %d(%d)\n", dst, len(dst))
	fmt.Printf("iv: %d\n", iv)
	fmt.Println("----------------------------------------")

	err = c.Init(iv, true)
	if err != nil {
		fmt.Print(err)
	}
	src = dst
	dst = make([]byte, 2+c.GetCryptor().(cipher.AEAD).Overhead()+len(src))
	err = c.Decrypt(dst, src)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println("check data decrypted")
	fmt.Printf("data: %s\n", dst)
	fmt.Printf("iv: %d\n", iv)
	fmt.Println("----------------------------------------")
}