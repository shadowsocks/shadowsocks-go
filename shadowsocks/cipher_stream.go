package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
	"github.com/Yawning/chacha20"
	"io"
	"crypto/rand"
	"bytes"
)

type CipherStream struct {
	Cipher
	EnCryptor cipher.Stream
	DeCryptor cipher.Stream
	Info      *cipherInfo
	key       []byte
	iv        [2][]byte
	ivSize    int
	keySize   int
}

/////////////////////////////////////////////////////////
func (this *CipherStream) isStream() bool { return true }
func (this *CipherStream) Init(iv []byte, doe DecOrEnc) (err error) {
	if bytes.Equal(this.iv[doe], iv) { return }
	var cryptor interface{}
	if cryptor, err = this.Info.makeCryptor(this.key, iv, doe); err != nil {
		return
	}
	this.iv[doe] = iv

	this.SetCryptor(cryptor, doe)
	return
}
func (this *CipherStream) SetKey(key []byte)        { this.key = key }
func (this *CipherStream) SetInfo(info *cipherInfo) { this.Info = info }
func (this *CipherStream) SetCryptor(cryptor interface{}, doe DecOrEnc) {
	if doe == Decrypt {
		this.DeCryptor = cryptor.(cipher.Stream)
	} else {
		this.EnCryptor = cryptor.(cipher.Stream)
	}
}
func (this *CipherStream) GetCryptor(doe DecOrEnc) interface{} {
	if doe == Decrypt {
		return this.DeCryptor
	} else {
		return this.EnCryptor
	}
}
func (this *CipherStream) NewIV() (iv []byte, err error) {
	iv = make([]byte, this.IVSize())
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	return
}
func (this *CipherStream) Key() []byte                         { return this.key }
func (this *CipherStream) IV(doe DecOrEnc) []byte          { return this.iv[doe] }
func (this *CipherStream) KeySize() int                        { return this.Info.KeySize }
func (this *CipherStream) IVSize() int                         { return this.Info.IVSize }
func (this *CipherStream) Encrypt(dst, src []byte) (err error) { this.EnCryptor.XORKeyStream(dst, src); return }
func (this *CipherStream) Decrypt(dst, src []byte) (err error) { this.DeCryptor.XORKeyStream(dst, src); return }

/////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////
func cfbCryptor(block cipher.Block, iv []byte, doe DecOrEnc) cipher.Stream {
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv)
	}
	return cipher.NewCFBDecrypter(block, iv)
}
func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	var block cipher.Block;
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	cryptor = cfbCryptor(block, iv, doe)
	return
}
func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	cryptor = cipher.NewCTR(block, iv)
	return
}
func newDESStream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	var block cipher.Block
	if block, err = des.NewCipher(key); err != nil {
		return
	}
	cryptor = cfbCryptor(block, iv, doe)
	return
}
func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	var block cipher.Block
	if block, err = blowfish.NewCipher(key); err != nil {
		return
	}
	cryptor = cfbCryptor(block, iv, doe)
	return
}
func newCast5Stream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	var block cipher.Block
	if block, err = cast5.NewCipher(key); err != nil {
		return
	}
	cryptor = cfbCryptor(block, iv, doe)
	return
}
func newRC4MD5Stream(key, iv []byte, doe DecOrEnc) (cryptor interface{}, err error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)
	return rc4.NewCipher(rc4key)
}
func newChaCha20Stream(key, iv []byte, doe DecOrEnc) (interface{}, error)     { return chacha20.NewCipher(key, iv) }
func newChaCha20IETFStream(key, iv []byte, doe DecOrEnc) (interface{}, error) { return chacha20.NewCipher(key, iv) }

/////////////////////////////////////////////////////////
type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

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
func newSalsa20Stream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

/////////////////////////////////////////////////////////
func newStream(password string, info *cipherInfo) (c Cipher, err error) {
	key := info.makeKey(password, info.KeySize)
	c = new(CipherStream)
	c.SetKey(key)
	c.SetInfo(info)
	return
}
/////////////////////////////////////////////////////////
