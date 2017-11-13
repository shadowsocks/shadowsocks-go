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
	"github.com/codahale/chacha20poly1305"
)

var errEmptyPassword = errors.New("empty key")

type CipherStream struct {
	Cipher

	key []byte
	iv   []byte
	iv_len int
}

func (c *CipherStream)init(doe DecOrEnc) (err error) {
	if (doe == Encrypt && c.enc != nil) || (doe == Decrypt && c.dec != nil) {
		if doe == Encrypt {
			c.iv_len = 0
		}
		return
	}
	cipherObj, err := c.info.initCipher(c.key, c.iv, doe)

	if doe == Encrypt {
		c.enc = cipherObj
		c.iv_len = len(c.iv)
	} else if doe == Decrypt {
		c.dec = cipherObj
	}
	return
}

func (c *CipherStream) encrypt(dst, src []byte) {
	enc := (c.enc).(cipher.Stream)
	enc.XORKeyStream(dst, src)
}

func (c *CipherStream) decrypt(dst, src []byte) {
	dec := (c.dec).(cipher.Stream)
	dec.XORKeyStream(dst, src)
}

func newStream(password string, mi *cipherInfo) (*CipherStream) {
	key := evpBytesToKey(password, mi.keyLen)

	c_stream := &CipherStream{key: key}
	c_stream.info = mi

	return c_stream
}

func initStream(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (interface{}, error) {
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"is_encrypt": doe,
			"err": err,
		}).Fatal("initCipher error")
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Warn("newAESCFBStream error")
	}
	return initStream(block, err, key, iv, doe)
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Warn("newAESCTRStream error")
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newDESStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Warn("newDESStream error")
	}
	return initStream(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Warn("newBlowFishStream error")
	}
	return initStream(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Warn("newCast5Stream error")
	}
	return initStream(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	c, err := rc4.NewCipher(rc4key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Fatal("newRC4MD5Stream error")
	}

	return c, err
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	c, err := chacha20.NewCipher(key, iv)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Fatal("newChaCha20Stream error")
	}

	return c, err
}

func newChaCha20IETFStream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	c, err := chacha20.NewCipher(key, iv)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Fatal("newChaCha20IETFStream error")
	}

	return c, err
}

func newChaCha20IETFPoly1305Aead(key, iv[]byte, _ DecOrEnc) (interface{}, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"iv": iv,
			"err": err,
		}).Fatal("newChaCha20IETFPoly1305Aead error")
	}

	return c, err
}

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
	} else if leakyBufSize >= dataSize {
		buf = leakyBuf.Get()
		defer leakyBuf.Put(buf)
		buf = buf[:dataSize]
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

func newSalsa20Stream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}
