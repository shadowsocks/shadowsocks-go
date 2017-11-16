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
)

var errEmptyPassword = errors.New("empty key")

type CipherStream struct {
	Cipher

	Doe DecOrEnc
	Enc  cipher.Stream
	Dec  cipher.Stream
	Info *cipherInfo

	key []byte
	iv   []byte
}

func (c *CipherStream) Init() (err error) {
	if (c.Doe == Encrypt && c.Enc != nil) || (c.Doe == Decrypt && c.Dec != nil) {
		return
	}

	c_new, err := c.Info.makeCipher(c)

	if c.Doe == Encrypt {
		c.Enc = c_new.(cipher.Stream)
	} else if c.Doe == Decrypt {
		c.Dec = c_new.(cipher.Stream)
	}
	return
}

func (c *CipherStream) Pack(b []byte) (data []byte, err error) {
	p := newPacketStream(c, Encrypt)
	err = p.initPacket(b)
	if err != nil {
		return
	}

	return p.getPacket(), nil
}

func (c *CipherStream) UnPack(b []byte) (data []byte, err error) {
	p := newPacketStream(c, Decrypt)
	err = p.initPacket(b)
	if err != nil {
		return
	}

	return p.getPacket(), nil
}

func (c *CipherStream) Encrypt(dst, src []byte) (error) {
	c.Enc.XORKeyStream(dst, src)
	c.Doe = Decrypt

	return nil
}

func (c *CipherStream) Decrypt(dst, src []byte) (error) {
	c.Dec.XORKeyStream(dst, src)
	c.Doe = Encrypt

	return nil
}

func (c *CipherStream) Copy() (*CipherStream) {
	nc := *c
	nc.Enc = nil
	nc.Dec = nil
	return &nc
}

func newStream(password string, mi *cipherInfo) (*CipherStream) {
	key := evpBytesToKey(password, mi.keyLen)

	c := &CipherStream{key: key}
	c.Info = mi

	return c
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

func newAESCFBStream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	block, err := aes.NewCipher(item.key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Warn("newAESCFBStream error")
	}
	return initStream(block, err, item.key, item.iv, item.Doe)
}

func newAESCTRStream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	block, err := aes.NewCipher(item.key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Warn("newAESCTRStream error")
		return nil, err
	}
	return cipher.NewCTR(block, item.iv), nil
}

func newDESStream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	block, err := des.NewCipher(item.key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Warn("newDESStream error")
	}
	return initStream(block, err, item.key, item.iv, item.Doe)
}

func newBlowFishStream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	block, err := blowfish.NewCipher(item.key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Warn("newBlowFishStream error")
	}
	return initStream(block, err, item.key, item.iv, item.Doe)
}

func newCast5Stream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	block, err := cast5.NewCipher(item.key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Warn("newCast5Stream error")
	}
	return initStream(block, err, item.key, item.iv, item.Doe)
}

func newRC4MD5Stream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	h := md5.New()
	h.Write(item.key)
	h.Write(item.iv)
	rc4key := h.Sum(nil)

	c, err := rc4.NewCipher(rc4key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Fatal("newRC4MD5Stream error")
	}

	return c, err
}

func newChaCha20Stream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	c, err := chacha20.NewCipher(item.key, item.iv)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Fatal("newChaCha20Stream error")
	}

	return c, err
}

func newChaCha20IETFStream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	c, err := chacha20.NewCipher(item.key, item.iv)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"iv": item.iv,
			"err": err,
		}).Fatal("newChaCha20IETFStream error")
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

func newSalsa20Stream(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherStream)
	var c salsaStreamCipher
	copy(c.nonce[:], item.iv[:8])
	copy(c.key[:], item.key[:32])
	return &c, nil
}
