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

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func initCipher(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (interface{}, error) {
	if err != nil {
		Logger.Fields(LogFields{"err": err}).Warn("initCipher error")
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"err": err,
		}).Warn("newAESCFBStream error")
	}
	return initCipher(block, err, key, iv, doe)
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
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
			"err": err,
		}).Warn("newDESStream error")
	}
	return initCipher(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"err": err,
		}).Warn("newBlowFishStream error")
	}
	return initCipher(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (interface{}, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		Logger.Fields(LogFields{
			"key": key,
			"err": err,
		}).Warn("newCast5Stream error")
	}
	return initCipher(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	return chacha20.NewCipher(iv, key)
}

func newChaCha20IETFStream(key, iv []byte, _ DecOrEnc) (interface{}, error) {
	return chacha20.NewCipher(iv, key)
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
		//buf = leakyBuf.Get()
		//defer leakyBuf.Put(buf)
		//buf = buf[:dataSize]
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

type cipherInfo struct {
	method string
	ctype string
	keyLen    int
	ivLen     int
	initCipher func(key, iv []byte, doe DecOrEnc) (interface{}, error)
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {"aes-128-cfb", "stream",16, 16, newAESCFBStream},
	"aes-192-cfb":   {"aes-192-cfb", "stream",24, 16, newAESCFBStream},
	"aes-256-cfb":   {"aes-256-cfb", "stream",32, 16, newAESCFBStream},
	"aes-128-ctr":   {"aes-128-ctr", "stream",16, 16, newAESCTRStream},
	"aes-192-ctr":   {"aes-192-ctr", "stream",24, 16, newAESCTRStream},
	"aes-256-ctr":   {"aes-256-ctr", "stream",32, 16, newAESCTRStream},
	"des-cfb":       {"des-cfb", "stream",8, 8, newDESStream},
	"bf-cfb":        {"bf-cfb", "stream",16, 8, newBlowFishStream},
	"cast5-cfb":     {"cast5-cfb", "stream",16, 8, newCast5Stream},
	"rc4-md5":       {"rc4-md5", "stream",16, 16, newRC4MD5Stream},
	"chacha20":      {"chacha20", "stream",32, 8, newChaCha20Stream},
	"chacha20-ietf": {"chacha20-ietf", "stream",32, 12, newChaCha20IETFStream},
	"salsa20":       {"salsa20", "stream",32, 8, newSalsa20Stream},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherMethod[method]
	if !ok {
		Logger.Fields(LogFields{"method": method}).Error("Unsupported encryption method")
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type Cipher struct {
	enc  interface{}
	dec  interface{}
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		Logger.Fields(LogFields{"password": password}).Error("empty password")
		return nil, errEmptyPassword
	}
	mi, ok := cipherMethod[method]
	if !ok {
		Logger.Fields(LogFields{"method": method}).Error("Unsupported encryption method")
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, mi.keyLen)

	c = &Cipher{key: key, info: mi}

	if err != nil {
		return nil, err
	}
	return c, nil
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *Cipher) initEncrypt() (err error) {
	//c.newIV()
	Logger.Fields(LogFields{
		"cipher_addr": c,
		"key": c.key,
		"iv": c.iv,
	}).Info("Checking cipher info for init")
	c.enc, err = c.info.initCipher(c.key, c.iv, Encrypt)
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.initCipher(c.key, iv, Decrypt)
	return
}

func (c *Cipher) encrypt(dst, src []byte) {
	if c.info.ctype == "stream" {
		enc := (c.enc).(cipher.Stream)
		enc.XORKeyStream(dst, src)
	}
}

func (c *Cipher) decrypt(dst, src []byte) {
	if c.info.ctype == "stream" {
		dec := (c.dec).(cipher.Stream)
		dec.XORKeyStream(dst, src)
	}
}

// Copy creates a new cipher at it's initial state.
func (c *Cipher) Copy() *Cipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initizliation time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// maganitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}
