package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Yawning/chacha20"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
)

// DecOrEnc type, encrypt or decrypt, used when create cipher
type DecOrEnc int

const (
	// Decrypt as its name
	Decrypt DecOrEnc = iota
	// Encrypt as its name
	Encrypt
)

var errEmptyPassword = errors.New("empty key")

// CheckCipherMethod checks if the cipher method is supported
func CheckCipherMethod(method string) error {
	if _, ok := cipherMethod[method]; !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

// Cipher is used to encrypt and decrypt things.
type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, mi.keyLen)

	c = &Cipher{key: key, info: mi}

	if err != nil {
		return nil, err
	}

	return c, nil
}

// InitEncrypt initializes the block cipher, returns IV.
func (c *Cipher) InitEncrypt() (iv []byte, err error) {
	iv = make([]byte, c.info.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	c.iv = iv
	c.enc, err = c.info.newStream(c.key, c.iv, Encrypt)
	return
}

// EncInited checks if the enc cipher is inited.
func (c *Cipher) EncInited() bool {
	return c.enc == nil
}

// InitDecrypt initializes the block cipher from given IV.
func (c *Cipher) InitDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

// DecInited checks if the dec cipher is inited.
func (c *Cipher) DecInited() bool {
	return c.dec == nil
}

// Encrypt encrypts src to dst, maybe the same slice.
func (c *Cipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

// Decrypt decrypts src to dst, maybe the same slice.
func (c *Cipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
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

// GetIV returns current IV, safe to use
func (c *Cipher) GetIV() []byte {
	ret := make([]byte, len(c.iv))
	copy(ret, c.iv)
	return ret
}

// GetKey returns current Key, safe to use
func (c *Cipher) GetKey() []byte {
	ret := make([]byte, len(c.key))
	copy(ret, c.key)
	return ret
}

// GetIVLen return the length of IV
func (c *Cipher) GetIVLen() int {
	return c.info.ivLen
}

// SetIV sets the given IV, please ensure the IV is valid value
func (c *Cipher) SetIV(iv []byte) {
	c.iv = make([]byte, len(iv))
	copy(c.iv, iv)
}

// GetKeyLen return the length of Key
func (c *Cipher) GetKeyLen() int {
	return c.info.keyLen
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

func newStream(block cipher.Block, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newStream(block, key, iv, doe)
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newStream(block, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newStream(block, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newStream(block, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(key, iv)
}

func newChaCha20IETFStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(key, iv)
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

func newSalsa20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {16, 16, newAESCFBStream},
	"aes-192-cfb":   {24, 16, newAESCFBStream},
	"aes-256-cfb":   {32, 16, newAESCFBStream},
	"aes-128-ctr":   {16, 16, newAESCTRStream},
	"aes-192-ctr":   {24, 16, newAESCTRStream},
	"aes-256-ctr":   {32, 16, newAESCTRStream},
	"des-cfb":       {8, 8, newDESStream},
	"bf-cfb":        {16, 8, newBlowFishStream},
	"cast5-cfb":     {16, 8, newCast5Stream},
	"rc4-md5":       {16, 16, newRC4MD5Stream},
	"chacha20":      {32, 8, newChaCha20Stream},
	"chacha20-ietf": {32, 12, newChaCha20IETFStream},
	"salsa20":       {32, 8, newSalsa20Stream},

	//"chacha20-ietf-poly1305": {32, 32, nil},
	//"aes-256-gcm":            {32, 32, nil},
	//"aes-192-gcm":            {24, 24, nil},
	//"aes-128-gcm":            {16, 16, nil},
}
