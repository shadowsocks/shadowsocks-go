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

var (
	streamCipherMethod = map[string]*streamGenerator{
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
	}
)

type streamGenerator struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

// CheckCipherMethod checks if the cipher method is supported
func CheckCipherMethod(method string) error {
	if _, ok := streamCipherMethod[method]; !ok {
		return ErrUnsupportedMethod
	}
	return nil
}

type streamCipher struct {
	enc     cipher.Stream
	dec     cipher.Stream
	keyLen  int
	ivLen   int
	key     []byte
	iv      []byte
	genator func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

func (c *streamCipher) KeySize() int       { return c.keyLen }
func (c *streamCipher) InitBolckSize() int { return c.ivLen }

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewStreamCipher(method, password string) (c *streamCipher, err error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, mi.keyLen)

	c = &streamCipher{
		keyLen:  mi.keyLen,
		ivLen:   mi.ivLen,
		key:     key,
		iv:      make([]byte, mi.ivLen, mi.ivLen),
		genator: mi.newStream,
	}

	if err != nil {
		return nil, err
	}

	return c, nil
}

// InitEncrypt initializes the block cipher, returns IV.
func (c *streamCipher) InitEncryptor() (iv []byte, err error) {
	iv = make([]byte, c.ivLen, c.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	c.iv = iv
	c.enc, err = c.genator(c.key, c.iv, Encrypt)
	return
}

// EncInited checks if the enc cipher is inited.
func (c *streamCipher) EncryptorInited() bool {
	return c.enc == nil
}

// InitDecrypt initializes the block cipher from given IV.
func (c *streamCipher) InitDecryptor(iv []byte) (err error) {
	ivC := make([]byte, c.ivLen, c.ivLen)
	copy(ivC, iv)
	c.iv = ivC
	c.dec, err = c.genator(c.key, ivC, Decrypt)
	return
}

// DecInited checks if the dec cipher is inited.
func (c *streamCipher) DecryptorInited() bool {
	return c.dec == nil
}

// Encrypt encrypts src to dst, maybe the same slice.
func (c *streamCipher) Encrypt(src, dst []byte) (int, error) {
	if c.EncryptorInited() {
		return -1, ErrCipherUninitialized
	}
	c.enc.XORKeyStream(dst[:len(src)], src)
	return len(src), nil
}

// Decrypt decrypts src to dst, maybe the same slice.
func (c *streamCipher) Decrypt(src, dst []byte) (int, error) {
	if c.DecryptorInited() {
		return -1, ErrCipherUninitialized
	}
	c.dec.XORKeyStream(dst[:len(src)], src)
	return len(src), nil
}

func (c *streamCipher) Pack(src, dst []byte) (int, error) {
	iv, err := c.InitEncryptor()
	if err != nil {
		return -1, err
	}
	n := copy(dst[0:], iv)
	if n != c.ivLen {
		return -1, ErrCapcityNotEnough
	}

	c.enc.XORKeyStream(dst[n:], src)
	return len(src) + c.ivLen, nil
}
func (c *streamCipher) Unpack(src, dst []byte) (int, error) {
	err := c.InitDecryptor(src[:c.ivLen])
	if err != nil {
		return -1, err
	}

	c.dec.XORKeyStream(dst, src[c.ivLen:])
	return len(src) - c.ivLen, nil
}

// Copy creates a new cipher at it's initial state.
func (c *streamCipher) Copy() Cipher {
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
