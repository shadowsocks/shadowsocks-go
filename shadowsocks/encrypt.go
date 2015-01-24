package shadowsocks

import (
	"bytes"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"
)

var errEmptyPassword = errors.New("empty key")

type tableCipher []byte

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

func (tbl tableCipher) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = tbl[src[i]]
	}
}

// NewTableCipher creates a new table based cipher.
func newTableCipher(s []byte) (enc, dec tableCipher) {
	const tbl_size = 256
	enc = make([]byte, tbl_size)
	dec = make([]byte, tbl_size)
	table := make([]uint64, tbl_size)

	var a uint64
	buf := bytes.NewBuffer(s)
	binary.Read(buf, binary.LittleEndian, &a)
	var i uint64
	for i = 0; i < tbl_size; i++ {
		table[i] = i
	}
	for i = 1; i < 1024; i++ {
		table = Sort(table, func(x, y uint64) int64 {
			return int64(a%uint64(x+i) - a%uint64(y+i))
		})
	}
	for i = 0; i < tbl_size; i++ {
		enc[i] = byte(table[i])
	}
	for i = 0; i < tbl_size; i++ {
		dec[enc[i]] = byte(i)
	}
	return enc, dec
}

func newRC4Cipher(key []byte) (enc, dec cipher.Stream, err error) {
	rc4Enc, err := rc4.NewCipher(key)
	if err != nil {
		return
	}
	// create a copy, as RC4 encrypt and decrypt uses the same keystream
	rc4Dec := *rc4Enc
	return rc4Enc, &rc4Dec, nil
}

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newStream(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb": {16, 16, newAESStream},
	"aes-192-cfb": {24, 16, newAESStream},
	"aes-256-cfb": {32, 16, newAESStream},
	"des-cfb":     {8, 8, newDESStream},
	"bf-cfb":      {16, 8, newBlowFishStream},
	"cast5-cfb":   {16, 8, newCast5Stream},
	"rc4-md5":     {16, 16, newRC4MD5Stream},
	"rc4":         {16, 0, nil},
	"table":       {16, 0, nil},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "table"
	}
	_, ok := cipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	if method == "" {
		method = "table"
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, mi.keyLen)

	c = &Cipher{key: key, info: mi}

	if mi.newStream == nil {
		if method == "table" {
			c.enc, c.dec = newTableCipher(key)
		} else if method == "rc4" {
			c.enc, c.dec, err = newRC4Cipher(key)
		}
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *Cipher) initEncrypt() (iv []byte, err error) {
	iv = make([]byte, c.info.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	if err != nil {
		return nil, err
	}
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
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

	switch c.enc.(type) {
	case tableCipher:
		return c
	case *rc4.Cipher:
		enc, _ := c.enc.(*rc4.Cipher)
		encCpy := *enc
		decCpy := *enc
		return &Cipher{enc: &encCpy, dec: &decCpy}
	default:
		nc := *c
		nc.enc = nil
		nc.dec = nil
		return &nc
	}
}
