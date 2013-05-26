package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
)

var errEmptyKey = errors.New("empty key")

type tableCipher []byte

func (tbl tableCipher) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = tbl[src[i]]
	}
}

// NewTableCipher creates a new table based cipher.
func newTableCipher(key string) (enc, dec tableCipher) {
	const tbl_size = 256
	enc = make([]byte, tbl_size)
	dec = make([]byte, tbl_size)
	table := make([]uint64, tbl_size)

	h := md5.New()
	h.Write([]byte(key))
	s := h.Sum(nil)

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

func newRC4Cipher(key string) (enc, dec cipher.Stream, err error) {
	h := md5.New()
	h.Write([]byte(key))
	rc4Enc, err := rc4.NewCipher(h.Sum(nil))
	if err != nil {
		return
	}
	// create a copy, as RC4 encrypt and decrypt uses the same keystream
	rc4Dec := *rc4Enc
	return rc4Enc, &rc4Dec, nil
}

type Cipher struct {
	enc    cipher.Stream
	dec    cipher.Stream
	key    string
	method string
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (*Cipher, error) {
	if password == "" {
		return nil, errEmptyKey
	}

	cipher := Cipher{method: method, key: password}
	var err error

	if method == "" || method == "table" {
		cipher.enc, cipher.dec = newTableCipher(password)
	} else if method == "rc4" {
		cipher.enc, cipher.dec, err = newRC4Cipher(password)
	}
	if err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Cipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

func (c *Cipher) Copy() *Cipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.
	switch c.enc.(type) {
	case tableCipher:
		return c
	case *rc4.Cipher:
		enc, _ := c.enc.(*rc4.Cipher)
		encCpy := *enc
		decCpy := *enc
		return &Cipher{enc: &encCpy, dec: &decCpy}
	default:
		nc, _ := NewCipher(c.method, c.key)
		return nc
	}
}
