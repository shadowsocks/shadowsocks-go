package shadowsocks

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
)

var errEmptyKey = errors.New("empty key")

type Cipher interface {
	// Some ciphers maintains context (e.g. RC4), which means different
	// connections need to use their own ciphers. Copy() will create an copy
	// of the cipher in the current state. Use this before calling
	// Encrypt/Decrypt to avoid initialization cost of of creating a new
	// cipher.
	Copy() Cipher
	// dst should have at least the same length as src
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type TableCipher struct {
	encTbl []byte
	decTbl []byte
}

// Creates a new table based cipher. err is always nil.
func NewTableCipher(key string) (c *TableCipher, err error) {
	if key == "" {
		return nil, errEmptyKey
	}
	const tbl_size = 256
	tbl := TableCipher{
		make([]byte, tbl_size),
		make([]byte, tbl_size),
	}
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
		tbl.encTbl[i] = byte(table[i])
	}
	for i = 0; i < tbl_size; i++ {
		tbl.decTbl[tbl.encTbl[i]] = byte(i)
	}
	return &tbl, nil
}

func (c *TableCipher) Encrypt(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = c.encTbl[src[i]]
	}
}

func (c *TableCipher) Decrypt(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = c.decTbl[src[i]]
	}
}

// Table cipher has no state, so can return itself.
func (c *TableCipher) Copy() Cipher {
	return c
}

type RC4Cipher struct {
	dec *rc4.Cipher
	enc *rc4.Cipher
}

func NewRC4Cipher(key string) (c *RC4Cipher, err error) {
	if key == "" {
		return nil, errEmptyKey
	}
	h := md5.New()
	h.Write([]byte(key))
	enc, err := rc4.NewCipher(h.Sum(nil))
	if err != nil {
		return
	}
	dec := *enc // create a copy
	c = &RC4Cipher{&dec, enc}
	return
}

func (c RC4Cipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c RC4Cipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Create a new RC4 cipher with the same keystream.
func (c RC4Cipher) Copy() Cipher {
	dec := *c.dec
	enc := *c.enc
	return &RC4Cipher{&dec, &enc}
}

// Create cipher based on name
func NewCipher(cipherName, key string) (Cipher, error) {
	switch cipherName {
	case "":
		return NewTableCipher(key)
	case "rc4":
		return NewRC4Cipher(key)
	}
	return nil, errors.New("encryption method " + cipherName + " not supported")
}
