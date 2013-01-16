package shadowsocks

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"
)

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
func NewTableCipher(key string) (c Cipher, err error) {
	const tbl_size = 256
	tbl := TableCipher{
		make([]byte, tbl_size, tbl_size),
		make([]byte, tbl_size, tbl_size),
	}
	table := make([]uint64, tbl_size, tbl_size)

	h := md5.New()
	io.WriteString(h, key)

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

func NewRC4Cipher(key string) (c Cipher, err error) {
	keybytes := []byte(key)
	enc, err := rc4.NewCipher(keybytes)
	if err != nil {
		return
	}
	dec, _ := rc4.NewCipher(keybytes)
	c = &RC4Cipher{dec, enc}
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

// Function to get default cipher
var NewCipher = NewTableCipher

// Set default cipher. Empty string of cipher name uses the simple table
// cipher.
func SetDefaultCipher(cipherName string) (err error) {
	switch cipherName {
	case "":
		NewCipher = NewTableCipher
	case "rc4":
		NewCipher = NewRC4Cipher
	default:
		return errors.New("encryption method " + cipherName + " not supported")
	}
	return
}
