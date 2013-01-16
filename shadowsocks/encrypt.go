package shadowsocks

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
)

type Cipher interface {
	// dst should have at least the same length as src
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type TableCipher struct {
	encTbl []byte
	decTbl []byte
}

func NewTableCipher(key string) (tbl *TableCipher) {
	const tbl_size = 256
	tbl = &TableCipher{
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
	return
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

// Function to get default cipher
var NewCipher = NewTableCipher

// Set default cipher. Empty string of cipher name uses the simple table
// cipher.
func SetDefaultCipher(cipherName string) (err error) {
	if cipherName == "" {
		return
	}
	return errors.New("cipher " + cipherName + " not supported")
}
