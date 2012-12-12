package shadowsocks

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
)

type EncryptTable struct {
	encTbl []byte
	decTbl []byte
}

func GetTable(key string) (tbl *EncryptTable) {
	const tbl_size = 256
	tbl = &EncryptTable{
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

func Encrypt2(table []byte, buf, result []byte) {
	for i := 0; i < len(buf); i++ {
		result[i] = table[buf[i]]
	}
}

func Encrypt(table []byte, buf []byte) []byte {
	var result = make([]byte, len(buf), len(buf))
	Encrypt2(table, buf, result)
	return result
}
