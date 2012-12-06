package shadowsocks

import (
	"crypto/md5"
	"io"
	"encoding/binary"
	"bytes"
)

func GetTable(key string) (encryptTable []byte, decryptTable []byte) {
	encryptTable = make([]byte, 256)
	decryptTable = make([]byte, 256)
	table := make([]uint64, 256)

	h := md5.New()
	io.WriteString(h, key)

	s := h.Sum(nil)

	var a uint64
	buf := bytes.NewBuffer(s)
	binary.Read(buf, binary.LittleEndian, &a)
	var i uint64
	for i = 0; i < 256; i++ {
		table[i] = i
	}
	for i = 1; i < 1024; i++ {
		table = Sort(table, func(x, y uint64) int64 {
				return int64(a%uint64(x + i) - a%uint64(y + i))
			})
	}
	for i = 0; i < 256; i++ {
		encryptTable[i] = byte(table[i])
	}
	for i = 0; i < 256; i++ {
		decryptTable[encryptTable[i]] = byte(i)
	}

	return
}

func Encrypt(table []byte, buf []byte) []byte {
	var result = make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		result[i] = table[buf[i]]
	}
	return result
}
