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
	table := make([]int, 256)

	h := md5.New()
	io.WriteString(h, key)

	s := h.Sum(nil)

	var a int64
	buf := bytes.NewBuffer(s)
	binary.Read(buf, binary.LittleEndian, &a)
	for i := 0; i < 256; i++ {
		table[i] = i
	}
	for i := 1; i < 1024; i++ {
		table = Sort(table, func(x, y int) int {
				return int(a%int64(x + i) - a%int64(y + i))
			})
	}
	for i := 0; i < 256; i++ {
		encryptTable[i] = byte(table[i])
	}
	for i := 0; i < 256; i++ {
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
