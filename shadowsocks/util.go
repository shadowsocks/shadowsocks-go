package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// PrintVersion prints the current version of shadowsocks-go
func PrintVersion() {
	const version = "1.2.1"
	fmt.Println("shadowsocks-go version", version)
}

// IsFileExists returns true if the file exists
func IsFileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		if stat.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.New(path + " exists but is not regular file")
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// HmacSha1 implements HmacSha1
func HmacSha1(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

func otaConnectAuth(iv, key, data []byte) []byte {
	return append(data, HmacSha1(append(iv, key...), data)...)
}

func otaReqChunkAuth(iv []byte, chunkID uint32, data []byte) (header []byte) {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIDBytes, chunkID)
	header = append(nb, HmacSha1(append(iv, chunkIDBytes...), data)...)
	return
}

func methodOTAEnabled(method string) bool {
	if strings.HasSuffix(strings.ToLower(method), "-auth") {
		method = method[:len(method)-5] // len("-auth") = 5
		return true
	}
	return false
}

func rawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	len := headerLenDmBase + hostLen // addrType + lenByte + address + port
	buf = make([]byte, len)
	buf[idType] = typeDm         // 3 means the address is domain name
	buf[idDmLen] = byte(hostLen) // host address length  followed by host address
	copy(buf[idDm0:], host)
	binary.BigEndian.PutUint16(buf[idDm0+hostLen:idDm0+hostLen+2], uint16(port))
	return
}
