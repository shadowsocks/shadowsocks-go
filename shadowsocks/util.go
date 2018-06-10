package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
)

func PrintVersion() {
	const version = "1.2.2"
	fmt.Println("shadowsocks-go version", version)
}

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

func HmacSha1(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

type ClosedFlag struct {
	flag bool
}

func (flag *ClosedFlag) SetClosed() {
	flag.flag = true
}

func (flag *ClosedFlag) IsClosed() bool {
	return flag.flag
}
