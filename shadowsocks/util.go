package shadowsocks

import (
	"errors"
	"fmt"
	"os"
)

func PrintVersion() {
	const version = "0.5"
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

func HasPort(s string) bool {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == ':' {
			return true
		}
	}
	return false
}
