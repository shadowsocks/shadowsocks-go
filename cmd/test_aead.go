package main

import (
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"fmt"
)

func main() {
	method := "chacha20-ietf-poly1305"
	password := "123456"
	c, err := ss.NewCipher(method, password)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"method": method,
			"password":password,
			"err": err,
		}).Fatal("new cipher error")
	}
	src := []byte("hello")
	//iv, err := c.NewIV()
	iv := []byte{55,131,26,68,227,24,211,193,86,191,218,220,166,40,137,205,88,43,111,134,240,9,244,59,180,175,99,46,182,168,89,31}
	en_cryptor, err := c.Init(iv, ss.Encrypt)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"iv":iv,
			"err": err,
		}).Fatal("get encryptor error")
	}

	dst := make([]byte, len(src)+en_cryptor.(*ss.CryptorAead).Overhead())
	en_cryptor.Encrypt(dst, src)
	fmt.Println(dst)

	de_cryptor, err := c.Init(iv, ss.Decrypt)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"iv":iv,
			"err": err,
		}).Fatal("get decryptor error")
	}

	err = de_cryptor.Decrypt(dst, dst)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"iv":iv,
			"err": err,
		}).Fatal("decrypt error")
	}
	fmt.Printf("dst: %s\n", dst[:len(src)])
}