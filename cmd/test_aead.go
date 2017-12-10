package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"crypto/cipher"
	"fmt"
)

func getNonce(cryptor cipher.AEAD) (nonce []byte) {
	var size int
	size = cryptor.NonceSize()
	nonce = make([]byte, size)
	return
}

func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
	return
}

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
	//iv, err := c.NewIV()
	//iv := []byte{144,196,220,148,226,43,179,9,123,110,176,237,81,3,152,169,39,139,19,172,126,205,250,168,86,87,154,73,35,214,32,54}
	iv := []byte{55,131,26,68,227,24,211,193,86,191,218,220,166,40,137,205,88,43,111,134,240,9,244,59,180,175,99,46,182,168,89,31}
	c.Init(iv, ss.Decrypt)

	cryptor := c.GetCryptor(ss.Decrypt).(cipher.AEAD)
	src := []byte{39,243,15,11,50,64,192,249,111,50,121,84,95,207,193,244,110,117}
	dst := make([]byte, len(src)+cryptor.Overhead())

	fmt.Printf("iv: %d\n", iv)
	fmt.Printf("dst_len: %d\n", len(dst))
	fmt.Printf("src_len: %d\n", len(src))
	nonce := getNonce(cryptor)
	for i := 0; i < 10; i++ {
		//c.(*ss.CipherAead).SetNonce(true)
		fmt.Printf("nonce: %d\n", nonce)
		_, err = cryptor.Open(dst, nonce, src, nil)
		if err != nil { fmt.Println(err) }
		increment(nonce)
		fmt.Printf("%d\n", dst)
	}
}