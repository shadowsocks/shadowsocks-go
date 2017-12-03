package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"crypto/cipher"
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
	//iv, err := c.NewIV()
	//iv := []byte{144,196,220,148,226,43,179,9,123,110,176,237,81,3,152,169,39,139,19,172,126,205,250,168,86,87,154,73,35,214,32,54}
	iv := []byte{54,211,221,126,29,73,15,101,192,103,98,71,255,159,44,33,68,117,12,136,61,140,123,125,40,179,172,59,40,33,67,237}
	c.Init(iv, ss.Decrypt)
	src := []byte{127,211,100,44,95,80,200,254,227,121,150,129,137,19,151,142,167,15}
	dst := make([]byte, len(src)+c.GetCryptor().(cipher.AEAD).Overhead())

	fmt.Printf("iv: %d\n", iv)
	fmt.Printf("dst_len: %d\n", len(dst))
	fmt.Printf("src_len: %d\n", len(src))
	for i := 0; i < 10; i++ {
		c.(*ss.CipherAead).SetNonce(true)
		fmt.Printf("nonce: %d\n", c.(*ss.CipherAead).Nonce())
		err = c.Decrypt(dst, src)
		if err != nil { fmt.Println(err) }
		fmt.Printf("%d\n", dst)
	}
}