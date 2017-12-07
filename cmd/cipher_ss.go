package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"crypto/cipher"
	"fmt"
)

type cipherInfo struct {
	method string
	KeySize    int
	IVSize     int
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {"aes-128-cfb", 16, 16},
	"aes-192-cfb":   {"aes-192-cfb", 24, 16},
	"aes-256-cfb":   {"aes-256-cfb", 32, 16},
	"aes-128-ctr":   {"aes-128-ctr", 16, 16},
	"aes-192-ctr":   {"aes-192-ctr", 24, 16},
	"aes-256-ctr":   {"aes-256-ctr", 32, 16},
	"des-cfb":       {"des-cfb", 8, 8},
	"bf-cfb":        {"bf-cfb", 16, 8},
	"cast5-cfb":     {"cast5-cfb", 16, 8},
	"rc4-md5":       {"rc4-md5", 16, 16},
	"chacha20":      {"chacha20", 32, 8},
	"chacha20-ietf": {"chacha20-ietf", 32, 12},
	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", 32, 32},
	"salsa20":       {"salsa20", 32, 8},
}

func check_cipher(info *cipherInfo, src []byte) {
	c, err := ss.NewCipher(info.method, "123456"); if err != nil { fmt.Print(err) }

	if info.method == "chacha20-ietf-poly1305" {
		///////////////////////////////////////
		fmt.Println("----------------------------------------")
		fmt.Printf("Testing aead %s\n", info.method)
		fmt.Println("----------------------------------------")

		iv, err := c.NewIV(); if err != nil { fmt.Print(err) }
		if err = c.Init(iv, ss.Encrypt); err != nil { fmt.Print(err) }

		dst := make([]byte, c.GetCryptor(ss.Encrypt).(cipher.AEAD).Overhead()+len(src))
		err = c.Encrypt(dst, src); if err != nil { fmt.Print(err) }

		fmt.Println("check data encrypted")
		fmt.Printf("data: %d(%d)\n", dst, len(dst))
		fmt.Printf("iv: %d\n", iv)
		fmt.Println("----------------------------------------")

		err = c.Init(iv, ss.Decrypt); if err != nil { fmt.Print(err) }

		src = dst
		dst = make([]byte, 2+c.GetCryptor(ss.Decrypt).(cipher.AEAD).Overhead()+len(src))

		err = c.Decrypt(dst, src); if err != nil { fmt.Print(err) }

		fmt.Println("check data decrypted")
		fmt.Printf("data: %s\n", dst)
		fmt.Printf("iv: %d\n", iv)
		fmt.Println("----------------------------------------")
	} else {
		///////////////////////////////////////
		fmt.Printf("Testing stream %s\n", info.method)
		fmt.Println("----------------------------------------")

		dst := make([]byte, len(src))
		iv, err := c.NewIV(); if err != nil { fmt.Print(err) }

		err = c.Init(iv, ss.Encrypt); if err != nil { fmt.Print(err) }
		err = c.Encrypt(dst, src); if err != nil { fmt.Print(err) }
		fmt.Println("check data encrypted")
		fmt.Printf("data: %d\n", dst)

		err = c.Init(iv, ss.Decrypt); if err != nil { fmt.Print(err) }
		err = c.Decrypt(dst, dst); if err != nil { fmt.Print(err) }

		fmt.Println("----------------------------------------")
		fmt.Println("check data decrypted")
		fmt.Printf("data: %s\n", dst)
		fmt.Println("----------------------------------------")
		///////////////////////////////////////
	}
}

func main() {
	src := []byte("hello")
	for _, item := range cipherMethod {
		check_cipher(item, src)
	}
	//////////////////////////////////////////////////////////////
	///////////////////////////////////////
	fmt.Println("Testing stream")
	fmt.Println("----------------------------------------")
	c, err := ss.NewCipher("aes-128-cfb", "123456"); if err != nil { fmt.Print(err) }
	dst := make([]byte, len(src))
	iv, err := c.NewIV(); if err != nil { fmt.Print(err) }
	err = c.Init(iv, ss.Encrypt); if err != nil { fmt.Print(err) }
	err = c.Encrypt(dst, src); if err != nil { fmt.Print(err) }
	fmt.Println("check data encrypted")
	fmt.Printf("data: %d\n", dst)

	err = c.Init(iv, ss.Decrypt); if err != nil { fmt.Print(err) }
	err = c.Decrypt(dst, dst); if err != nil { fmt.Print(err) }

	fmt.Println("----------------------------------------")
	fmt.Println("check data decrypted")
	fmt.Printf("data: %s\n", dst)
	fmt.Println("----------------------------------------")
	///////////////////////////////////////
	fmt.Println("----------------------------------------")
	fmt.Println("Testing aead")
	fmt.Println("----------------------------------------")
	c, err = ss.NewCipher("chacha20-ietf-poly1305", "123456"); if err != nil { fmt.Print(err) }

	iv, err = c.NewIV(); if err != nil { fmt.Print(err) }
	err = c.Init(iv, ss.Encrypt); if err != nil { fmt.Print(err) }

	dst = make([]byte, c.GetCryptor(ss.Encrypt).(cipher.AEAD).Overhead()+len(src))
	err = c.Encrypt(dst, src); if err != nil { fmt.Print(err) }

	fmt.Println("check data encrypted")
	fmt.Printf("data: %d(%d)\n", dst, len(dst))
	fmt.Printf("iv: %d\n", iv)
	fmt.Println("----------------------------------------")

	err = c.Init(iv, ss.Decrypt); if err != nil { fmt.Print(err) }

	src = dst
	dst = make([]byte, 2+c.GetCryptor(ss.Decrypt).(cipher.AEAD).Overhead()+len(src))
	err = c.Decrypt(dst, src); if err != nil { fmt.Print(err) }

	fmt.Println("check data decrypted")
	fmt.Printf("data: %s\n", dst)
	fmt.Printf("iv: %d\n", iv)
	fmt.Println("----------------------------------------")
}