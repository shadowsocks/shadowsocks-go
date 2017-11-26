package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"bytes"
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
	aead := c.(*ss.CipherAead)
	aead_copy := aead.Copy()
	//////////////////////////////////
	buffer := bytes.NewBuffer(nil)

	src_len := 26
	src := make([]byte, src_len)
	for i := 97; i < src_len + 97; i++ {
		src[i-97] = byte(i)
	}

	//////////////////////////////////
	encrypt := new(ss.PacketAead)
	encrypt.Cipher = aead
	encrypt.Init(buffer, src, ss.Encrypt)
	encrypt.Pack()
	/////////////////////////////////
	src = buffer.Bytes()
	_, src = ss.RemoveEOF(src)
	//src = src[aead.IVSize():] // need to cut iv from header, cause we use buffer to test not real socket connection
	ss.Logger.Fields(ss.LogFields{
		"src": src,
		"iv": encrypt.Cipher.IV(),
		//"src_str": string(src),
		//"data": buffer.Bytes(),
	}).Info("check encrypted data")
	/////////////////////////////////
	decrypt := new(ss.PacketAead)
	decrypt.Cipher = aead_copy
	decrypt.Init(buffer, src, ss.Decrypt)
	decrypt.UnPack()
	/////////////////////////////////
	src = buffer.Bytes()
	_, src = ss.RemoveEOF(src)
	//src = src[aead.IVSize():] // need to cut iv from header, cause we use buffer to test not real socket connection
	ss.Logger.Fields(ss.LogFields{
		"src_str": string(src),
		"src": src,
		"iv": decrypt.Cipher.IV(),
		//"src_str": string(src),
		//"data": buffer.Bytes(),
	}).Info("check decrypted data")
	/////////////////////////////////
}