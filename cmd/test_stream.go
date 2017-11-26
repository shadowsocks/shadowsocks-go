package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"bytes"
)

func main() {
	method := "chacha20-ietf"
	password := "123456"
	c, err := ss.NewCipher(method, password)
	if err != nil {
		ss.Logger.Fields(ss.LogFields{
			"method": method,
			"password":password,
			"err": err,
		}).Fatal("new cipher error")
	}
	stream := c.(*ss.CipherStream)
	stream_copy := stream.Copy()
	//////////////////////////////////
	buffer := bytes.NewBuffer(nil)

	src_len := 26
	src := make([]byte, src_len)
	for i := 97; i < src_len + 97; i++ {
		src[i-97] = byte(i)
	}

	//////////////////////////////////
	encrypt := new(ss.PacketStream)
	encrypt.Cipher = stream
	encrypt.Init(buffer, src, ss.Encrypt)
	encrypt.Pack()
	/////////////////////////////////
	ss.Logger.Fields(ss.LogFields{
		"src": src,
		"src_str": string(src),
		"data": buffer.Bytes(),
	}).Info("check encrypted data")
	/////////////////////////////////
	decrypt := new(ss.PacketStream)
	decrypt.Cipher = stream_copy
	decrypt.Init(buffer, src, ss.Decrypt)
	decrypt.UnPack()
}