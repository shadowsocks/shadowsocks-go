package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"crypto/rand"
)

func genSalt(salt_len int) ([]byte, error) {
	salt := make([]byte, salt_len)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		ss.Logger.Fields(ss.LogFields{
			"err": err,
		}).Warn("new salt failed")
		return nil, err
	}

	return salt, nil
}

func main() {
	key := make([]byte, chacha20poly1305.KeySize)
	ss.Logger.Fields(ss.LogFields{
		"key": key,
		"key_len": len(key),
	}).Info("check key")
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
	salt, err := genSalt(32)

	ss.Logger.Info(aead)

	var dst []byte
	src := []byte("11")

	//encrypt
	aead.Doe = ss.Encrypt
	aead.SetSalt(salt)
	aead.Init()
	ss.Logger.Fields(ss.LogFields{
		"method": method,
		"password":password,
		"salt": aead.GetSalt(),
		"src":src,
		"dec": aead.Dec,
		"enc": aead.Enc,
		"doe": aead.Doe,
	}).Info("before encrypt")
	aead.Encrypt(dst, src)
	//nonce := make([]byte, aead.Enc.NonceSize())
	//ss.Logger.Fields(ss.LogFields{
	//	"method": method,
	//	"password":password,
	//	"nonce":nonce,
	//	"src":src,
	//	"dec": aead.Dec,
	//	"enc": aead.Enc,
	//	"doe": aead.Doe,
	//}).Info("cipher info")
	//src = aead.Enc.Seal(nil, nonce, src, nil)

	ss.Logger.Fields(ss.LogFields{
		"data": string(aead.Payload),
	}).Info("check data pack")

	// decrypt
	aead_copy.Doe = ss.Decrypt
	aead_copy.SetSalt(salt)
	aead_copy.Init()
	ss.Logger.Fields(ss.LogFields{
		"method": method,
		"password":password,
		"salt": aead_copy.GetSalt(),
		"src":aead.Payload,
		"dec": aead_copy.Dec,
		"enc": aead_copy.Enc,
		"doe": aead_copy.Doe,
	}).Info("before decrypt")
	aead_copy.Decrypt(dst, aead.Payload)
	//nonce = make([]byte, aead.Dec.NonceSize())
	//data, err := aead.Dec.Open(nil, nonce, src, nil)
	//if err != nil {
	//	ss.Logger.Fields(ss.LogFields{
	//		"nonce":nonce,
	//		"src":src,
	//		"err": err,
	//	}).Fatal("new cipher error")
	//}

	ss.Logger.Fields(ss.LogFields{
		"data": string(aead_copy.Payload),
	}).Info("check data unpack")
}