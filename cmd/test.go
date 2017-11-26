package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
)

const payloadSizeMask = 0x3FFF // 16*1024 - 1

//func genIV(iv_len int) ([]byte, error) {
//	iv := make([]byte, iv_len)
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		ss.Logger.Fields(ss.LogFields{
//			"err": err,
//		}).Warn("new iv failed")
//		return nil, err
//	}
//
//	return iv, nil
//}

func main() {
	//key := make([]byte, chacha20poly1305.KeySize)
	//ss.Logger.Fields(ss.LogFields{
	//	"key": key,
	//	"key_len": len(key),
	//}).Info("check key")
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
	//iv, err := genIV(aead.IVSize())

	ss.Logger.Info(aead)

	//var dst []byte
	src_len := 26
	src := make([]byte, src_len)
	for i := 97; i < src_len + 97; i++ {
		src[i-97] = byte(i)
	}

	//encrypt
	aead.Init(nil, ss.Encrypt)
	iv := aead.IV()
	dst := make([]byte, 2+aead.Enc.Overhead()+payloadSizeMask+aead.Enc.Overhead())
	ss.Logger.Fields(ss.LogFields{
		"method": method,
		"password":password,
		"iv": aead.IV(),
		"src":src,
		"src_str":string(src),
		"dec": aead.Dec,
		"enc": aead.Enc,
		//"doe": aead.Doe,
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

	_, dst = ss.RemoveEOF(dst)
	ss.Logger.Fields(ss.LogFields{
		"data": dst,
	}).Info("check data pack")

	// decrypt
	//aead_copy.Doe = ss.Decrypt
	//aead_copy.SetSalt(salt)
	aead_copy.Init(iv, ss.Decrypt)
	src = dst
	dst = make([]byte, payloadSizeMask+aead_copy.Dec.Overhead())
	ss.Logger.Fields(ss.LogFields{
		"method": method,
		"password":password,
		"iv": aead_copy.IV(),
		"src":src,
		"dec": aead_copy.Dec,
		"enc": aead_copy.Enc,
		//"doe": aead_copy.Doe,
	}).Info("before decrypt")
	aead_copy.Decrypt(dst, src)
	//nonce = make([]byte, aead.Dec.NonceSize())
	//data, err := aead.Dec.Open(nil, nonce, src, nil)
	//if err != nil {
	//	ss.Logger.Fields(ss.LogFields{
	//		"nonce":nonce,
	//		"src":src,
	//		"err": err,
	//	}).Fatal("new cipher error")
	//}

	_, dst = ss.RemoveEOF(dst)

	ss.Logger.Fields(ss.LogFields{
		"dst": dst,
		"data": string(dst),
	}).Info("check data unpack")
}