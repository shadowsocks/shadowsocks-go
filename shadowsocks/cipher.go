package shadowsocks

import (
	"errors"
	"crypto/md5"
)

type DecOrEnc int
type CipherType int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type cipherInfo struct {
	method      string
	KeySize     int
	IVSize      int
	makeCipher  func(password string, info *cipherInfo) (Cipher, error)            // make general cipher
	makeKey     func(password string, keySize int) (key []byte)                    // make key by password
	makeCryptor func(key []byte, iv []byte, doe DecOrEnc) (CryptorCipher, error) // make stream for stream cipher with key or make aead for aead cipher with subkey which is made by key and iv
}

type CryptorCipher interface {
	init(cryptor interface{})
	Encrypt(dst, src []byte) (err error)
	Decrypt(dst, src []byte) (err error)
}

type Cryptor interface {
	init(c Cipher) Cryptor
	initCryptor(doe DecOrEnc) interface{}
	GetBuffer() ([]byte)
}

type Cipher interface {
	isStream() bool
	Init(iv []byte, doe DecOrEnc) (cryptor CryptorCipher, err error)
	SetKey(key []byte)
	SetInfo(info *cipherInfo)
	NewIV() (iv []byte, err error)
	KeySize() int
	IVSize() int
	//Encrypt(dst, src []byte) error
	//Decrypt(dst, src []byte) error
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":            {"aes-128-cfb", 16, 16, newStream, genKey, newAESCFBStream},
	"aes-192-cfb":            {"aes-192-cfb", 24, 16, newStream, genKey, newAESCFBStream},
	"aes-256-cfb":            {"aes-256-cfb", 32, 16, newStream, genKey, newAESCFBStream},
	"aes-128-ctr":            {"aes-128-ctr", 16, 16, newStream, genKey, newAESCTRStream},
	"aes-192-ctr":            {"aes-192-ctr", 24, 16, newStream, genKey, newAESCTRStream},
	"aes-256-ctr":            {"aes-256-ctr", 32, 16, newStream, genKey, newAESCTRStream},
	"des-cfb":                {"des-cfb", 8, 8, newStream, genKey, newDESStream},
	"bf-cfb":                 {"bf-cfb", 16, 8, newStream, genKey, newBlowFishStream},
	"cast5-cfb":              {"cast5-cfb", 16, 8, newStream, genKey, newCast5Stream},
	"rc4-md5":                {"rc4-md5", 16, 16, newStream, genKey, newRC4MD5Stream},
	"chacha20":               {"chacha20", 32, 8, newStream, genKey, newChaCha20Stream},
	"chacha20-ietf":          {"chacha20-ietf", 32, 12, newStream, genKey, newChaCha20IETFStream},
	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", 32, 32, newAead, genKey, newChaCha20IETFPoly1305Aead},
	"salsa20":                {"salsa20", 32, 8, newStream, genKey, newSalsa20Stream},
	"aes-256-gcm":                {"aes-256-gcm", 32, 12, newAead, genKey, newAesGCMAead},
	"aes-192-gcm":                {"aes-192-gcm", 24, 12, newAead, genKey, newAesGCMAead},
	"aes-128-gcm":                {"aes-128-gcm", 16, 12, newAead, genKey, newAesGCMAead},
}
////////////////////////////////////////////////////////////////////////////////////////
func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}

	if _, ok := cipherMethod[method]; !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c Cipher, err error) {
	if password == "" {
		err = errors.New("password is empty")
		return
	}
	mi, ok := cipherMethod[method]
	if !ok {
		err = errors.New("Unsupported encryption method: " + method)
		return
	}
	return mi.makeCipher(password, mi)
}

// key-derivation function from original Shadowsocks
func genKey(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
