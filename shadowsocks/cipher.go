package shadowsocks

import (
	"errors"
	"io"
)

type DecOrEnc int
type CipherType int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type cipherInfo struct {
	method string
	KeySize    int
	IVSize     int
	makeCipher func(password string, info *cipherInfo) (Cipher, error) // make general cipher
	makeKey func(password string, keySize int) (key []byte) // make key by password
	makeCryptor func(key []byte, iv []byte, decrypt DecOrEnc) (interface{}, error) // make stream for stream cipher with key or make aead for aead cipher with subkey which is made by key and iv
}

type Cryptor interface {
	Init(c Cipher) Cryptor
	initEncrypt(r io.Reader, w io.Writer) (err error)
	initDecrypt(r io.Reader, w io.Writer) (err error)
	Pack(b []byte) (n int, err error)
	UnPack(b []byte) (n int, err error)
	WriteTo() (n int, err error)
	Read(b []byte) (n int, err error)
	GetBuffer() (buffer *LeakyBufType, err error)
}

type Cipher interface {
	isStream() bool
	Init(iv []byte, decrypt DecOrEnc) (err error)
	SetKey(key []byte)
	SetInfo(info *cipherInfo)
	SetCryptor(cryptor interface{}, decrypt DecOrEnc)
	GetCryptor(decrypt DecOrEnc) interface{}
	NewIV() (iv []byte, err error)
	KeySize() int
	IVSize() int
	Encrypt(dst, src []byte) error
	Decrypt(dst, src []byte) error
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {"aes-128-cfb", 16, 16, newStream, genStreamKey, newAESCFBStream},
	"aes-192-cfb":   {"aes-192-cfb", 24, 16, newStream, genStreamKey, newAESCFBStream},
	"aes-256-cfb":   {"aes-256-cfb", 32, 16, newStream, genStreamKey, newAESCFBStream},
	"aes-128-ctr":   {"aes-128-ctr", 16, 16, newStream, genStreamKey, newAESCTRStream},
	"aes-192-ctr":   {"aes-192-ctr", 24, 16, newStream, genStreamKey, newAESCTRStream},
	"aes-256-ctr":   {"aes-256-ctr", 32, 16, newStream, genStreamKey, newAESCTRStream},
	"des-cfb":       {"des-cfb", 8, 8, newStream, genStreamKey, newDESStream},
	"bf-cfb":        {"bf-cfb", 16, 8, newStream, genStreamKey, newBlowFishStream},
	"cast5-cfb":     {"cast5-cfb", 16, 8, newStream, genStreamKey, newCast5Stream},
	"rc4-md5":       {"rc4-md5", 16, 16, newStream, genStreamKey, newRC4MD5Stream},
	"chacha20":      {"chacha20", 32, 8, newStream, genStreamKey, newChaCha20Stream},
	"chacha20-ietf": {"chacha20-ietf", 32, 12, newStream, genStreamKey, newChaCha20IETFStream},
	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", 32, 32, newAead, genAeadKey, newChaCha20IETFPoly1305Aead},
	"salsa20":       {"salsa20", 32, 8, newStream, genStreamKey, newSalsa20Stream},
}
////////////////////////////////////////////////////////////////////////////////////////
func CheckCipherMethod(method string) error {
	if method == "" { method = "aes-256-cfb" }
	_, ok := cipherMethod[method]; if !ok { return errors.New("Unsupported encryption method: " + method) }; return nil
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func newCipher(method, password string) (c Cipher, err error) {
	if password == "" { err = errors.New("password is empty"); return }
	mi, ok := cipherMethod[method]
	if !ok { err = errors.New("Unsupported encryption method: " + method); return }
	return mi.makeCipher(password, mi)
}

func NewCryptor(method, password string) (c Cryptor, err error) {
	cipher, err := newCipher(method, password); if err != nil { return }
	if cipher.isStream() { c = new(StreamCryptor).Init(cipher) } else { c = new(AeadCryptor).Init(cipher) }; return
}