package encrypt

import (
	"errors"
	"strings"
)

// Error type in encrypt packet
var (
	ErrCipherUninitialized = errors.New("cipher needs initialize before encrypt/decrypt")
	ErrCapcityNotEnough    = errors.New("slice capcity is not enough")
	ErrAgain               = errors.New("require more data")
	ErrEmptyPassword       = errors.New("empty password")
	ErrUnsupportedMethod   = errors.New("unsupported encryption method")

	cipherMethod = map[string]struct{}{
		"aes-128-gcm":            {},
		"aes-192-gcm":            {},
		"aes-256-gcm":            {},
		"chacha20-ietf-poly1305": {},
		"aes-128-cfb":            {},
		"aes-192-cfb":            {},
		"aes-256-cfb":            {},
		"aes-128-ctr":            {},
		"aes-192-ctr":            {},
		"aes-256-ctr":            {},
		"des-cfb":                {},
		"bf-cfb":                 {},
		"cast5-cfb":              {},
		"rc4-md5":                {},
		"chacha20":               {},
		"chacha20-ietf":          {},
		"salsa20":                {},
	}
)

// Cipher is the encdyptor and decryptor
type Cipher interface {
	KeySize() int       // KeySize return the key length which cipher request
	InitBolckSize() int // InitBolckSize give out the size of init block for cipher init, also called as aslt or iv
	Copy() Cipher       // Copy return the copy of the cipher with given password. Need to inititalze before use
	//Close()                                // Close the cipher and release the resource
	Encrypt(src, dest []byte) (int, error) // Encrypt data from src to dest, return the bytes after encryption
	Decrypt(src, dest []byte) (int, error) // Decrypt data from src to dest, return the bytes after decryption
	Pack(src, dest []byte) (int, error)    // Pack will encrypt the src data block to dest and return the bytes encrypted, ONLY USED FOR UDP
	Unpack(src, dest []byte) (int, error)  // Unpack decrypt the src data block to dest, return the bytes decrypted, ONLY USED FOR UDP
	EncryptorInited() bool                 // EncryptorInited return wether encryptor is initalized
	InitEncryptor() ([]byte, error)        // InitEncryptor init the encryptor and return the randomly generated InintBolck
	DecryptorInited() bool                 // DecryptorInited return wether decryptor is initialized
	InitDecryptor(data []byte) error       // InitDecryptor initialize the decryptor with given initBolck
}

// PickCipher return the uninitialized cipher with given passwd
func PickCipher(method, passwd string) (Cipher, error) {
	method = strings.ToLower(method)
	if strings.Contains(method, "gcm") || strings.Contains(method, "poly1305") {
		cip, err := NewAEADCipher(method, passwd)
		if err != nil {
			return nil, err
		}
		return cip, nil
	}
	cip, err := NewStreamCipher(method, passwd)
	if err != nil {
		return nil, err
	}
	return cip, nil
}

// CheckCipherMethod checks if the cipher method is supported
func CheckCipherMethod(method string) error {
	if _, ok := cipherMethod[method]; !ok {
		return ErrUnsupportedMethod
	}
	return nil
}
