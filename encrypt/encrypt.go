package encrypt

import (
	"errors"
	"strings"
)

// Error type in encrypt packet
var (
	ErrCipherUninitialized = errors.New("cipher needs initialize before encrypt/decrypt")
	ErrUnsupportedMethod   = errors.New("unsupported encryption method")
	ErrCapcityNotEnough    = errors.New("slice capcity is not enough")
	ErrAgain               = errors.New("require more data")
	ErrEmptyPassword       = errors.New("empty password")
)

// Cipher is the encdyptor and decryptor
type Cipher interface {
	KeySize() int                          // KeySize return the key length which cipher request
	InitBolckSize() int                    // InitBolckSize give out the size of init block for cipher init, also called as aslt or iv
	Copy() Cipher                          // Copy return the copy of the cipher with given password. Need to inititalze before use
	Encrypt(src, dest []byte) (int, error) // Encrypt data from src to dest, return the bytes after encryption
	Decrypt(src, dest []byte) (int, error) // Decrypt data from src to dest, return the bytes after decryption
	EncryptorInited() bool                 // EncryptorInited return wether encryptor is initalized
	InitEncryptor() ([]byte, error)        // InitEncryptor init the encryptor and return the randomly generated InintBolck
	DecryptorInited() bool                 // DecryptorInited return wether decryptor is initialized
	InitDecryptor(data []byte) error       // InitDecryptor initialize the decryptor with given initBolck
	Pack(src, dest []byte) (int, error)    // Pack will encrypt the src data block to dest and return the bytes encrypted, ONLY USED FOR UDP
	Unpack(src, dest []byte) (int, error)  // Unpack decrypt the src data block to dest, return the bytes decrypted, ONLY USED FOR UDP
}

// PickCipher return the uninitialized cipher with given passwd
func PickCipher(method, passwd string) (Cipher, error) {
	method = strings.ToLower(method)
	if strings.Contains(method, "gcm") || strings.Contains(method, "aead") {
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
