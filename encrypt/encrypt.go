package encrypt

import (
	"errors"
	"strings"
)

var (
	ErrCapcityNotEnough  = errors.New("error slice capcity is not enough")
	ErrUnsupportedMethod = errors.New("unsupported encryption method")
	ErrAgain             = errors.New("require more data")
	ErrEmptyPassword     = errors.New("empty password")
)

type Cipher interface {
	KeySize() int
	Copy() Cipher

	EncryptorInited() bool
	DecryptorInited() bool
	Encrypt(src, dest []byte) (int, error)
	Decrypt(src, dest []byte) (int, error)

	// add two total func Pack and Unpack for interface suit for both stream and packet
	Pack(src, dest []byte) (int, error)
	Unpack(src, dest []byte) (int, error)
}

// two cipher interface for distingushing the AEAD and Stream cipher
type AEADCipher interface {
	Cipher
	SaltSize() int
	InitEncryptor() ([]byte, error)
	InitDecryptor(salt []byte) error
}

type StreamCipher interface {
	Cipher
	IVSize() int
	InitEncryptor() ([]byte, error)
	InitDecryptor(iv []byte) error
}

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
