package encrypt

import (
	"errors"
	"strings"
)

var (
	ErrCipherUninitialized = errors.New("cipher needs initialize before encrypt/decrypt")
	ErrCapcityNotEnough    = errors.New("error slice capcity is not enough")
	ErrUnsupportedMethod   = errors.New("unsupported encryption method")
	ErrAgain               = errors.New("require more data")
	ErrEmptyPassword       = errors.New("empty password")
)

type Cipher interface {
	KeySize() int
	InitBolckSize() int // iv or salt size is depend on the cipher type
	Copy() Cipher

	EncryptorInited() bool
	Encrypt(src, dest []byte) (int, error)
	InitEncryptor() ([]byte, error)

	DecryptorInited() bool
	Decrypt(src, dest []byte) (int, error)
	InitDecryptor(data []byte) error

	// add two total func Pack and Unpack for interface suit for both stream and packet
	Pack(src, dest []byte) (int, error)
	Unpack(src, dest []byte) (int, error)
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
