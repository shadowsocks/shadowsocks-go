package encrypt

import (
	"crypto/cipher"
	"crypto/md5"
	"net"
	"strings"
)

type Cipher interface {
	KeySize() int
	Copy() Cipher

	NewConnectionEncryptor(conn net.Conn) net.Conn
	EncryptorInited() bool
	DecryptorInited() bool
	Encrypt(src, dest []byte) (int, error)
	Decrypt(src, dest []byte) (int, error)

	// add two total func Pack and Unpack for interface suit for both stream and packet
	NewPacketEncryptor(conn net.PacketConn) net.PacketConn
	Pack(src, dest []byte) (int, error)
	Unpack(src, dest []byte) (int, error)
}

// two cipher interface for distingushing the AEAD and Stream cipher
type AEADCipher interface {
	Cipher
	SaltSize() int
	InitEncryptor(salt []byte) (cipher.AEAD, error)
	InitDecryptor(salt []byte) (cipher.AEAD, error)
}

type StreamCipher interface {
	Cipher
	IVSize() int
	InitEncryptor(iv []byte) (cipher.Stream, error)
	InitDecryptor(iv []byte) (cipher.Stream, error)
}

func PickCipher(method, passwd string) Cipher {
	method = strings.ToLower(method)

	// return aead cipher
	if strings.Contains(method, "aead") {
		var genator *aeadGenerator
		switch method {
		case "chacha20-ietf-poly1305":
			genator = &aeadGenerator{32, 32, newChaCha20IETFEncoder}
		case "aes-256-gcm":
			genator = &aeadGenerator{32, 32, newAESGCMEncoder}
		case "aes-192-gcm":
			genator = &aeadGenerator{24, 24, newAESGCMEncoder}
		case "aes-128-gcm":
			genator = &aeadGenerator{16, 16, newAESGCMEncoder}
		default:
			//TODO error no method
		}

		// per handle the passwd
		prePsk := kdf(passwd, genator.keyLen)

		cipher := aeadCipher{
			psk:     make([]byte, genator.keyLen, genator.keyLen),
			nonce:   make([]byte, NonceSize, NonceSize),
			salt:    make([]byte, genator.salt, genator.salt),
			buffer:  bufferPool.Get().([]byte),
			genator: genator.newAEAD,
		}
		return &cipher
	}

	return nil
}

// buffer pool for cipher buffer reuse
//var bufferPool = sync.Pool{
//	New: func() interface{} {
//		return make([]byte, BufferSize, BufferSize)
//	},
//}

// key-derivation function for key pre-handle
func kdf(password string, keyLen int) []byte {
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
