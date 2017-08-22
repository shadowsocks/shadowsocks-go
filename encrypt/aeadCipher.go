package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"net"

	"github.com/lixin9311/shadowsocks-go/shadowsocks"

	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfoTag = []byte("ss-subkey")
	nonceSize   = 12
	nullNonce   = make([]byte, nonceSize, nonceSize)
)

// increase uesd for nonce increacement, will warpped when reach the maximum of length byte can reach
func increase(src []byte) {
	for i := range src {
		src[i]++
		if src[i] != 0 {
			return
		}
	}
}

// generate the salt randomly fror user
func genSalt(salt []byte) {
	// if salt is NULL, then gen the salt randomly
	// by default, salt is random generated for each invocation by writer
	// reader should input the specific salt incase of the hkdf key
	switch len(salt) {
	case 16, 24, 32:
	default:
		panic("error salt len")
	}

	n, err := io.ReadFull(rand.Reader, salt)
	if err != nil || n != len(salt) {
		panic("error salt gen")
	}
}

type aeadCipher struct {
	psk        []byte
	salt       []byte
	readNonce  []byte
	writeNonce []byte
	readBuffer []byte
	saltSize   int
	dataLen    int

	enc     cipher.AEAD
	dec     cipher.AEAD
	genator func(key, salt []byte, doe DecOrEnc) (cipher.AEAD, error)
}

func (c *aeadCipher) KeySize() int          { return len(c.psk) }
func (c *aeadCipher) SaltSize() int         { return c.saltSize }
func (c *aeadCipher) EncryptorInited() bool { return c.enc == nil }
func (c *aeadCipher) InitEncryptor() ([]byte, error) {
	if c.salt == nil {
		c.salt = make([]byte, c.SaltSize(), c.SaltSize())
		genSalt(c.salt)
	}

	// init the write nonce
	c.writeNonce = make([]byte, nonceSize, nonceSize)

	// gen the aead cipher
	c.enc, err = c.genator(c.psk, c.salt, Encrypt)

	return c.salt, err
}

func (c *aeadCipher) DecryptorInited() bool { return c.dec == nil }
func (c *aeadCipher) InitDecryptor(salt []byte) error {
	if c.salt == nil {
		c.salt = make([]byte, c.saltSize, c.saltSize)
		n := copy(c.salt, salt)
		if n != c.saltSize {
			panic("TODO")
		}
	}

	// init the read nonce
	c.readNonce = make([]byte, 12)

	// gen the aead cipher
	c.dec, err = c.genator(c.psk, c.salt, Decrypt)
	return err
}

func (c *aeadCipher) Encrypt(src, dest []byte) error {
	if c.EncryptorInited() {
		c.InitEncryptor()
		// write the salt
		n := copy(dest, c.salt) // salt lay out if this is the initialization of the encryptor
		if n != c.saltSize {
			panic("error dest len")
		}
	}

	msglen := len(src)
	srclen := make([]byte, 2)
	destlen := dest[c.SaltSize() : 2+c.enc.Overhead()+msglen+c.enc.Overhead()] // data length layout
	destdata := dest[2+c.enc.Overhead():]                                      // data layout

	// handle the length with bigendian encoding
	srclen[0], srclen[1] = byte(msglen>>8), byte(msglen)

	// encrypt length
	c.enc.Seal(destlen[:0], c.writeNonce, srclen[:2], nil)
	increase(c.writeNonce)

	// encrypt data
	c.enc.Seal(destdata[:0], c.writeNonce, src, nil)
	increase(c.writeNonce)

	return nil
}

func (c *aeadCipher) Decrypt(src, dest []byte) error {
	if c.DecryptorInited() {
		// FIXME BUG TODO XXX this is uninitialized
		n = copy(c.readBuffer[c.dataLen:], src)
		if n != len(src) {
			// XXX fatal error!!!
		}
		c.dataLen += len(src)

		if c.dataLen < c.saltSize {
			// if salt is not complete, put salt partation in lastReadBuffer and wait for next part
			// FIXME return error ? or return nothing and nothing wrong
			return nil, nil
		}

		// initialize the decryptor with the salt
		err := c.InitDecryptor(c.readBuffer[:c.saltSize])
		if err != nil {
			panic(err)
		}
		n := copy(c.readBuffer[0:], c.readBuffer[saltSize:])
		c.dataLen -= c.saltSize
		goto afterInit
	}

	// append the last buffer
	n = copy(c.readBuffer[c.dataLen:], src)
	c.dataLen += n
	if n != len(src) {
		// XXX
		panic()
	}

afterInit:
	// consume the raw data length
	if c.dataLen < 2+c.dec.Overhead() {
		//wait for enough data for length dec
		// XXX
		return nil
	}

	// handle the message block length
	srcdatalen := c.readBuffer[:2+c.dec.Overhead()]
	msglenbyte := make([]byte, 2)
	n, err = aead.Open(msglenbyte[:0], readNonce, srcdatalen, nil)
	if err != nil {
		return nil, err
	}
	if n != 2 {
		// XXX fatal
		panic("error length 2")
	}
	msglen := int(msglenbyte[0])<<8 + int(msglenbyte[1])

	blockDataLen := c.dataLen - 2 - c.dec.Overhead()
	if blockDataLen < msglen+c.dec.Overhead() {
		// need the comming data for decrypt
		return
	}

	if cap(dest) < msglen+c.dec.NonceSize() {
		panic("error in dest dec")
	}

	// cool! data len is enough, increas the read nonce first time cause the data is consumed
	increase(c.readNonce)

	// read the length and decrypted
	// read the data and decrypt

	//dest := make([]byte, msglen, msglen)
	srcdata = c.readBuffer[2+c.dec.Overhead() : 2+c.dec.Overhead()+msglen+c.dec.Overhead()]
	n, err = aead.Open(dest[:0], readNonce, srcdata, nil)
	if err != nil {
		return nil, err
	}
	if n != msglen {
		panic("error msg len")
	}
	increase(readNonce)

	// left the reamin data in the buffer
	n = copy(c.readBuffer[0:], c.readBuffer[2+c.dec.Overhead()+msglen+c.dec.Overhead():])
	c.dataLen = n

	return dest, nil
}

func (c *aeadCipher) Pack(src, dest []byte) error {
	c.InitEncryptor()
	// write the salt
	n := copy(dest[0:], c.salt) // salt lay out if this is the initialization of the encryptor
	if n != c.saltSize {
		panic("error dest len")
	}

	destdata := dest[c.saltSize:]

	// encrypt the data
	aead.Seal(destdata[:0], nullNonce, src, nil)

	return nil
}

func (c *aeadCipher) Unpack(src, dest []byte) error {
	// initialize the decryptor with the salt
	err := c.InitDecryptor(src[:c.saltSize])
	if err != nil {
		panic(err)
	}

	srcdata := src[c.saltSize:]

	if cap(dest) < len(srcdata)+c.dec.NonceSize() {
		// XXX
		panic("error cap too small")
	}

	_, err = aead.Open(dest[:0], nullNonce, srcdata, nil)
	if err != nil {
		panic(err)
	}

	return nil
}

func (c *aeadCipher) NewConnectionEncryptor(conn net.Conn) net.Conn {
	return shadowsocks.SecureConn
}
func (c *aeadCipher) NewPacketEncryptor(conn net.PacketConn) net.PacketConn {
	return shadowsocks.SecurePacketConn
}

func (c *aeadCipher) Copy() AEADCipher {
	return &aeadCipher{
		psk:     c.psk,
		genator: c.genator,
	}
}

//HKDFSha1 get the key for encyptor
func HKDFSha1(key, dest []byte) {
	keyReader := hkdf.New(sha1.New, key, salt, hkdfInfoTag)
	n, err := io.ReadFull(keyReader, dest)
	if err != nil || n != len(dest) {
		//XXX panic the error while gen the key
		panic("error internal: hkdf generate the key error," + err.Error())
	}
}

func newaesAEAD(key, salt []byte) (cipher.AEAD, error) {
	// genreate aes cipher block
	cipherBlock, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}

	// gen AEAD cipher with aes cipher
	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	return aead, nil
}
