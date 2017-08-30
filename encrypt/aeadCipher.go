package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	// NonceSize defined the largest number nonce can reach, once reached, the nonce will warpped
	NonceSize        = 12
	readBufferSize   = 0xFFFFF             // get 4k for buffer size
	hkdfInfoTag      = []byte("ss-subkey") // at present, this tag is defined as ss-subkey
	nullNonce        = make([]byte, NonceSize, NonceSize)
	aeadCipherMethod = map[string]*aeadGenerator{
		"chacha20-ietf-poly1305": {32, 32, newChaCha20IETFEncoder},
		"aes-256-gcm":            {32, 32, newAESGCMEncoder},
		"aes-192-gcm":            {24, 24, newAESGCMEncoder},
		"aes-128-gcm":            {16, 16, newAESGCMEncoder},
	}
)

type aeadGenerator struct {
	keyLen  int
	saltLen int
	newAEAD func(key, salt []byte, keylen int) (cipher.AEAD, error)
}

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
	// reader should input the specific salt to hkdf key
	switch len(salt) {
	case 16, 24, 32:
	default:
		panic("error salt len")
	}
	//FIXME
	n, err := io.ReadFull(rand.Reader, salt)
	if err != nil || n != len(salt) {
		panic("error salt gen")
	}
}

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

type aeadCipher struct {
	psk        []byte
	salt       []byte
	readNonce  []byte
	writeNonce []byte
	readBuffer []byte
	saltSize   int
	keySize    int
	dataLen    int

	enc     cipher.AEAD
	dec     cipher.AEAD
	genator func(key, salt []byte, keylen int) (cipher.AEAD, error)
}

// NewAEADCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewAEADCipher(method, password string) (c Cipher, err error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}

	var genator *aeadGenerator
	genator, ok := aeadCipherMethod[method]
	if !ok {
		return nil, ErrUnsupportedMethod
	}

	cipher := aeadCipher{
		readNonce:  make([]byte, NonceSize, NonceSize),
		writeNonce: make([]byte, NonceSize, NonceSize),
		salt:       make([]byte, genator.saltLen, genator.saltLen),
		psk:        kdf(password, genator.keyLen), // per handle the passwd
		keySize:    genator.keyLen,
		saltSize:   genator.saltLen,
		genator:    genator.newAEAD,
		readBuffer: make([]byte, readBufferSize),
	}

	return &cipher, nil
}

func (c *aeadCipher) KeySize() int          { return c.keySize }
func (c *aeadCipher) InitBolckSize() int    { return c.saltSize }
func (c *aeadCipher) EncryptorInited() bool { return c.enc == nil }
func (c *aeadCipher) DecryptorInited() bool { return c.dec == nil }
func (c *aeadCipher) InitEncryptor() ([]byte, error) {
	if c.salt == nil {
		c.salt = make([]byte, c.saltSize, c.saltSize)
	}
	genSalt(c.salt)

	var err error
	// gen the aead cipher
	c.enc, err = c.genator(c.psk, c.salt, c.keySize)
	return c.salt, err
}

func (c *aeadCipher) InitDecryptor(salt []byte) (err error) {
	c.salt = make([]byte, c.saltSize, c.saltSize)
	copy(c.salt, salt)

	// gen the aead cipher
	c.dec, err = c.genator(c.psk, c.salt, c.keySize)
	return err
}

func (c *aeadCipher) Encrypt(src, dest []byte) (int, error) {
	if c.EncryptorInited() {
		return -1, ErrCipherUninitialized
	}
	msglen := len(src)
	srclen := make([]byte, 2)

	destlen := dest[:2+c.enc.Overhead()]                                              // data length layout
	destdata := dest[2+c.enc.Overhead() : 2+c.enc.Overhead()+msglen+c.enc.Overhead()] // data layout

	// handle the length with bigendian encoding
	srclen[0], srclen[1] = byte(msglen>>8), byte(msglen)

	// encrypt length
	c.enc.Seal(destlen[:0], c.writeNonce, srclen[:2], nil)
	increase(c.writeNonce)

	// encrypt data
	c.enc.Seal(destdata[:0], c.writeNonce, src, nil)
	increase(c.writeNonce)

	// 2 + c.enc.Overhead() + msglen + c.enc.Overhead()
	// [salt(if exist)] + [encrypted datalen] + [encrypted data]
	return 2 + c.enc.Overhead() + msglen + c.enc.Overhead(), nil
}

func (c *aeadCipher) Decrypt(src, dest []byte) (int, error) {
	// if any error returned, dest buffer data should be undifined
	// but the src will be consume once you call the Decrypt if the ErrAgain returned
	if c.DecryptorInited() {
		return -1, ErrCipherUninitialized
	}

	// XXX FIXME append the last buffer
	if len(c.readBuffer[c.dataLen:]) < len(src) {
		return -1, ErrCapcityNotEnough
	}
	n := copy(c.readBuffer[c.dataLen:], src)
	c.dataLen += n

	// consume the raw data length
	if c.dataLen < 2+c.dec.Overhead() {
		//wait for enough data for length decrypt
		return 2 + c.dec.Overhead() - c.dataLen, ErrAgain
	}

	// read the length and decrypt, handle the message block length
	srcdatalen := c.readBuffer[:2+c.dec.Overhead()]
	msglenbyte := make([]byte, 2)
	_, err := c.dec.Open(msglenbyte[:0], c.readNonce, srcdatalen, nil)
	if err != nil {
		return -1, err
	}
	msglen := int(msglenbyte[0])<<8 + int(msglenbyte[1])

	blockDataLen := c.dataLen - 2 - c.dec.Overhead()
	if blockDataLen < msglen+c.dec.Overhead() {
		// need the comming data for payload decrypt
		return msglen + c.dec.Overhead() - blockDataLen, ErrAgain
	}

	// XXX if needed
	if cap(dest) < msglen+c.dec.NonceSize() {
		return -1, ErrCapcityNotEnough
	}
	increase(c.readNonce)

	// read the data and decrypt
	srcdata := c.readBuffer[2+c.dec.Overhead() : 2+c.dec.Overhead()+msglen+c.dec.Overhead()]
	_, err = c.dec.Open(dest[:0], c.readNonce, srcdata, nil)
	if err != nil {
		return -1, err
	}
	increase(c.readNonce)

	// left the reamin data in the buffer
	copy(c.readBuffer, c.readBuffer[2+c.dec.Overhead()+msglen+c.dec.Overhead():c.dataLen])
	c.dataLen -= 2 + c.dec.Overhead() + msglen + c.dec.Overhead()

	// dataStart + 2 + c.enc.Overhead() + msglen + c.enc.Overhead()
	// [salt(if exist)] + [encrypted datalen] + [encrypted data]
	if c.dataLen > 0 {
		for {
			comming := c.decryptConsumer(dest[msglen:])
			if comming == 0 {
				// tried but notenough data for dec
				break
			}
			msglen += comming
		}
	}
	return msglen, nil
}

func (c *aeadCipher) decryptConsumer(dest []byte) int {
	// consume the cached data
	if c.dataLen < 2+c.dec.Overhead() {
		//wait for enough data for length decrypt
		return 0
	}

	// read the length and decrypt, handle the message block length
	srcdatalen := c.readBuffer[:2+c.dec.Overhead()]
	msglenbyte := make([]byte, 2)
	_, err := c.dec.Open(msglenbyte[:0], c.readNonce, srcdatalen, nil)
	if err != nil {
		return 0
		//panic(err)
	}
	msglen := int(msglenbyte[0])<<8 + int(msglenbyte[1])

	blockDataLen := c.dataLen - 2 - c.dec.Overhead()
	if blockDataLen < msglen+c.dec.Overhead() {
		return 0
	}

	// XXX if needed
	if cap(dest) < msglen+c.dec.NonceSize() {
		return 0
	}
	increase(c.readNonce)

	// read the data and decrypt
	srcdata := c.readBuffer[2+c.dec.Overhead() : 2+c.dec.Overhead()+msglen+c.dec.Overhead()]
	_, err = c.dec.Open(dest[:0], c.readNonce, srcdata, nil)
	if err != nil {
		panic(err)
	}
	increase(c.readNonce)

	// left the reamin data in the buffer
	copy(c.readBuffer, c.readBuffer[2+c.dec.Overhead()+msglen+c.dec.Overhead():c.dataLen])
	c.dataLen -= 2 + c.dec.Overhead() + msglen + c.dec.Overhead()

	// dataStart + 2 + c.enc.Overhead() + msglen + c.enc.Overhead()
	// [salt(if exist)] + [encrypted datalen] + [encrypted data]
	return msglen
}

func (c *aeadCipher) Pack(src, dest []byte) (int, error) {
	// TODO FIXME
	c.InitEncryptor()
	// write the salt
	n := copy(dest[0:], c.salt) // salt lay out if this is the initialization of the encryptor
	if n != c.saltSize {
		return -1, ErrCapcityNotEnough
	}

	destdata := dest[c.saltSize:]

	// encrypt the data
	c.enc.Seal(destdata[:0], nullNonce, src, nil)

	return c.saltSize + c.enc.Overhead() + len(src) + c.enc.Overhead(), nil
}

func (c *aeadCipher) Unpack(src, dest []byte) (int, error) {
	// initialize the decryptor with the salt
	err := c.InitDecryptor(src[:c.saltSize])
	if err != nil {
		return -1, err
	}

	srcdata := src[c.saltSize:]

	if cap(dest) < len(srcdata)+c.dec.NonceSize() {
		return -1, ErrCapcityNotEnough
	}

	_, err = c.dec.Open(dest[:0], nullNonce, srcdata, nil)
	if err != nil {
		return -1, err
	}

	return len(srcdata) - c.dec.Overhead(), nil
}

func (c *aeadCipher) Copy() Cipher {
	cip := *c
	cip.dec = nil
	cip.enc = nil
	cip.readNonce = make([]byte, NonceSize, NonceSize)
	cip.writeNonce = make([]byte, NonceSize, NonceSize)
	cip.readBuffer = make([]byte, readBufferSize)
	cip.dataLen = 0

	return &cip
}

//HKDFSha1 get the key for encyptor
func HKDFSha1(key, salt, dest []byte) {
	keyReader := hkdf.New(sha1.New, key, salt, hkdfInfoTag)
	_, err := io.ReadFull(keyReader, dest)
	if err != nil {
		//XXX panic the error while gen the key
		// n != len(dest)
		panic("error internal: hkdf generate the key error," + err.Error())
	}
}

func newAESGCMEncoder(key, salt []byte, keylen int) (cipher.AEAD, error) {
	destkey := make([]byte, keylen)
	HKDFSha1(key, salt, destkey)

	// genreate aes cipher block
	cipherBlock, err := aes.NewCipher(destkey)
	if err != nil {
		return nil, err
	}

	// gen AEAD cipher with aes cipher
	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	key = destkey
	return aead, nil
}

func newChaCha20IETFEncoder(key, salt []byte, keylen int) (cipher.AEAD, error) {
	destkey := make([]byte, keylen)
	HKDFSha1(key, salt, destkey)

	// genreate chacha20 ietf encryptor
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	key = destkey
	return aead, nil
}
