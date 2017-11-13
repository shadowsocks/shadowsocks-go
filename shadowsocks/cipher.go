package shadowsocks

import (
	"errors"
	"crypto/cipher"
	"reflect"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type cipherInfo struct {
	method string
	ctype string
	keyLen    int
	ivLen     int
	initCipher func(key, iv []byte, doe DecOrEnc) (interface{}, error)
}

type Cipher struct {
	enc  interface{}
	dec  interface{}
	key  []byte
	info *cipherInfo
	iv   []byte
	iv_len int
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":   {"aes-128-cfb", "stream",16, 16, newAESCFBStream},
	"aes-192-cfb":   {"aes-192-cfb", "stream",24, 16, newAESCFBStream},
	"aes-256-cfb":   {"aes-256-cfb", "stream",32, 16, newAESCFBStream},
	"aes-128-ctr":   {"aes-128-ctr", "stream",16, 16, newAESCTRStream},
	"aes-192-ctr":   {"aes-192-ctr", "stream",24, 16, newAESCTRStream},
	"aes-256-ctr":   {"aes-256-ctr", "stream",32, 16, newAESCTRStream},
	"des-cfb":       {"des-cfb", "stream",8, 8, newDESStream},
	"bf-cfb":        {"bf-cfb", "stream",16, 8, newBlowFishStream},
	"cast5-cfb":     {"cast5-cfb", "stream",16, 8, newCast5Stream},
	"rc4-md5":       {"rc4-md5", "stream",16, 16, newRC4MD5Stream},
	"chacha20":      {"chacha20", "stream",32, 8, newChaCha20Stream},
	"chacha20-ietf": {"chacha20-ietf", "stream",32, 12, newChaCha20IETFStream},
	"chacha20-ietf-poly1305": {"chacha20-ietf-poly1305", "aead",32, 12, newChaCha20IETFPoly1305Aead},
	"salsa20":       {"salsa20", "stream",32, 8, newSalsa20Stream},
}
////////////////////////////////////////////////////////////////////////////////////////
func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherMethod[method]
	if !ok {
		Logger.Fields(LogFields{"method": method}).Error("Unsupported encryption method")
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c interface{}, err error) {
	if password == "" {
		Logger.Fields(LogFields{"password": password}).Error("empty password")
		return nil, errEmptyPassword
	}
	mi, ok := cipherMethod[method]
	if !ok {
		Logger.Fields(LogFields{"method": method}).Error("Unsupported encryption method")
		return nil, errors.New("Unsupported encryption method: " + method)
	}
	Logger.Fields(LogFields{
		"method": method,
		"mi": mi,
		"ok": ok,
	}).Info("Checking cipher info")

	if mi.ctype == "stream" {
		c = newStream(password, mi)
	} else if mi.ctype == "aead" {

	}

	return c, nil
}

// Copy creates a new cipher at it's initial state.
func CopyCipher(c interface{}) interface{} {

	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initizliation time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// maganitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	Logger.Fields(LogFields{
		"type": reflect.TypeOf(c).String(),
	}).Info("Checking cipher type")
	if reflect.TypeOf(c).String() == "*shadowsocks.CipherStream" {
		c := c.(*CipherStream)
		nc := *c
		nc.enc = nil
		nc.dec = nil
		return &nc
	}

	return nil
}
///////////////////////////////////////////////////////////////////////////////////
// Initializes the cipher
func (c *Cipher) init(doe DecOrEnc) (err error) {
	if (doe == Encrypt && c.enc != nil) || (doe == Decrypt && c.dec != nil) {
		if doe == Encrypt {
			c.iv_len = 0
		}
		return
	}
	cipherObj, err := c.info.initCipher(c.key, c.iv, doe)

	if doe == Encrypt {
		c.enc = cipherObj
		c.iv_len = len(c.iv)
	} else if doe == Decrypt {
		c.dec = cipherObj
	}
	return
}

func (c *Cipher) encrypt(dst, src []byte) {
	if c.info.ctype == "stream" {
		enc := (c.enc).(cipher.Stream)
		enc.XORKeyStream(dst, src)
	} else if c.info.ctype == "aead" {
		//enc := (c.enc).(cipher.AEAD)
		//enc.XORKeyStream(dst, src)
	}
}

func (c *Cipher) decrypt(dst, src []byte) {
	if c.info.ctype == "stream" {
		dec := (c.dec).(cipher.Stream)
		dec.XORKeyStream(dst, src)
	} else if c.info.ctype == "aead" {
		//dec := (c.dec).(cipher.AEAD)
		//dec.XORKeyStream(dst, src)
	}
}