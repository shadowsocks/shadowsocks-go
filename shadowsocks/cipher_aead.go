package shadowsocks

import (
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/cipher"
	"golang.org/x/crypto/hkdf"
	"crypto/sha1"
	"io"
	"crypto/md5"
	"errors"
	"crypto/rand"
)

type CipherAead struct {
	Cipher

	Doe DecOrEnc
	Enc  cipher.AEAD
	Dec  cipher.AEAD
	Info *cipherInfo

	iv []byte
	key []byte
	subkey []byte
	salt   []byte
	salt_len int
	Payload []byte
}

func (c *CipherAead) newIV() (err error) {
	iv := make([]byte, c.Info.ivLen)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("new iv failed")
		return
	}
	c.iv = iv
	return
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		Logger.Fields(LogFields{
			"secret": secret,
			"salt": salt,
			"info": info,
			"err": err,
		}).Panic("generate key error")
	}
}
// key-derivation function from original Shadowsocks
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

func newAead(password string, mi *cipherInfo) (*CipherAead) {
	key := kdf(password, mi.keyLen)

	c := &CipherAead{}
	c.key = key
	c.Info = mi

	return c
}
////////////////////////////////////////////////////////////////////////////

func (c *CipherAead) Init(iv []byte, doe DecOrEnc) (err error) {
	c.Doe = doe

	if iv != nil {
		c.iv = iv
	} else if c.iv == nil {
		err = c.newIV()
		if err != nil {
			return err
		}
	}

	subkey := make([]byte, len(c.key))
	hkdfSHA1(c.key, c.salt, []byte("ss-subkey"), subkey)
	c.subkey = subkey

	c_new, err := c.Info.makeCipher(c)

	if c.Doe == Encrypt {
		c.Enc = *c_new.(*cipher.AEAD)
		//c.salt_len = len(c.salt)
	} else if c.Doe == Decrypt {
		c.Dec = *c_new.(*cipher.AEAD)
	}
	return
}

func (c *CipherAead) Encrypt(dst, src []byte) error {
	c.Doe = Decrypt
	Logger.Fields(LogFields{
		"key": c.key,
		"salt": c.salt,
		"salt_len": c.salt_len,
	}).Info("checking cipher info")
	//enc := (c.Enc).(cipher.AEAD)
	nonce := make([]byte, c.Enc.NonceSize())
	data := c.Enc.Seal(nil, nonce, src, nil)

	c.Payload = make([]byte, 2+len(data)+len(c.salt))
	copy(c.Payload[2:], c.salt)
	copy(c.Payload[len(c.salt)+2:], data)
	//c.Payload = dst[:len(c.salt)+len(data)]

	return nil
}

func (c *CipherAead) Decrypt(dst, src []byte) error {
	if len(src) < c.Dec.NonceSize() {
		Logger.Fields(LogFields{
			"src_len": len(src),
			"src": src,
			"src_string": string(src),
			"err": "no need to decrypt unpacked data",
		}).Warn("decrypt warning")
		c.Payload = src
		return errors.New("no need to decrypt unpacked data")
	}
	offset := 2
	if len(src) > len(c.salt) {
		offset = len(c.salt)+2
	}
	Logger.Fields(LogFields{
		//"offset": offset,
		"src_len": len(src),
		"salt_len": c.salt_len,
		"src": src,
		"src_string": string(src),
	}).Info("check decrypt")
	c.Doe = Encrypt
	nonce := make([]byte, c.Dec.NonceSize())
	data, err := c.Dec.Open(nil, nonce, src[offset:], nil)
	if err != nil {
		Logger.Fields(LogFields{
			"key": c.key,
			"salt": c.salt,
			"salt_len": c.salt_len,
			"nonce": nonce,
			"err": err,
		}).Warn("decrypt error")
		return err
	}
	c.Payload = data
	return nil
}

func (c *CipherAead) SetSalt(salt []byte) {
	c.salt = salt
}

func (c *CipherAead) GetSalt() []byte {
	return c.salt
}

func (c *CipherAead) Copy() (*CipherAead) {
	nc := *c
	nc.Enc = nil
	nc.Dec = nil
	return &nc
}

func newChaCha20IETFPoly1305Aead(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherAead)
	Logger.Fields(LogFields{
		"key": item.key,
		"key_len": len(item.key),
		"subkey": item.subkey,
		"subkey_len": len(item.subkey),
	}).Info("check newChaCha20IETFPoly1305Aead info")
	c, err := chacha20poly1305.New(item.subkey)
	if err != nil {
		Logger.Fields(LogFields{
			"key": item.key,
			"subkey": item.subkey,
			"err": err,
		}).Fatal("newChaCha20IETFPoly1305Aead error")
	}

	return &c, err
}