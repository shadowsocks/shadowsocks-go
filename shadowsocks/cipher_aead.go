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

	nonce []byte
	iv []byte
	key []byte
	subkey []byte
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

func hkdfSHA1(secret, iv, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, iv, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		Logger.Fields(LogFields{
			"secret": secret,
			"iv": iv,
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
	c.nonce = nil

	if iv != nil {
		c.iv = iv
	} else if c.iv == nil {
		err = c.newIV()
		if err != nil {
			return err
		}
	}

	subkey := make([]byte, c.KeySize())
	hkdfSHA1(c.key, c.iv, []byte("ss-subkey"), subkey)
	c.subkey = subkey

	c_new, err := c.Info.makeCipher(c)

	if c.Doe == Encrypt {
		c.Enc = *c_new.(*cipher.AEAD)
	} else if c.Doe == Decrypt {
		c.Dec = *c_new.(*cipher.AEAD)
	}
	return
}

func (c *CipherAead) Encrypt(dst, src []byte) error {
	c.Enc.Seal(dst[:0], c.Nonce(), src, nil)

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

	_, err := c.Dec.Open(dst[:0], c.Nonce(), src, nil)
	if err != nil {
		Logger.Fields(LogFields{
			"key": c.key,
			"iv": c.iv,
			"iv_len": c.Info.ivLen,
			"nonce": c.Nonce(),
			"err": err,
		}).Warn("decrypt error")
		return err
	}

	return nil
}

func (c *CipherAead) Nonce() []byte {
	if c.nonce == nil {
		c.SetNonce(false)
	}
	return c.nonce
}

func (c *CipherAead) SetNonce(increment bool) {
	if increment {
		for i := range c.nonce {
			c.nonce[i]++
			if c.nonce[i] != 0 {
				return
			}
		}
		return
	}

	crypto := c.Enc
	if c.Doe == Decrypt {
		crypto = c.Dec
	}

	c.nonce = make([]byte, crypto.NonceSize())
}

func (c *CipherAead) IV() []byte {
	return c.iv
}

func (c *CipherAead) IVSize() int {
	if ks := c.KeySize(); ks > c.Info.ivLen {
		return ks
	}

	return c.Info.ivLen
}

func (c *CipherAead) KeySize() int {
	return len(c.key)
}

func (c *CipherAead) Copy() (*CipherAead) {
	nc := *c
	nc.Enc = nil
	nc.Dec = nil
	return &nc
}

func newChaCha20IETFPoly1305Aead(cipher_item interface{}) (interface{}, error) {
	item := cipher_item.(*CipherAead)
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