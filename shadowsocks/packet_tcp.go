package shadowsocks

import (
	"io"
	"crypto/rand"
)

type Packet struct {
	*Cipher
	payload []byte
	payload_len int
}

/*
 * [IV][encrypted payload]
 */
type PacketStream struct {
	*Packet

	iv []byte
	iv_len int
}

/*
 * [encrypted payload length][length tag][encrypted payload][payload tag]
 */
type PacketAead struct {
	*Packet

	tag []byte
	tag_len int
}


////////////////////////////////////////////////////////////////////////////////

func (c *Conn) initIV(is_gen bool) (err error) {
	iv := make([]byte, c.cipher.info.ivLen)
	if is_gen && c.cipher.iv == nil {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			Logger.Fields(LogFields{
				"c.cipher.info": c.cipher.info,
				"err": err,
			}).Warn("new iv failed")
			return err
		}
		c.cipher.iv = iv
		return
	} else if !is_gen{
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			Logger.Fields(LogFields{
				"iv": iv,
				"err": err,
			}).Warn("shadowsocks: read iv from connect error")
			return err
		}
		if len(c.cipher.iv) != 0 {
			Logger.Fields(LogFields{
				"c.cipher.iv": c.cipher.iv,
			}).Warn("shadowsocks: no need to update iv")
			return
		}
		c.cipher.iv = iv
	}

	return nil
}

func (c *Conn) pack(b []byte) ([]byte, error) {
	iv_len := 0
	if c.cipher.enc == nil {
		if err := c.initIV(true); err != nil {
			return nil, err
		}
		Logger.Fields(LogFields{
			"cipher_addr": c.cipher,
			"key": c.cipher.key,
			"iv": c.cipher.iv,
		}).Info("Checking cipher info for init")
		err := c.cipher.initEncrypt()
		if err != nil {
			Logger.Fields(LogFields{"err": err}).Warn("shadowsocks: initEncrypt error")
			return nil, err
		}
		iv_len = len(c.cipher.iv)
	}

	cipherData := c.buffer.Get()
	dataSize := len(b) + iv_len
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if c.cipher.iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, c.cipher.iv)
	}
	c.cipher.encrypt(cipherData[iv_len:], b)

	return cipherData, nil
}

func (c *Conn) unpack(b []byte) (int, error) {
	n := 0
	if c.cipher.dec == nil {
		if err := c.initIV(false); err != nil {
			return n, err
		}
		if err := c.cipher.initDecrypt(c.cipher.iv); err != nil {
			Logger.Fields(LogFields{
				"iv": c.cipher.iv,
				"err":   err,
			}).Warn("shadowsocks: initDecrypt error")
			return n, err
		}
	}
	cipherData := c.buffer.Get()

	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}
	n, err := c.Conn.Read(cipherData)
	if err != nil {
		Logger.Fields(LogFields{
			"n": n,
			"cipherData": cipherData,
			"err": err,
		}).Warn("shadowsocks: read cipherData error")
		return n, err
	}

	if n > 0 {
		c.cipher.decrypt(b[0:n], cipherData[0:n])
	}
	return n, err
}
////////////////////////////////////////////////////////////////
