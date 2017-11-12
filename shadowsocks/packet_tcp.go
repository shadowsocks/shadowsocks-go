package shadowsocks

import (
	"io"
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
func (c *Conn) initIV(r io.Reader) {
	iv := make([]byte, c.cipher.info.ivLen)
	if _, err := io.ReadFull(r, iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read data from connect error")
		return
	}
	if len(c.cipher.iv) != 0 {
		return
	}
	c.cipher.iv = iv
}

func (c *Conn) pack(b []byte) ([]byte, error) {
	iv_len := 0
	if c.cipher.enc == nil {
		iv, err := c.cipher.initEncrypt()
		if err != nil {
			Logger.Fields(LogFields{"err": err}).Warn("shadowsocks: initEncrypt error")
			return nil, err
		}
		iv_len = len(iv)
		c.cipher.iv = iv
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
		c.initIV(c.Conn)
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