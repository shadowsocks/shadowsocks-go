package shadowsocks

import (
	"io"
	"bytes"
)

/*
 * [IV][encrypted payload]
 */
type PacketStream struct {
	Packet
	Cipher *CipherStream
	iv_offset int
	packet []byte // [IV][encrypted payload]
	data []byte
	writer io.Writer
	reader io.Reader
}

func (this *PacketStream) Init(w io.Writer, r io.Reader, doe DecOrEnc) (err error) {
	this.data, err = this.getData(r)
	if err != nil {
		return
	}

	this.writer = w
	if doe == Encrypt {
		this.packet = make([]byte, len(this.data) + this.Cipher.Info.ivLen)
		err  = this.initEncrypt()
		if err != nil {
			return
		}
	} else if doe == Decrypt {
		err  = this.initDecrypt()
		if err != nil {
			return
		}
	}
	return
}

func (this *PacketStream) initEncrypt() (err error) {
	if this.Cipher.Enc == nil {
		err = this.Cipher.Init(nil, Encrypt)
		if err != nil {
			return
		}
		this.iv_offset = this.Cipher.Info.ivLen
		copy(this.packet, this.Cipher.iv) // write iv to packet header
	} else {
		this.iv_offset = 0
	}
	return
}

func (this *PacketStream) initDecrypt() (err error) {
	if this.Cipher.Dec == nil {
		var iv []byte
		iv, err = this.getIV()
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("get iv from connection error")
			return
		}

		this.iv_offset = len(iv)
		err = this.Cipher.Init(iv, Decrypt)
		if err != nil {
			Logger.Fields(LogFields{
				"iv": iv,
				"this.cipher.iv": this.Cipher.iv,
				"err": err,
			}).Warn("decrypt init error")
			return
		}
	} else {
		this.iv_offset = 0
	}
	return
}

func (this *PacketStream) getIV() (iv []byte, err error) {
	iv = make([]byte, this.Cipher.Info.ivLen)
	if _, err = io.ReadFull(bytes.NewReader(this.data), iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *PacketStream) Pack() (err error) {
	err = this.Cipher.Encrypt(this.packet[this.iv_offset:], this.data) // encrypt true data and write encrypted data to rest of space in packet
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.packet,
			"cipher.iv": this.Cipher.iv,
			"err": err,
		}).Warn("encrypt error")
		return
	}

	_, this.packet = RemoveEOF(this.packet)
	Logger.Fields(LogFields{
		"data": this.packet,
		"cipher.iv": this.Cipher.iv,
	}).Info("check after encrypt")

	if this.packet == nil {
		return
	}

	_, err = this.writer.Write(this.packet)
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.packet,
			"err": err,
		}).Warn("write data to connection error")
		return
	}
	return
}

func (this *PacketStream) UnPack() (err error) {
	payload := this.data[this.iv_offset:]
	data := make([]byte, leakyBufSize) // get packet data from buffer first
	// assign packet size
	if len(payload) > len(data) { // if connect got new data
		data = make([]byte, len(payload))
	} else {
		data = data[:len(payload)]
	}

	err = this.Cipher.Decrypt(data, payload) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			"payload": payload,
			"this.cipher.iv": this.Cipher.iv,
			"err": err,
		}).Warn("encrypt error")
		return
	}
	_, data = RemoveEOF(data)
	if data == nil {
		return
	}

	_, err = this.writer.Write(data)
	if err != nil {
		Logger.Fields(LogFields{
			"data": data,
			"data_str": string(data),
			"err": err,
		}).Warn("write data to connection error")
		return
	}
	return
}