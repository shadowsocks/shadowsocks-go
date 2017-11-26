package shadowsocks

import (
	"io"
	"bytes"
	"math"
)

const payloadSizeMask = 0x3FFF // 16*1024 - 1

/*
 * [encrypted payload length][length tag][encrypted payload][payload tag]
 */
type PacketAead struct {
	Packet
	Cipher *CipherAead
	Info *cipherInfo

	tag []byte
	tag_len int

	iv_offset int
	packet []byte // [IV][encrypted payload]
	data []byte
	writer io.Writer
}

func (this *PacketAead) Init(w io.Writer, data []byte, doe DecOrEnc) {
	this.writer = w
	this.data = data
	if doe == Encrypt {
		this.initEncrypt()
	} else if doe == Decrypt {
		this.initDecrypt()
	}
}

func (this *PacketAead) initEncrypt() {
	if this.Cipher.Enc == nil {
		this.Cipher.Init(nil, Encrypt)
		this.iv_offset = 2 + this.Cipher.Enc.Overhead()

		_, err := this.writer.Write(this.Cipher.iv)
		if err != nil {
			Logger.Fields(LogFields{
				"data": this.packet,
				"err": err,
			}).Warn("write iv to connection error")
			return
		}
	} else {
		this.iv_offset = 2
	}
}

func (this *PacketAead) initDecrypt() {
	if this.Cipher.Dec == nil {
		iv, err := this.getIV()
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
}

func (this *PacketAead) getIV() (iv []byte, err error) {
	iv = make([]byte, this.Cipher.IVSize())
	if _, err = io.ReadFull(bytes.NewReader(this.data), iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *PacketAead) Pack() {

	data_len := len(this.data)
	chunk_num := math.Ceil(float64(data_len)/payloadSizeMask)

	for chunk_counter := chunk_num; chunk_counter > 0; chunk_counter-- {
		if data_len > payloadSizeMask {
			data_len = payloadSizeMask
		}
		data := this.data[:data_len]
		this.PackChunk(data)
		this.data = this.data[data_len:]
		data_len = len(this.data)
	}
}

func (this *PacketAead) PackChunk(data []byte) {
	this.packet = make([]byte, 2+this.Cipher.Enc.Overhead()+payloadSizeMask+this.Cipher.Enc.Overhead())
	header := make([]byte, 2+this.Cipher.Enc.Overhead())
	payload := this.packet[2+this.Cipher.Enc.Overhead():]
	payload_len := len(data)

	this.packet[0], this.packet[1] = byte(payload_len>>8), byte(payload_len)
	this.Cipher.Encrypt(header, this.packet[:2])
	this.Cipher.SetNonce(true)
	copy(this.packet[:2+this.Cipher.Enc.Overhead()], header)

	this.Cipher.Encrypt(payload, data)
	this.Cipher.SetNonce(true)

	copy(this.packet[2+this.Cipher.Enc.Overhead():], payload)

	_, this.packet = RemoveEOF(this.packet)
	if this.packet == nil {
		Logger.Warn("no data to write to connection")
		return
	}

	_, err := this.writer.Write(this.packet)
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.packet,
			"err": err,
		}).Warn("write data to connection error")
		return
	}
}

func (this *PacketAead) UnPack() {
	if len(this.data) <= this.iv_offset {
		Logger.Fields(LogFields{
			"data": this.data,
			"this.cipher.iv": this.Cipher.iv,
		}).Warn("no data to unpack")
		return
	}

	this.packet = make([]byte, 2+payloadSizeMask+this.Cipher.Dec.Overhead())
	header_buf := make([]byte, 2+this.Cipher.Dec.Overhead())
	header := this.data[this.iv_offset:this.iv_offset+2+this.Cipher.Dec.Overhead()]

	err := this.Cipher.Decrypt(header_buf, header) // decrypt packet data
	this.Cipher.SetNonce(true)
	if err != nil {
		Logger.Fields(LogFields{
			"header": header,
			"this.cipher.iv": this.Cipher.iv,
			"err": err,
		}).Warn("decrypt header error")
		return
	}

	payload_size := int(header[0])<<8 + int(header[1]) & payloadSizeMask

	payload := this.data[this.iv_offset+2+this.Cipher.Dec.Overhead():]

	data := make([]byte, payload_size)
	err = this.Cipher.Decrypt(data, payload) // decrypt packet data
	this.Cipher.SetNonce(true)
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.data,
			"payload": payload,
			"this.cipher.iv": this.Cipher.iv,
			"err": err,
		}).Warn("decrypt payload error")
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
}