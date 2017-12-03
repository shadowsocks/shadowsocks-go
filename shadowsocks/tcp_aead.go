package shadowsocks

import (
	"io"
	"math"
	"bytes"
	"crypto/cipher"
	"errors"
	"crypto/rand"
)

type AeadCryptor struct {
	Cryptor
	dataBuffer *bytes.Buffer
	buffer *LeakyBufType
	reader io.Reader
	writer io.Writer

	cipher Cipher
	iv []byte
}

func (this *AeadCryptor) getPayloadSizeMask() int {
	return 0x3FFF // 16*1024 - 1
}

func (this *AeadCryptor) GetBuffer() (buffer *LeakyBufType, err error) {
	var cryptor cipher.AEAD
	buffer = this.buffer
	if buffer != nil { return }
	if this.cipher == nil {
		err = errors.New("cryptor not init")
		return
	}
	encryptor := this.cipher.GetCryptor(Encrypt)
	decryptor := this.cipher.GetCryptor(Decrypt)
	if encryptor != nil { cryptor = encryptor.(cipher.AEAD) } else { cryptor = decryptor.(cipher.AEAD) }
	size := 2 + cryptor.Overhead() + this.getPayloadSizeMask() + cryptor.Overhead()
	buffer = NewLeakyBuf(maxNBuf, size); this.buffer = buffer; return
}

func (this *AeadCryptor) newIV() (err error) {
	iv := make([]byte, this.cipher.IVSize()); if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }; this.iv = iv; return}


func (this *AeadCryptor) Init(cipher Cipher) Cryptor {
	this.cipher = cipher
	this.dataBuffer = bytes.NewBuffer(nil)
	return this
}

func (this *AeadCryptor) initEncrypt(r io.Reader, w io.Writer) (err error) {
	this.reader = r; this.writer = w
	if err = this.newIV(); err != nil { return }

	if err = this.cipher.Init(this.iv, Encrypt); err != nil { return }

	_, err = this.dataBuffer.Write(this.iv)

	return
}

func (this *AeadCryptor) initDecrypt(r io.Reader, w io.Writer) (err error) {
	this.reader = r; this.writer = w

	var iv []byte; iv, err = this.getIV(); if err != nil { return }

	this.iv = iv

	err = this.cipher.Init(iv, Decrypt)

	return
}

func (this *AeadCryptor) getIV() (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	if _, err = io.ReadFull(this.reader, iv); err != nil { return }

	return
}

func (this *AeadCryptor) Pack(packet_data []byte) (n int, err error) {
	cryptor := this.cipher.GetCryptor(Encrypt).(cipher.AEAD)
	packet_len := len(packet_data)
	chunk_num := math.Ceil(float64(packet_len)/float64(this.getPayloadSizeMask()))

	for chunk_counter := chunk_num; chunk_counter > 0;  {
		payload_len := packet_len
		if payload_len > this.getPayloadSizeMask() {
			payload_len = this.getPayloadSizeMask()
		}

		packet_buf := make([]byte, 2+cryptor.Overhead()+payload_len+cryptor.Overhead())
		payload_buf := packet_buf[2+cryptor.Overhead() : 2+cryptor.Overhead()+payload_len+cryptor.Overhead()]

		// get header
		packet_buf[0], packet_buf[1] = byte(payload_len>>8), byte(payload_len)

		// pack header
		err = this.cipher.Encrypt(packet_buf, packet_buf[:2])
		if err != nil {
			Logger.Fields(LogFields{
				"header": packet_buf[:2],
				"this.cipher.iv": this.iv,
				//"nonce": this.CipherInst.nonce,
				"err": err,
			}).Warn("encrypt header error")
			break
		}

		// get payload
		payload := packet_data[:payload_len]

		// pack payload
		err = this.cipher.Encrypt(payload_buf, payload)
		if err != nil {
			Logger.Fields(LogFields{
				"payload": payload_buf,
				"this.cipher.iv": this.iv,
				//"nonce": this.CipherInst.nonce,
				"err": err,
			}).Warn("encrypt payload error")
			break
		}

		_, err = this.dataBuffer.Write(packet_buf)
		if err != nil {
			Logger.Fields(LogFields{
				"data": packet_buf,
				"err": err,
			}).Warn("write data to buffer error")
			break
		}
		chunk_counter--
		packet_len -= payload_len
	}

	return this.WriteTo()
}

func (this *AeadCryptor) UnPack(b []byte) (n int, err error) {
	buffer_size := len(b)
	cryptor := this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
	/// read header
	header_offset := 2+cryptor.Overhead()
	header := b[:header_offset]

	if _, err = io.ReadFull(this.reader, header); err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}

	/// unpack header
	err = this.cipher.Decrypt(header, header) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			"header": header,
			"this.cipher.iv": this.iv,
			"err": err,
		}).Warn("decrypt header error")
		return
	}

	/// get payload size
	payload_size := int(header[0])<<8 + int(header[1]) & this.getPayloadSizeMask()
	if buffer_size < payload_size + cryptor.Overhead() {
		err = errors.New("buffer size is too small")
		return
	}

	/// read payload encrypted data
	payload := b[:payload_size+cryptor.Overhead()]
	if _, err = io.ReadFull(this.reader, payload); err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}

	/// unpack payload
	err = this.cipher.Decrypt(payload, payload) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			//"data_str": string(data),
			"payload_len": len(payload),
			"payload": payload,
			"this.cipher.iv": this.iv,
			//"nonce": this.CipherInst.nonce,
			"err": err,
		}).Warn("decrypt payload error")
		return
	}
	payload = payload[:payload_size]

	_, err = this.dataBuffer.Write(payload)
	if err != nil {
		Logger.Fields(LogFields{
			"data": payload,
			"data_str": string(payload),
			"err": err,
		}).Warn("write data to connection error")
		return
	}

	return this.Read(b)
}

func (this *AeadCryptor) WriteTo() (n int, err error) {
	var n_64 int64
	if n_64, err = this.dataBuffer.WriteTo(this.writer); err != nil { return }
	n = int(n_64)
	return
}

func (this *AeadCryptor) Read(b []byte) (n int, err error) {
	return this.dataBuffer.Read(b)
}