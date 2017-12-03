package shadowsocks

import (
	"io"
	"bytes"
	"crypto/rand"
	"errors"
)

type StreamCryptor struct {
	Cryptor
	dataBuffer *bytes.Buffer
	buffer *LeakyBufType
	reader io.Reader
	writer io.Writer

	iv [2][]byte

	cipher Cipher
}

func (this *StreamCryptor) getPayloadSizeMask() int {
	return 1024
	//return 32*1024
}

func (this *StreamCryptor) GetBuffer() (buffer *LeakyBufType, err error) {
	buffer = this.buffer
	if buffer != nil { return }
	buffer = NewLeakyBuf(maxNBuf, this.getPayloadSizeMask()); this.buffer = buffer; return
}

func (this *StreamCryptor) newIV() (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize()); if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }; return }

func (this *StreamCryptor) Init(cipher Cipher) Cryptor {
	this.cipher = cipher
	this.dataBuffer = bytes.NewBuffer(nil)
	return this
}

func (this *StreamCryptor) isInit(decrypt DecOrEnc) bool {
	//if this.cipher != nil && this.cipher.GetCryptor(decrypt) != nil && this.iv[decrypt] != nil { return true }
	if this.cipher != nil && this.cipher.GetCryptor(decrypt) != nil { return true }

	return false
}

func (this *StreamCryptor) initEncrypt(r io.Reader, w io.Writer) (err error) {
	this.reader = r; this.writer = w;
	this.dataBuffer = bytes.NewBuffer(nil)

	var iv []byte
	if iv, err = this.newIV(); err != nil { return }
	if err = this.cipher.Init(iv, Encrypt); err != nil { return }

	if _, err = this.dataBuffer.Write(iv); err != nil { return }
	this.iv[Encrypt] = iv

	return
}

func (this *StreamCryptor) initDecrypt(r io.Reader, w io.Writer) (err error) {
	this.reader = r; this.writer = w
	this.dataBuffer = bytes.NewBuffer(nil)

	var iv []byte; if iv, err = this.getIV(); err != nil { return }

	if err = this.cipher.Init(iv, Decrypt); err != nil { return }
	this.iv[Decrypt] = iv

	return
}

func (this *StreamCryptor) getIV() (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	if _, err = io.ReadFull(this.reader, iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *StreamCryptor) Pack(b []byte) (n int, err error) {
	if !this.isInit(Encrypt) {
		Logger.Warn("Encryptor not init")
		err = errors.New("Encryptor not init")
		return
	}
	if n, err = bytes.NewReader(b).Read(b); err != nil { return }
	buf := make([]byte, n)

	if n > 0 {
		packet_data := b[:n]

		err = this.cipher.Encrypt(buf, packet_data)
		if err != nil {
			Logger.Fields(LogFields{
				"data": packet_data,
				"cipher.iv": this.iv[Encrypt],
				"err": err,
			}).Warn("encrypt error")
			return
		}

		_, err = this.dataBuffer.Write(buf)
		if err != nil {
			Logger.Fields(LogFields{
				"data": buf,
				"err": err,
			}).Warn("write data to connection error")
			return
		}
	}

	return this.WriteTo()
}

func (this *StreamCryptor) UnPack(b []byte) (n int, err error) {
	if !this.isInit(Decrypt) {
		Logger.Warn("Decryptor not init")
		err = errors.New("Decryptor not init")
		return
	}
	this.dataBuffer = bytes.NewBuffer(nil)

	n, err = this.reader.Read(b)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}

	if n > 0 {
		payload := b[:n]
		err = this.cipher.Decrypt(payload, payload) // decrypt packet data
		if err != nil {
			Logger.Fields(LogFields{
				"payload": payload,
				"this.cipher.iv": this.iv[Decrypt],
				"err": err,
			}).Warn("decrypt error")
			return
		}

		_, err = this.dataBuffer.Write(payload)
		if err != nil {
			Logger.Fields(LogFields{
				"data": payload,
				"data_str": string(payload),
				"err": err,
			}).Warn("write data to connection error")
			return
		}
	}

	return this.Read(b)
}

func (this *StreamCryptor) WriteTo() (n int, err error) {
	var n_64 int64
	if n_64, err = this.dataBuffer.WriteTo(this.writer); err != nil { return }
	n = int(n_64)
	return
}

func (this *StreamCryptor) Read(b []byte) (n int, err error) {
	data := this.dataBuffer.Bytes()
	return bytes.NewReader(data).Read(b)
}