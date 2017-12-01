package shadowsocks

import (
	"io"
	"bytes"
)

type ConnStream struct {
	ConnCipher
	dataBuffer *bytes.Buffer
	reader io.Reader

	iv_offset int

	CipherInst Cipher
}

func (this *ConnStream) getPayloadSizeMask() int {
	return 32 * 1024
}

//func (this *ConnStream) getBuffer() *LeakyBufType {
//	return NewLeakyBuf(maxNBuf, this.getPayloadSizeMask())
//}


func (this *ConnStream) Init(r io.Reader, cipher Cipher) {
	//this.CipherInst = cipher.Inst.(*CipherStream)
	this.CipherInst = cipher
	this.dataBuffer = bytes.NewBuffer(nil)
}

func (this *ConnStream) initEncrypt(r io.Reader, cipher Cipher) (err error) {
	if this.CipherInst != nil && this.CipherInst.GetCryptor() != nil {
		this.iv_offset = 0
		return
	}
	this.Init(r, cipher)

	err = this.CipherInst.Init(nil, false)
	if err != nil {
		return
	}
	this.iv_offset = 0

	_, err = this.dataBuffer.Write(this.CipherInst.IV())
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("write iv to connection error")
		return
	}

	return
}

func (this *ConnStream) initDecrypt(r io.Reader, cipher Cipher) (err error) {
	if this.CipherInst != nil && this.CipherInst.GetCryptor() != nil {
		this.iv_offset = 0
		return
	}

	this.Init(r, cipher)

	var iv []byte
	iv, err = this.getIV()
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("get iv from connection error")
		return
	}

	this.iv_offset = len(iv)
	err = this.CipherInst.Init(iv, true)
	if err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"this.cipher.iv": this.CipherInst.IV(),
			"err": err,
		}).Warn("decrypt init error")
		return
	}
	return
}

func (this *ConnStream) getIV() (iv []byte, err error) {
	iv = make([]byte, this.CipherInst.IVSize())
	if _, err = io.ReadFull(this.reader, iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *ConnStream) Pack(packet_data []byte) (err error) {
	packet_buf := make([]byte, this.iv_offset + len(packet_data))

	if this.iv_offset > 0 {
		copy(packet_buf[:this.iv_offset], this.CipherInst.IV()) // write iv to header
	}

	err = this.CipherInst.Encrypt(packet_buf[this.iv_offset:], packet_data) // encrypt true data and write encrypted data to rest of space in packet
	if err != nil {
		Logger.Fields(LogFields{
			"data": packet_data,
			"cipher.iv": this.CipherInst.IV(),
			"err": err,
		}).Warn("encrypt error")
		return
	}

	_, err = this.dataBuffer.Write(packet_buf)
	if err != nil {
		Logger.Fields(LogFields{
			"data": packet_buf,
			"err": err,
		}).Warn("write data to connection error")
		return
	}

	return
}

func (this *ConnStream) UnPack() (err error) {
	var n int
	payload := make([]byte, this.getPayloadSizeMask())
	n, err = this.reader.Read(payload)
	if err != nil && err != io.EOF {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}

	if n <= 0 {
		return
	}

	payload = payload[:n]
	err = this.CipherInst.Decrypt(payload, payload) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			"payload": payload,
			"this.cipher.iv": this.CipherInst.IV(),
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

	return
}

func (this *ConnStream) WriteTo(w io.Writer) (n int64, err error) {
	return this.dataBuffer.WriteTo(w)
}

func (this *ConnStream) Read(b []byte) (n int, err error) {
	return this.dataBuffer.Read(b)
}