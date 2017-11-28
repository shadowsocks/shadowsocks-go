package shadowsocks

import (
	"net"
	"io"
)

type ConnStream struct {
	net.Conn
	Cipher *Cipher
	Buffer *LeakyBufType

	//////////////////

	data_buffer io.Writer

	iv_offset int

	CipherInst *CipherStream
}

func (this *ConnStream) getPayloadSizeMask() int {
	return 32 * 1024
}

func (this *ConnStream) getBuffer() *LeakyBufType {
	return NewLeakyBuf(maxNBuf, this.getPayloadSizeMask())
}


func (this *ConnStream) Init() {
	inst := this.Cipher.Inst
	this.CipherInst = inst.(*CipherStream)
}

func (this *ConnStream) initEncrypt() (err error) {
	this.Init()

	err = this.CipherInst.Init(nil, Encrypt)
	if err != nil {
		return
	}
	this.iv_offset = 0

	_, err = this.data_buffer.Write(this.CipherInst.iv)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("write iv to connection error")
		return
	}

	return
}

func (this *ConnStream) initDecrypt() (err error) {
	this.Init()

	var iv []byte
	iv, err = this.getIV()
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("get iv from connection error")
		return
	}

	this.iv_offset = len(iv)
	err = this.CipherInst.Init(iv, Decrypt)
	if err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"this.cipher.iv": this.CipherInst.iv,
			"err": err,
		}).Warn("decrypt init error")
		return
	}
	return
}

func (this *ConnStream) getIV() (iv []byte, err error) {
	iv = make([]byte, this.CipherInst.IVSize())
	if _, err = io.ReadFull(this.Conn, iv); err != nil {
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
		copy(packet_buf[:this.iv_offset], this.CipherInst.iv) // write iv to header
	}

	err = this.CipherInst.Encrypt(packet_buf[this.iv_offset:], packet_data) // encrypt true data and write encrypted data to rest of space in packet
	if err != nil {
		Logger.Fields(LogFields{
			"data": packet_data,
			"cipher.iv": this.CipherInst.iv,
			"err": err,
		}).Warn("encrypt error")
		return
	}

	_, err = this.data_buffer.Write(packet_buf)
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
	n, err = this.Conn.Read(payload)
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
			"this.cipher.iv": this.CipherInst.iv,
			"err": err,
		}).Warn("decrypt error")
		return
	}

	_, err = this.data_buffer.Write(payload)
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