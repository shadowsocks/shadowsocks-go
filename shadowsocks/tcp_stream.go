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
	return 4108 // according to leakybuf
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
	this.iv_offset = this.CipherInst.Info.ivLen

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
	//Logger.Fields(LogFields{
	//	"data": packet_data,
	//	"data_len": len(packet_data),
	//	"data_str": string(packet_data),
	//}).Info("check data before pack")
	//
	//packet_len := len(packet_data)
	//chunk_num := math.Ceil(float64(packet_len)/float64(this.getPayloadSizeMask()))
	//Logger.Fields(LogFields{
	//	"packet_len": packet_len,
	//	"chunk_num": chunk_num,
	//}).Info("check packet info")
	//for chunk_counter := chunk_num; chunk_counter > 0;  {
	//	payload_len := packet_len
	//	if payload_len > this.getPayloadSizeMask() {
	//		payload_len = this.getPayloadSizeMask()
	//	}
	//
	//	packet_buf := make([]byte, 2+this.CipherInst.Enc.Overhead()+payload_len+this.CipherInst.Enc.Overhead())
	//	payload_buf := packet_buf[2+this.CipherInst.Enc.Overhead() : 2+this.CipherInst.Enc.Overhead()+payload_len+this.CipherInst.Enc.Overhead()]
	//
	//	// get header
	//	packet_buf[0], packet_buf[1] = byte(payload_len>>8), byte(payload_len)
	//
	//	Logger.Fields(LogFields{
	//		"header": packet_buf[:2],
	//		"iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//	}).Info("check header before Encrypt")
	//
	//	// pack header
	//	err = this.CipherInst.Encrypt(packet_buf, packet_buf[:2])
	//	if err != nil {
	//		Logger.Fields(LogFields{
	//			"header": packet_buf[:2],
	//			"this.cipher.iv": this.CipherInst.iv,
	//			"nonce": this.CipherInst.nonce,
	//			"err": err,
	//		}).Warn("encrypt header error")
	//		break
	//	}
	//	Logger.Fields(LogFields{
	//		"header": packet_buf[:2+this.CipherInst.Enc.Overhead()],
	//		"iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//	}).Info("check header after Encrypt")
	//	this.CipherInst.SetNonce(true)
	//
	//	// get payload
	//	payload := packet_data[:payload_len]
	//
	//	Logger.Fields(LogFields{
	//		"payload_str": string(payload),
	//		"payload": payload,
	//		"iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//	}).Info("check payload before Encrypt")
	//
	//	// pack payload
	//	err = this.CipherInst.Encrypt(payload_buf, payload)
	//	if err != nil {
	//		Logger.Fields(LogFields{
	//			"payload": payload_buf,
	//			"this.cipher.iv": this.CipherInst.iv,
	//			"nonce": this.CipherInst.nonce,
	//			"err": err,
	//		}).Warn("encrypt payload error")
	//		break
	//	}
	//	Logger.Fields(LogFields{
	//		"packet_buf": packet_buf,
	//		"payload": payload_buf,
	//		"iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//	}).Info("check payload after Encrypt")
	//	this.CipherInst.SetNonce(true)
	//
	//	_, err = this.data_buffer.Write(packet_buf)
	//	if err != nil {
	//		Logger.Fields(LogFields{
	//			"data": packet_buf,
	//			"err": err,
	//		}).Warn("write data to buffer error")
	//		break
	//	}
	//	chunk_counter--
	//	packet_len -= payload_len
	//}

	return
}

func (this *ConnStream) UnPack() (err error) {
	//var n int
	///// read header
	//header := make([]byte, 2+this.CipherInst.Dec.Overhead())
	//
	//Logger.Info("begin reading header")
	//n, err = this.Conn.Read(header)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"err": err,
	//	}).Warn("read data error")
	//	return
	//}
	//Logger.Info("done reading header")
	//
	//if n <= 0 {
	//	return
	//}
	//header = header[:n]
	//
	///// unpack header
	//Logger.Fields(LogFields{
	//	"data": header,
	//	"iv": this.CipherInst.iv,
	//}).Info("check header before unpack")
	//err = this.CipherInst.Decrypt(header, header) // decrypt packet data
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"header": header,
	//		"this.cipher.iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//		"err": err,
	//	}).Warn("decrypt header error")
	//	return
	//}
	//this.CipherInst.SetNonce(true)
	//
	///// get payload size
	//payload_size := int(header[0])<<8 + int(header[1]) & this.getPayloadSizeMask()
	//
	///// read payload encrypted data
	//payload := make([]byte, payload_size+this.CipherInst.Dec.Overhead())
	//n, err = this.Conn.Read(payload)
	//if err != nil && err != io.EOF {
	//	Logger.Fields(LogFields{
	//		"err": err,
	//	}).Warn("read data error")
	//	return
	//}
	//
	///// unpack payload
	//err = this.CipherInst.Decrypt(payload, payload) // decrypt packet data
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		//"data_str": string(data),
	//		"payload_len": len(payload),
	//		"payload": payload,
	//		"this.cipher.iv": this.CipherInst.iv,
	//		"nonce": this.CipherInst.nonce,
	//		"err": err,
	//	}).Warn("decrypt payload error")
	//	return
	//}
	//payload = payload[:payload_size]
	//this.CipherInst.SetNonce(true)
	//
	////_, payload = RemoveEOF(payload)
	//Logger.Fields(LogFields{
	//	"data": string(payload),
	//	"iv": this.CipherInst.iv,
	//}).Info("check payload after unpack")
	//
	//if payload == nil {
	//	return
	//}
	//
	//_, err = this.data_buffer.Write(payload)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"data": payload,
	//		"data_str": string(payload),
	//		"err": err,
	//	}).Warn("write data to connection error")
	//	return
	//}
	return
}