package shadowsocks

import (
	"io"
	"math"
)

func (this *Conn) Init() {
	inst := this.Cipher.Inst
	if this.Cipher.CType == C_STREAM {

	} else if this.Cipher.CType == C_AEAD {
		this.CipherInst = inst.(*CipherAead)
	}
}

//func (this *Conn) SetData(data []byte, doe DecOrEnc) (err error) {
//	this.doe = doe
//	this.buffer[this.doe] = bytes.NewBuffer(nil)
//	if this.doe == Encrypt {
//		this.data[this.doe] = data
//	} else if this.doe == Decrypt {
//		this.data[this.doe], err = this.getData(data)
//		if err != nil {
//			return
//		}
//	}
//
//	return
//}

// fetch data for decrypt
func (this *Conn) getData(b []byte) (data []byte, err error) {
	/////////////////////////////////////////////////////////
	//var n int
	//buf := this.readBuf
	//if len(b) > len(buf) {
	//	buf = make([]byte, len(b))
	//} else {
	//	buf = buf[:len(b)]
	//}
	//n, err = this.Conn.Read(buf)
	//if err != nil {
	//	return
	//}
	//data = buf[:n]
	////////////////////////////////////////////////////////
	var n int
	buf := leakyBuf.Get()
	buf_len := len(buf)
	data_len := 0
	counter := 1
	for {
		n, err = this.Conn.Read(buf)
		if err != nil && err != io.EOF {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("read data error")
			return
		} else if n == buf_len {
			tmp_buf := make([]byte, buf_len*counter)
			if data != nil {
				copy(tmp_buf, data)
			}
			copy(tmp_buf[data_len:], buf[:n])
			data = tmp_buf
			data_len += n
		} else { // read all data while got eof error
			if counter == 1 {
				data = buf[:n]
			} else {
				tmp_buf := make([]byte, buf_len*(counter-1)+n)
				copy(tmp_buf, data)
				copy(tmp_buf[data_len:], buf[:n])
				data = tmp_buf
			}
			data_len += n

			break
		}
		counter++
	}

	return
}

//func (this *Conn) Init(w io.Writer, r io.Reader, doe DecOrEnc) (err error) {
//	this.data, err = this.getData(r)
//	if err != nil {
//		return
//	}
//	this.writer = w
//	if doe == Encrypt {
//		err = this.initEncrypt()
//		if err != nil {
//			return
//		}
//	} else if doe == Decrypt {
//		err = this.initDecrypt()
//		if err != nil {
//			return
//		}
//	}
//	return
//}

func (this *Conn) initEncrypt() (err error) {
	this.Init()

	err = this.CipherInst.Init(nil, Encrypt)
	if err != nil {
		return
	}
	this.iv_offset[this.doe] = 2 + this.CipherInst.Enc.Overhead()

	_, err = this.buffer[this.doe].Write(this.CipherInst.iv)
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.packet,
			"err": err,
		}).Warn("write iv to connection error")
		return
	}

	return
}

func (this *Conn) initDecrypt() (err error) {
	this.Init()

	var iv []byte
	iv, err = this.getIV()
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("get iv from connection error")
		return
	}

	this.iv_offset[this.doe] = len(iv)
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

func (this *Conn) getIV() (iv []byte, err error) {
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

func (this *Conn) Pack(packet_data []byte) (err error) {
	//var n int
	Logger.Fields(LogFields{
		"doe": this.doe,
		"data": packet_data,
		"data_len": len(packet_data),
		"data_str": string(packet_data),
	}).Info("check data before pack")

	packet_len := len(packet_data)
	chunk_num := math.Ceil(float64(packet_len)/payloadSizeMask)
	Logger.Fields(LogFields{
		"packet_len": packet_len,
		"chunk_num": chunk_num,
	}).Info("check packet info")
	for chunk_counter := chunk_num; chunk_counter > 0;  {
		payload_len := packet_len
		if payload_len > payloadSizeMask {
			payload_len = payloadSizeMask
		}

		packet_buf := make([]byte, 2+this.CipherInst.Enc.Overhead()+payload_len+this.CipherInst.Enc.Overhead())
		payload_buf := packet_buf[2+this.CipherInst.Enc.Overhead() : 2+this.CipherInst.Enc.Overhead()+payload_len+this.CipherInst.Enc.Overhead()]
		//n, err = this.Conn.Read(payload_buf)
		//if err != nil {
		//	Logger.Fields(LogFields{
		//		"err": err,
		//	}).Warn("read payload error")
		//	break
		//}
		//Logger.Fields(LogFields{
		//	"payload_buf": payload_buf,
		//	"n": n,
		//}).Info("check payload")

		//if n > 0 {
		//	packet_buf = packet_buf[:2+this.CipherInst.Enc.Overhead()+n+this.CipherInst.Enc.Overhead()]
		//	payload_buf = payload_buf[:n]
			// get header
			packet_buf[0], packet_buf[1] = byte(payload_len>>8), byte(payload_len)

		Logger.Fields(LogFields{
			"header": packet_buf[:2],
			"iv": this.CipherInst.iv,
			"nonce": this.CipherInst.nonce,
		}).Info("check header before Encrypt")
			// pack header
			err = this.CipherInst.Encrypt(packet_buf, packet_buf[:2])
			if err != nil {
				Logger.Fields(LogFields{
					"header": packet_buf[:2],
					"this.cipher.iv": this.CipherInst.iv,
					"nonce": this.CipherInst.nonce,
					"err": err,
				}).Warn("encrypt header error")
				break
			}
			Logger.Fields(LogFields{
				"header": packet_buf[:2+this.CipherInst.Enc.Overhead()],
				"iv": this.CipherInst.iv,
				"nonce": this.CipherInst.nonce,
			}).Info("check header after Encrypt")
			this.CipherInst.SetNonce(true)

			// get payload
			payload := packet_data[:payload_len]

		Logger.Fields(LogFields{
			"payload_str": string(payload),
			"payload": payload,
			"iv": this.CipherInst.iv,
			"nonce": this.CipherInst.nonce,
		}).Info("check payload before Encrypt")
			// pack payload
			err = this.CipherInst.Encrypt(payload_buf, payload)
			if err != nil {
				Logger.Fields(LogFields{
					"payload": payload_buf,
					"this.cipher.iv": this.CipherInst.iv,
					"nonce": this.CipherInst.nonce,
					"err": err,
				}).Warn("encrypt payload error")
				break
			}
			Logger.Fields(LogFields{
				"packet_buf": packet_buf,
				"payload": payload_buf,
				"iv": this.CipherInst.iv,
				"nonce": this.CipherInst.nonce,
			}).Info("check payload after Encrypt")
			this.CipherInst.SetNonce(true)

			_, err = this.buffer[this.doe].Write(packet_buf)
			if err != nil {
				Logger.Fields(LogFields{
					"data": packet_buf,
					"err": err,
				}).Warn("write data to buffer error")
				break
			}
			chunk_counter--
			packet_len -= payload_len
		//}
	}
	//data_len := len(packet_data)
	//chunk_num := math.Ceil(float64(data_len)/payloadSizeMask)
	//
	//for chunk_counter := chunk_num; chunk_counter > 0; chunk_counter-- {
	//	if data_len > payloadSizeMask {
	//		data_len = payloadSizeMask
	//	}
	//	data := packet_data[:data_len]
	//	err = this.PackChunk(data)
	//	if err != nil {
	//		return
	//	}
	//	if data_len == len(packet_data) {
	//		return
	//	}
	//	packet_data = packet_data[data_len:]
	//	data_len = len(packet_data)
	//}
	return
}

//func (this *Conn) Pack(packet_data []byte) (err error) {
//	Logger.Fields(LogFields{
//		"doe": this.doe,
//		"data": packet_data,
//		"data_len": len(packet_data),
//		"data_str": string(packet_data),
//	}).Info("check data before pack")
//	data_len := len(packet_data)
//	chunk_num := math.Ceil(float64(data_len)/payloadSizeMask)
//
//	for chunk_counter := chunk_num; chunk_counter > 0; chunk_counter-- {
//		if data_len > payloadSizeMask {
//			data_len = payloadSizeMask
//		}
//		data := packet_data[:data_len]
//		err = this.PackChunk(data)
//		if err != nil {
//			return
//		}
//		if data_len == len(packet_data) {
//			return
//		}
//		packet_data = packet_data[data_len:]
//		data_len = len(packet_data)
//	}
//	return
//}

//func (this *Conn) PackChunk(data []byte) (err error) {
//	packet_data := make([]byte, 2+this.CipherInst.Enc.Overhead()+payloadSizeMask+this.CipherInst.Enc.Overhead())
//	header := make([]byte, 2+this.CipherInst.Enc.Overhead())
//	payload := packet_data[2+this.CipherInst.Enc.Overhead():]
//	payload_len := len(data)
//
//	packet_data[0], packet_data[1] = byte(payload_len>>8), byte(payload_len)
//	err = this.CipherInst.Encrypt(header, packet_data[:2])
//	if err != nil {
//		return
//	}
//	Logger.Fields(LogFields{
//		"header": header,
//		"iv": this.CipherInst.iv,
//	}).Info("check header after Encrypt")
//	this.CipherInst.SetNonce(true)
//	copy(packet_data[:2+this.CipherInst.Enc.Overhead()], header)
//
//	err = this.CipherInst.Encrypt(payload, data)
//	if err != nil {
//		return
//	}
//	//Logger.Fields(LogFields{
//	//	"payload": payload,
//	//	"iv": this.CipherInst.iv,
//	//}).Info("check payload after Encrypt")
//	this.CipherInst.SetNonce(true)
//
//	copy(packet_data[2+this.CipherInst.Enc.Overhead():], payload)
//
//	_, packet_data = RemoveEOF(packet_data)
//	if packet_data == nil {
//		Logger.Warn("no data to write to connection")
//		return
//	}
//
//	_, err = this.buffer[this.doe].Write(packet_data)
//	if err != nil {
//		Logger.Fields(LogFields{
//			"data": packet_data,
//			"err": err,
//		}).Warn("write data to connection error")
//		return
//	}
//
//	return
//}

func (this *Conn) UnPack() (err error) {
	var n int
	/// read header
	header := make([]byte, 2+this.CipherInst.Dec.Overhead())

	Logger.Info("begin reading header")
	n, err = this.Conn.Read(header)
	if err != nil {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}
	Logger.Info("done reading header")
	//if n, err = io.ReadFull(this.Conn, header); err != nil {
	//	Logger.Fields(LogFields{
	//		"header": header,
	//		"err": err,
	//	}).Warn("shadowsocks: read header from connect error")
	//	return
	//}
	if n <= 0 {
		return
	}
	header = header[:n]

	/// unpack header
	Logger.Fields(LogFields{
		"data": header,
		"iv": this.CipherInst.iv,
	}).Info("check header before unpack")
	err = this.CipherInst.Decrypt(header, header) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			"header": header,
			"this.cipher.iv": this.CipherInst.iv,
			"nonce": this.CipherInst.nonce,
			"err": err,
		}).Warn("decrypt header error")
		return
	}
	this.CipherInst.SetNonce(true)

	/// get payload size
	payload_size := int(header[0])<<8 + int(header[1]) & payloadSizeMask

	/// read payload encrypted data
	payload := make([]byte, payload_size+this.CipherInst.Dec.Overhead())
	n, err = this.Conn.Read(payload)
	if err != nil && err != io.EOF {
		Logger.Fields(LogFields{
			"err": err,
		}).Warn("read data error")
		return
	}
	//payload = payload[:n]

	/// unpack payload
	//data := make([]byte, n+2)
	err = this.CipherInst.Decrypt(payload, payload) // decrypt packet data
	if err != nil {
		Logger.Fields(LogFields{
			//"data_str": string(data),
			"payload_len": len(payload),
			"payload": payload,
			"this.cipher.iv": this.CipherInst.iv,
			"nonce": this.CipherInst.nonce,
			"err": err,
		}).Warn("decrypt payload error")
		return
	}
	payload = payload[:payload_size]
	this.CipherInst.SetNonce(true)
	//////////////////////////////////////////
	//packet_data := this.data[this.doe]
	//Logger.Fields(LogFields{
	//	"data": packet_data,
	//	"iv": this.CipherInst.iv,
	//}).Info("check data before unpack")
	//if len(packet_data) <= this.iv_offset[this.doe] {
	//	Logger.Fields(LogFields{
	//		"buffer": this.buffer[this.doe].(*bytes.Buffer).Bytes(),
	//		"data": packet_data,
	//		"this.cipher.iv": this.CipherInst.iv,
	//	}).Warn("no data to unpack")
	//	return
	//}
	//
	////packet_buf := make([]byte, 2+payloadSizeMask+this.CipherInst.Dec.Overhead())
	//header_buf := make([]byte, 2+this.CipherInst.Dec.Overhead())
	//header := packet_data[this.iv_offset[this.doe]:this.iv_offset[this.doe]+2+this.CipherInst.Dec.Overhead()]
	//
	//Logger.Fields(LogFields{
	//	"data": header,
	//	"iv": this.CipherInst.iv,
	//}).Info("check header before unpack")
	//err = this.CipherInst.Decrypt(header_buf, header) // decrypt packet data
	//this.CipherInst.SetNonce(true)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"header": header,
	//		"this.cipher.iv": this.CipherInst.iv,
	//		"err": err,
	//	}).Warn("decrypt header error")
	//	return
	//}
	//Logger.Fields(LogFields{
	//	"data": header_buf,
	//	"iv": this.CipherInst.iv,
	//}).Info("check header after unpack")
	//
	//payload_size := int(header[0])<<8 + int(header[1]) & payloadSizeMask
	//
	//payload := packet_data[this.iv_offset[this.doe]+2+this.CipherInst.Dec.Overhead():]
	//
	//Logger.Fields(LogFields{
	//	"data": payload,
	//	"iv": this.CipherInst.iv,
	//}).Info("check payload before unpack")
	//data := make([]byte, payload_size)
	//err = this.CipherInst.Decrypt(data, payload) // decrypt packet data
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"data": packet_data,
	//		"payload": payload,
	//		"this.cipher.iv": this.CipherInst.iv,
	//		"err": err,
	//	}).Warn("decrypt payload error")
	//	return
	//}
	//this.CipherInst.SetNonce(true)
	_, payload = RemoveEOF(payload)
	Logger.Fields(LogFields{
		"data": string(payload),
		"iv": this.CipherInst.iv,
	}).Info("check payload after unpack")
	//this.data = data
	if payload == nil {
		return
	}

	_, err = this.buffer[this.doe].Write(payload)
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