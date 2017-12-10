package shadowsocks

import (
	"io"
	"math"
	"errors"
)

type StreamCryptorAead struct {
	Cryptor
	cipher Cipher
}

func (this *StreamCryptorAead) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}

func (this *StreamCryptorAead) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(StreamEnCryptorAead).Init(this.cipher, this.GetBuffer())
	} else {
		return new(StreamDeCryptorAead).Init(this.cipher, this.GetBuffer())
	}
}

func (this *StreamCryptorAead) getPayloadSizeMask() int {
	return 0x3FFF // 16*1024 - 1
}

func (this *StreamCryptorAead) GetBuffer() []byte {
	return make([]byte, this.getPayloadSizeMask())
}

/////////////////////////////////////////////////////////////////////////////////////////
type StreamEnCryptorAead struct {
	StreamEnCryptor
	iv       []byte
	cipher   Cipher
	buffer   []byte
	is_begin bool
	*CryptorAead
}

func (this *StreamEnCryptorAead) Init(c Cipher, b []byte) StreamEnCryptor {
	this.cipher = c
	this.buffer = b
	this.is_begin = true

	return this
}

func (this *StreamEnCryptorAead) WriteTo(b []byte, w io.Writer) (n int, err error) {
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	// for debug
	var header_src, payload_src []byte
	///////////////////////////////////////////////
	if this.is_begin {
		if this.iv, err = this.cipher.NewIV(); err != nil {
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("get new iv error")
			}
			///////////////////////////////////////////////
			return
		}
		var cryptor interface{}
		if cryptor, err = this.cipher.Init(this.iv, Encrypt); err != nil {
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"iv": this.iv,
					"err": err,
				}).Warn("init encrypt cryptor error")
			}
			///////////////////////////////////////////////
			return
		}
		this.CryptorAead = cryptor.(*CryptorAead)
		this.is_begin = false
		if _, err = w.Write(this.iv); err != nil { // important to keep it at last
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"iv": this.iv,
					"err": err,
				}).Warn("write iv to connection error")
			}
			///////////////////////////////////////////////
			return
		}
	}

	size := len(this.buffer)
	packet_len := len(b)
	chunk_num := math.Ceil(float64(packet_len) / float64(size))
	overhead := this.Overhead()
	header_offset := 2 + overhead

	for chunk_counter := chunk_num; chunk_counter > 0; {
		payload_len := packet_len
		if payload_len > size {
			payload_len = size
		}

		packet_buf := make([]byte, header_offset+payload_len+overhead)
		payload_buf := packet_buf[header_offset: header_offset+payload_len+overhead]


		// get header
		packet_buf[0], packet_buf[1] = byte(payload_len>>8), byte(payload_len)
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			header_src = make([]byte, header_offset)
			copy(header_src, packet_buf[:2])
		}
		///////////////////////////////////////////////
		// pack header
		this.Encrypt(packet_buf[:0], packet_buf[:2])

		// get payload
		payload := b[:payload_len]

		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			payload_src = make([]byte, payload_len)
			copy(payload_src, payload)
		}
		///////////////////////////////////////////////
		// pack payload
		this.Encrypt(payload_buf[:0], payload)
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"header_src": header_src,
				"header": packet_buf[:header_offset],
				"packet_buf":  packet_buf,
				"payload_src": payload_src,
				"payload_src_str": string(payload_src),
				"payload":     packet_buf[header_offset:header_offset+payload_len+overhead],
				"payload_len": payload_len,
				"iv":          this.iv,
				"nonce": this.getNonce(),
			}).Debug("Check payload after encrypt")
		}
		///////////////////////////////////////////////

		if _, err = w.Write(packet_buf); err != nil {
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"packet_buf": packet_buf,
					"err": err,
				}).Warn("write encrypted data to connection error")
			}
			///////////////////////////////////////////////
			break
		}
		chunk_counter--
		packet_len -= payload_len
		b = b[payload_len:]
	}

	return
}

type StreamDeCryptorAead struct {
	StreamDeCryptor
	iv       []byte
	cipher   Cipher
	is_begin bool
	*CryptorAead
	buffer   []byte
}

func (this *StreamDeCryptorAead) Init(c Cipher, b []byte) StreamDeCryptor {
	this.cipher = c
	this.is_begin = true
	this.buffer = b

	return this
}

func (this *StreamDeCryptorAead) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *StreamDeCryptorAead) ReadTo(b []byte, r io.Reader) (n int, err error) {
	var header_ct, header_src, payload_ct, payload_src []byte
	if this.is_begin {
		if this.iv, err = this.getIV(r); err != nil {
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("get iv error")
			}
			///////////////////////////////////////////////
			return
		}
		var cryptor interface{}
		if cryptor, err = this.cipher.Init(this.iv, Decrypt); err != nil {
			//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
			if DebugLog {
				Logger.Fields(LogFields{
					"iv": this.iv,
					"err": err,
				}).Warn("init decrypt cryptor error")
			}
			///////////////////////////////////////////////
			return
		}
		this.CryptorAead = cryptor.(*CryptorAead)
		this.is_begin = false
	}

	buffer_size := len(this.buffer)
	overhead := this.Overhead()
	/// read header
	header_offset := 2 + overhead
	header := b[:header_offset]

	if _, err = io.ReadFull(r, header); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"header_offset": header_offset,
				"err": err,
			}).Warn("read header error")
		}
		///////////////////////////////////////////////
		return
	}

	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		header_ct = make([]byte, len(header))
		copy(header_ct, header)
	}
	///////////////////////////////////////////////

	/// unpack header
	if err = this.Decrypt(header[:0], header); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"header_ct": header_ct,
				"iv": this.iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("decrypt header error")
		}
		////////////////////////////////////////////////
		return
	}

	/// get payload size
	payload_size := int(header[0])<<8 + int(header[1])&buffer_size
	if buffer_size < payload_size {
		err = errors.New("buffer size is too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"payload_size": payload_size,
				"buffer_size": buffer_size,
				"iv": this.iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("buffer size error")
		}
		///////////////////////////////////////////////
		return
	}
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		header_src = make([]byte, 2)
		copy(header_src, header[:2])
	}
	///////////////////////////////////////////////

	/// read payload encrypted data
	payload := make([]byte, payload_size+overhead)
	if _, err = io.ReadFull(r, payload); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"header_src": header_src,
				"iv": this.iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("read payload error")
		}
		///////////////////////////////////////////////
		return
	}

	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		payload_ct = make([]byte, len(payload))
		copy(payload_ct, payload)
	}
	///////////////////////////////////////////////

	/// unpack payload
	if err = this.Decrypt(payload[:0], payload); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"header_src": header_src,
				"payload_ct": payload_ct,
				"iv": this.iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("decrypt payload error")
		}
		///////////////////////////////////////////////
		return
	}

	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		payload_src = make([]byte, payload_size)
		copy(payload_src, payload[:payload_size])
	}
	///////////////////////////////////////////////

	copy(b, payload[:payload_size])
	n = payload_size

	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"header_src": header_src,
			"payload_src": payload_src,
			"payload_ct": payload_ct,
			"b": b[:payload_size],
			"iv": this.iv,
			"nonce": this.getNonce(),
		}).Debug("check data after decrypt")
	}
	///////////////////////////////////////////////

	return
}
