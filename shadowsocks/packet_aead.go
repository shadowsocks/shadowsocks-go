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
		//copy(this.packet, this.Cipher.iv) // write iv to packet header
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
		//if chunk_counter < chunk_num {
		//	this.Cipher.SetNonce(true)
		//}
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
	Logger.Fields(LogFields{
		"header_src": this.packet[:2],
		"header": header,
	}).Info("check header after encrypt")
	copy(this.packet[:2+this.Cipher.Enc.Overhead()], header)

	this.Cipher.Encrypt(payload, data)
	this.Cipher.SetNonce(true)
	Logger.Fields(LogFields{
		"payload_src": string(data),
		"payload": payload,
		"iv": this.Cipher.iv,
	}).Info("check payload after encrypt")
	//_, payload = RemoveEOF(payload)
	//Logger.Fields(LogFields{
	//	"payload_len": payload_len,
	//	"packet": this.packet,
	//	"payload": payload,
	//	"iv": this.Cipher.iv,
	//}).Info("check size")


	copy(this.packet[2+this.Cipher.Enc.Overhead():], payload)
	//copy(this.packet[2:], this.Cipher.iv)
	//copy(this.packet[len(this.Cipher.iv)+2:], payload)

	_, this.packet = RemoveEOF(this.packet)
	if this.packet == nil {
		Logger.Warn("no data to write to connection")
		return
	}
	Logger.Fields(LogFields{
		"this.packet": this.packet,
		"iv": this.Cipher.iv,
	}).Info("check final packet data")
	_, err := this.writer.Write(this.packet)
	if err != nil {
		Logger.Fields(LogFields{
			"data": this.packet,
			"err": err,
		}).Warn("write data to connection error")
		return
	}
}

//func (this *PacketAead) Pack() {
//	this.packet = make([]byte, 2+this.Cipher.Enc.Overhead()+payloadSizeMask+this.Cipher.Enc.Overhead())
//	payload := this.packet[2+this.Cipher.Enc.Overhead() : 2+this.Cipher.Enc.Overhead()+payloadSizeMask]
//
//	//nonce := make([]byte, this.Cipher.Enc.NonceSize())
//	//payload := this.Cipher.Enc.Seal(nil, nonce, this.data, nil)
//	this.Cipher.Encrypt(payload, this.data)
//	payload_len, payload := RemoveEOF(payload)
//
//	this.packet[0], this.packet[1] = byte(payload_len>>8), byte(payload_len)
//
//	copy(this.packet[2:], this.Cipher.iv)
//	copy(this.packet[len(this.Cipher.iv)+2:], payload)
//
//	_, err := this.writer.Write(this.packet)
//	if err != nil {
//		Logger.Fields(LogFields{
//			"data": this.packet,
//			"err": err,
//		}).Warn("write data to connection error")
//		return
//	}
//
//	//Logger.Fields(LogFields{
//	//	"data": this.packet,
//	//	"cipher.iv": this.Cipher.iv,
//	//}).Info("check info")
//	//c.Payload = make([]byte, 2+len(data)+len(c.iv))
//	//copy(c.Payload[2:], c.iv)
//	//copy(c.Payload[len(c.iv)+2:], data)
//	///////////////////////////////////////////////////////////////
//	//err := this.Cipher.Encrypt(this.packet[this.iv_offset:], this.data) // encrypt true data and write encrypted data to rest of space in packet
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"data": this.packet,
//	//		"cipher.iv": this.Cipher.iv,
//	//		"err": err,
//	//	}).Warn("encrypt error")
//	//	return
//	//}
//	//Logger.Fields(LogFields{
//	//	"data": this.packet,
//	//	"cipher.iv": this.Cipher.iv,
//	//}).Info("check after encrypt")
//	//
//	//_, this.packet = RemoveEOF(this.packet)
//	//Logger.Fields(LogFields{
//	//	"data": this.packet,
//	//	"cipher.iv": this.Cipher.iv,
//	//}).Info("check after encrypt")
//	//
//	//if this.packet == nil {
//	//	return
//	//}
//	//
//	//_, err = this.writer.Write(this.packet)
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"data": this.packet,
//	//		"err": err,
//	//	}).Warn("write data to connection error")
//	//	return
//	//}
//	//////////////////////////////////////////////////////////////
//}

func (this *PacketAead) UnPack() {
	Logger.Fields(LogFields{
		"data": this.data,
	}).Info("check data before unpack")
	if len(this.data) <= this.iv_offset {
		Logger.Fields(LogFields{
			"data": this.data,
			"this.cipher.iv": this.Cipher.iv,
		}).Warn("no data to unpack")
		return
	}

	this.packet = make([]byte, 2+payloadSizeMask+this.Cipher.Dec.Overhead())
	//header := this.data[:2+this.Cipher.Dec.Overhead()]
	header_buf := make([]byte, 2+this.Cipher.Dec.Overhead())
	header := this.data[this.iv_offset:this.iv_offset+2+this.Cipher.Dec.Overhead()] // for testing

	Logger.Fields(LogFields{
		"iv_offset": this.iv_offset,
		"data_len": len(this.data),
		"data": this.data,
		"header": header,
	}).Info("check header data before decrypt")
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
	Logger.Fields(LogFields{
		"header_buf": header_buf,
		"data": this.data,
	}).Info("check header data after decrypt")

	//payload_size := int(this.data[0])<<8 + int(this.data[1])
	payload_size := int(header[0])<<8 + int(header[1]) & payloadSizeMask // for testing
	Logger.Fields(LogFields{
		"payload_size": payload_size,
		//"payload": payload,
		//"payload_len": len(payload),
	}).Info("check size")
	//payload := this.data[2+this.Cipher.Dec.Overhead():]
	payload := this.data[this.iv_offset+2+this.Cipher.Dec.Overhead():] // for testing

	//data := make([]byte, leakyBufSize) // get packet data from buffer first
	//// assign packet size
	//if len(payload) > len(data) { // if connect got new data
	//	data = make([]byte, len(payload))
	//} else {
	//	data = data[:len(payload)]
	//}

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

//////////////////////////////////////////////////////////////////
//func newPacketAead(cipher *CipherAead, doe DecOrEnc) *PacketAead {
//	packetObj := &PacketAead{}
//
//	packetObj.cipher = cipher
//	packetObj.cipher.Doe = doe
//	packetObj.packet = nil
//
//	return packetObj
//}
//func (this *PacketAead) initPacket(data []byte) (err error) {
//	this.data = data
//	err = this.setSalt()
//	if err != nil {
//		return
//	}
//
//	err = this.setPacket(data)
//	if err != nil {
//		return
//	}
//
//	return
//}

//func (this *PacketAead) initSalt() (err error) {
//	salt := make([]byte, this.cipher.info.ivLen)
//	if this.cipher.doe == Encrypt && this.cipher.enc == nil  {
//		if this.cipher.salt == nil {
//			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
//				Logger.Fields(LogFields{
//					"c.cipher.info": this.cipher.info,
//					"err": err,
//				}).Warn("new salt failed")
//				return err
//			}
//			this.cipher.salt = salt
//		}
//	} else if this.cipher.doe == Decrypt && this.cipher.dec == nil {
//		if _, err := io.ReadFull(this.conn.Conn, salt); err != nil {
//			Logger.Fields(LogFields{
//				"salt": salt,
//				"err": err,
//			}).Warn("shadowsocks: read salt from connect error")
//			return err
//		}
//		if len(this.cipher.salt) != 0 {
//			Logger.Fields(LogFields{
//				"c.cipher.iv": this.cipher.salt,
//			}).Warn("shadowsocks: no need to update salt")
//			return nil
//		}
//		this.cipher.salt = salt
//	}
//
//	return nil
//}
//
//func (this *PacketAead) setSalt() (error) {
//	if err := this.initSalt(); err != nil {// generating a new salt
//		return err
//	}
//
//	err := this.cipher.init() // init encrypt with salt generated previous
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (this *PacketAead) setPacket(data []byte) error {
//	if this.hold {
//		this.packet = data
//		return nil
//	}
//
//	if this.cipher.doe == Encrypt {
//		this.encrypt(data)
//	} else if this.cipher.doe == Decrypt {
//		this.decrypt(data)
//	}
//	this.packet = this.cipher.payload
//
//	return nil
//}
//
//func (this *PacketAead) getPacket() ([]byte) {
//	return this.packet
//}
//
//func (this *PacketAead) encrypt(payload []byte) {
//	salt_len := len(this.cipher.salt)
//	// assign packet size
//	packet_data := this.buff
//	dataSize := len(payload) + salt_len + 16
//	if dataSize > len(packet_data) {
//		packet_data = make([]byte, dataSize)
//	} else {
//		packet_data = packet_data[:dataSize]
//	}
//
//	this.cipher.encrypt(packet_data[salt_len:], payload) // encrypt true data and write encrypted data to rest of space in packet
//
//
//	// Put initialization vector in buffer, do a single write to send both
//	// iv and data.
//	copy(this.cipher.payload[:salt_len], this.cipher.salt) // write iv to packet header
//	//copy(packet_data[salt_len:], this.cipher.payload) // write iv to packet header
//	Logger.Fields(LogFields{
//		"packet_data": packet_data,
//		"packet": this.cipher.payload,
//		"payload": payload,
//		"payload_string": string(payload),
//	}).Info("Checking payload")
//	this.packet = this.cipher.payload
//}
//
//func (this *PacketAead) decrypt(data []byte) error {
//	packet_data := this.buff // get packet data from buffer first
//
//	// assign packet size
//	if len(data) > len(packet_data) { // if connect got new data
//		packet_data = make([]byte, len(data))
//	} else {
//		packet_data = packet_data[:len(data)]
//	}
//	n, err := this.conn.Conn.Read(packet_data) // read data from connect
//	if err != nil {
//		Logger.Fields(LogFields{
//			"n": n,
//			"packet_data": packet_data,
//			"err": err,
//		}).Warn("shadowsocks: read packet data error")
//		return err
//	}
//
//	if n > 0 { // if got any data from connect
//		this.cipher.decrypt(data, packet_data[0:n]) // decrypt packet data
//	}
//
//	this.packet = this.cipher.payload
//	return nil
//}

//func (this *PacketAead) initSalt() (err error) {
//	salt := make([]byte, this.cipher.Info.ivLen)
//	if this.cipher.Doe == Encrypt && this.cipher.Enc == nil  {
//		if this.cipher.salt == nil {
//			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
//				Logger.Fields(LogFields{
//					"c.cipher.info": this.cipher.Info,
//					"err": err,
//				}).Warn("new salt failed")
//				return err
//			}
//			this.cipher.salt = salt
//		}
//	} else if this.cipher.Doe == Decrypt && this.cipher.Dec == nil {
//		if _, err := io.ReadFull(bytes.NewReader(this.data), salt); err != nil {
//			Logger.Fields(LogFields{
//				"salt": salt,
//				"err": err,
//			}).Warn("shadowsocks: read salt from connect error")
//			return err
//		}
//		if len(this.cipher.salt) != 0 {
//			Logger.Fields(LogFields{
//				"c.cipher.salt": this.cipher.salt,
//			}).Warn("shadowsocks: no need to update salt")
//			return nil
//		}
//		this.cipher.salt = salt
//	}
//
//	return nil
//}
//
//func (this *PacketAead) setSalt() error {
//	if err := this.initSalt(); err != nil {// generating a new salt
//		return err
//	}
//
//	err := this.cipher.Init() // init encrypt with salt generated previous
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (this *PacketAead) setPacket(data []byte) error {
//	if this.cipher.Doe == Encrypt {
//		this.encrypt(data)
//	} else if this.cipher.Doe == Decrypt {
//		this.decrypt(data)
//	}
//	this.packet = this.cipher.Payload
//
//	return nil
//}
//
//func (this *PacketAead) getPacket() ([]byte) {
//	return this.packet
//}
//
//func (this *PacketAead) sendPacket() {
//	//_, err := this.conn.Write(this.cipher.salt)
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"salt": this.cipher.salt,
//	//		"err": err,
//	//	}).Warn("Send salt error")
//	//}
//	//_, err = this.conn.Write(this.packet[len(this.cipher.salt)+2:])
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"data": this.packet[len(this.cipher.salt)+2:],
//	//		"err": err,
//	//	}).Warn("Send data error")
//	//}
//}
//
//func (this *PacketAead) encrypt(payload []byte) {
//	salt_len := len(this.cipher.salt)
//	// assign packet size
//	packet_data := make([]byte, leakyBufSize)
//	dataSize := len(payload) + salt_len + 16
//	if dataSize > len(packet_data) {
//		packet_data = make([]byte, dataSize)
//	} else {
//		packet_data = packet_data[:dataSize]
//	}
//
//	// Put initialization vector in buffer, do a single write to send both
//	// iv and data.
//	//copy(packet_data, this.cipher.salt) // write iv to packet header
//	Logger.Fields(LogFields{
//		"payload_len": len(payload),
//		"payload": payload,
//		"payload_string": string(payload),
//	}).Info("Checking payload before encrypt")
//	this.cipher.Encrypt(packet_data, payload) // encrypt true data and write encrypted data to rest of space in packet
//	//this.cipher.Decrypt(packet_data, this.cipher.Payload)
//	Logger.Fields(LogFields{
//		"salt": string(this.cipher.salt),
//		"payload_unpack_len": len(this.cipher.Payload),
//		"payload_unpack": string(this.cipher.Payload),
//	}).Info("Checking payload after encrypt")
//
//	//this.packet = this.cipher.Payload
//}
//
//func (this *PacketAead) decrypt(data []byte) error {
//	packet_data := make([]byte, leakyBufSize) // get packet data from buffer first
//	//Logger.Fields(LogFields{
//	//	//"buf": packet_data,
//	//	//"buf_string": string(packet_data),
//	//	"payload": data,
//	//	"payload_string": string(data),
//	//}).Info("Checking data before decrypt")
//	//if len(data) < this.cipher.Dec.NonceSize() {
//	//	return errors.New("data not encrypted")
//	//}
//
//	// assign packet size
//	if len(data) > len(packet_data) { // if connect got new data
//		packet_data = make([]byte, len(data))
//	} else {
//		//packet_data = packet_data[:len(data)]
//	}
//	//n, err := this.conn.Conn.Read(packet_data) // read data from connect
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"n": n,
//	//		"packet_data": packet_data,
//	//		"err": err,
//	//	}).Fatal("shadowsocks: read packet data error")
//	//	return err
//	//}
//	Logger.Fields(LogFields{
//		"packet_data": string(packet_data),
//	}).Info("Checking packet_data")
//
//	if len(data) > this.cipher.Dec.NonceSize() { // if got any data from connect
//		Logger.Fields(LogFields{
//			"salt": this.cipher.salt,
//			"payload": data,
//			"payload_string": string(packet_data),
//			"packet_data": packet_data,
//		}).Info("Checking payload before decrypt")
//		this.cipher.Decrypt(packet_data, data[len(this.cipher.salt):]) // decrypt packet data
//		Logger.Fields(LogFields{
//			"payload": this.cipher.Payload,
//			"payload_string": string(this.cipher.Payload),
//		}).Info("Checking payload after decrypt")
//	} else {
//		this.cipher.Payload = nil
//	}
//
//	return nil
//}