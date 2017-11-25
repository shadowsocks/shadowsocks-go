package shadowsocks

import (
	"io"
	"crypto/rand"
	"bytes"
)

type Packet struct {
	writer io.Writer
	data []byte

	payload []byte
	payload_len int

	packet []byte // [IV][encrypted payload]
}

/*
 * [IV][encrypted payload]
 */
//type PacketStream struct {
//	Packet
//	cipher *CipherStream
//
//	//iv []byte
//	payload []byte
//	//enc_iv []byte
//	//dec_iv []byte
//}

/*
 * [encrypted payload length][length tag][encrypted payload][payload tag]
 */
type PacketAead struct {
	Packet
	cipher *CipherAead

	tag []byte
	tag_len int
}

////////////////////////////////////////////////////////////////////////////////
//func newPacketStream(cipher *CipherStream, doe DecOrEnc) *PacketStream {
//	p := &PacketStream{}
//
//	//p.cipher = cipher
//	//p.cipher.Doe = doe
//	//p.packet = nil
//
//	return p
//}
//func (this *PacketStream) initPacket(data []byte) (err error) {
//	this.data = data
//	err = this.setIV()
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

//func (this *PacketStream) initIV() (err error) {
//	iv := make([]byte, this.cipher.Info.ivLen)
//	if this.cipher.Doe == Encrypt && this.cipher.Enc == nil  {
//		if this.enc_iv == nil {
//			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//				Logger.Fields(LogFields{
//					"c.cipher.info": this.cipher.Info,
//					"err": err,
//				}).Warn("new iv failed")
//				return err
//			}
//			this.enc_iv = iv
//		}
//	} else if this.cipher.Doe == Decrypt && this.cipher.Dec == nil {
//		if _, err := io.ReadFull(bytes.NewReader(this.data), iv); err != nil {
//			Logger.Fields(LogFields{
//				"iv": iv,
//				"err": err,
//			}).Warn("shadowsocks: read iv from connect error")
//			return err
//		}
//		if len(this.dec_iv) != 0 {
//			Logger.Fields(LogFields{
//				"c.cipher.iv": this.dec_iv,
//			}).Warn("shadowsocks: no need to update iv")
//			return nil
//		}
//		this.dec_iv = iv
//	}
//
//	return nil
//}

//func (this *PacketStream) setIV() error {
//	if err := this.initIV(); err != nil {// generating a new iv
//		return err
//	}
//
//	if this.cipher.Doe == Encrypt {
//		this.cipher.iv = this.enc_iv
//	} else if this.cipher.Doe == Decrypt {
//		this.cipher.iv = this.dec_iv
//	}
//
//	err := this.cipher.Init() // init encrypt with iv generated previous
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (this *PacketStream) setPacket(data []byte) error {
//	//Logger.Fields(LogFields{
//	//	"iv": this.cipher.iv,
//	//	"doc": this.cipher.Doe,
//	//}).Info("Check IV")
//	if this.cipher.Doe == Encrypt {
//		this.encrypt(data)
//	} else if this.cipher.Doe == Decrypt {
//		err := this.decrypt(data)
//		if err != nil {
//			return err
//		}
//	}
//
//	return nil
//}
//
//func (this *PacketStream) getPacket() ([]byte) {
//	return this.packet
//}
//func (this *PacketStream) init(w io.Writer, data []byte, cipher *CipherStream) {
//	this.cipher = cipher
//	//this.iv = cipher.iv
//	this.payload = data
//	this.writer = w
//}
//
//func (this *PacketStream) pack() (err error) {
//	iv_len := len(this.cipher.iv)
//	// assign packet size
//	data := make([]byte, leakyBufSize)
//	dataSize := len(this.payload) + iv_len
//	if dataSize > len(data) {
//		data = make([]byte, dataSize)
//	} else {
//		data = data[:dataSize]
//	}
//
//	// Put initialization vector in buffer, do a single write to send both
//	// iv and data.
//	copy(data, this.cipher.iv) // write iv to packet header
//
//	err = this.cipher.Encrypt(data[iv_len:], this.payload) // encrypt true data and write encrypted data to rest of space in packet
//	if err != nil {
//		Logger.Fields(LogFields{
//			"payload": this.payload,
//			"iv": this.cipher.iv,
//			"err": err,
//		}).Warn("encrypt error")
//		return
//	}
//	//this.packet = packet_data
//	_, data = RemoveEOF(data)
//
//	_, err = this.writer.Write(data)
//	if err != nil {
//		Logger.Fields(LogFields{
//			"data": data,
//			"err": err,
//		}).Warn("write data to connection error")
//	}
//	return
//}
//
//func (this *PacketStream) unpack() (err error) {
//	if this.payload == nil || len(this.payload) == 0 {
//		Logger.Warn("data try to unpack is empty")
//		return
//	}
//	data := make([]byte, leakyBufSize) // get packet data from buffer first
//
//	// assign packet size
//	if len(this.payload) > len(data) { // if connect got new data
//		data = make([]byte, len(this.payload))
//	} else {
//		data = data[:len(this.payload)]
//	}
//	//n, err := this.conn.Conn.Read(packet_data) // read data from connect
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"n": n,
//	//		"packet_data": packet_data,
//	//		"err": err,
//	//	}).Warn("shadowsocks: read packet data error")
//	//	return err
//	//}
//
//	//if n > 0 { // if got any data from connect
//	//	this.cipher.Decrypt(data[0:n], packet_data[0:n]) // decrypt packet data
//	//}
//
//	Logger.Fields(LogFields{
//		"this.payload": this.payload,
//		"iv": this.cipher.iv,
//	}).Info("check before decrypt data")
//	err = this.cipher.Decrypt(data, this.payload) // decrypt packet data
//	if err != nil {
//		Logger.Fields(LogFields{
//			"payload": this.payload,
//			"iv": this.cipher.iv,
//			"err": err,
//		}).Warn("encrypt error")
//		return
//	}
//	_, data = RemoveEOF(data)
//	Logger.Fields(LogFields{
//		"data": data,
//		"data_str": string(data),
//	}).Info("check decrypt data")
//
//	_, err = this.writer.Write(data)
//	if err != nil {
//		Logger.Fields(LogFields{
//			"data": data,
//			"data_str": string(data),
//			"err": err,
//		}).Warn("write data to connection error")
//	}
//
//	return
//}

//func (this *PacketStream) encrypt(payload []byte) {
//	iv_len := len(this.cipher.iv)
//	// assign packet size
//	packet_data := make([]byte, leakyBufSize)
//	dataSize := len(payload) + iv_len
//	if dataSize > len(packet_data) {
//		packet_data = make([]byte, dataSize)
//	} else {
//		packet_data = packet_data[:dataSize]
//	}
//
//	// Put initialization vector in buffer, do a single write to send both
//	// iv and data.
//	copy(packet_data, this.cipher.iv) // write iv to packet header
//
//	this.cipher.Encrypt(packet_data[iv_len:], payload) // encrypt true data and write encrypted data to rest of space in packet
//	this.packet = packet_data
//}
//
//func (this *PacketStream) decrypt(data []byte) error {
//	packet_data := make([]byte, leakyBufSize) // get packet data from buffer first
//
//	// assign packet size
//	if len(data) > len(packet_data) { // if connect got new data
//		packet_data = make([]byte, len(data))
//	} else {
//		packet_data = packet_data[:len(data)]
//	}
//	//n, err := this.conn.Conn.Read(packet_data) // read data from connect
//	//if err != nil {
//	//	Logger.Fields(LogFields{
//	//		"n": n,
//	//		"packet_data": packet_data,
//	//		"err": err,
//	//	}).Warn("shadowsocks: read packet data error")
//	//	return err
//	//}
//
//	//if n > 0 { // if got any data from connect
//	//	this.cipher.Decrypt(data[0:n], packet_data[0:n]) // decrypt packet data
//	//}
//
//	this.cipher.Decrypt(packet_data, data[len(this.cipher.iv):]) // decrypt packet data
//
//	this.packet = packet_data
//	return nil
//}
//////////////////////////////////////////////////////////////////
func newPacketAead(cipher *CipherAead, doe DecOrEnc) *PacketAead {
	packetObj := &PacketAead{}

	packetObj.cipher = cipher
	packetObj.cipher.Doe = doe
	packetObj.packet = nil

	return packetObj
}
func (this *PacketAead) initPacket(data []byte) (err error) {
	this.data = data
	err = this.setSalt()
	if err != nil {
		return
	}

	err = this.setPacket(data)
	if err != nil {
		return
	}

	return
}

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

func (this *PacketAead) initSalt() (err error) {
	salt := make([]byte, this.cipher.Info.ivLen)
	if this.cipher.Doe == Encrypt && this.cipher.Enc == nil  {
		if this.cipher.salt == nil {
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				Logger.Fields(LogFields{
					"c.cipher.info": this.cipher.Info,
					"err": err,
				}).Warn("new salt failed")
				return err
			}
			this.cipher.salt = salt
		}
	} else if this.cipher.Doe == Decrypt && this.cipher.Dec == nil {
		if _, err := io.ReadFull(bytes.NewReader(this.data), salt); err != nil {
			Logger.Fields(LogFields{
				"salt": salt,
				"err": err,
			}).Warn("shadowsocks: read salt from connect error")
			return err
		}
		if len(this.cipher.salt) != 0 {
			Logger.Fields(LogFields{
				"c.cipher.salt": this.cipher.salt,
			}).Warn("shadowsocks: no need to update salt")
			return nil
		}
		this.cipher.salt = salt
	}

	return nil
}

func (this *PacketAead) setSalt() error {
	if err := this.initSalt(); err != nil {// generating a new salt
		return err
	}

	err := this.cipher.Init() // init encrypt with salt generated previous
	if err != nil {
		return err
	}

	return nil
}

func (this *PacketAead) setPacket(data []byte) error {
	if this.cipher.Doe == Encrypt {
		this.encrypt(data)
	} else if this.cipher.Doe == Decrypt {
		this.decrypt(data)
	}
	this.packet = this.cipher.Payload

	return nil
}

func (this *PacketAead) getPacket() ([]byte) {
	return this.packet
}

func (this *PacketAead) sendPacket() {
	//_, err := this.conn.Write(this.cipher.salt)
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"salt": this.cipher.salt,
	//		"err": err,
	//	}).Warn("Send salt error")
	//}
	//_, err = this.conn.Write(this.packet[len(this.cipher.salt)+2:])
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"data": this.packet[len(this.cipher.salt)+2:],
	//		"err": err,
	//	}).Warn("Send data error")
	//}
}

func (this *PacketAead) encrypt(payload []byte) {
	salt_len := len(this.cipher.salt)
	// assign packet size
	packet_data := make([]byte, leakyBufSize)
	dataSize := len(payload) + salt_len + 16
	if dataSize > len(packet_data) {
		packet_data = make([]byte, dataSize)
	} else {
		packet_data = packet_data[:dataSize]
	}

	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	//copy(packet_data, this.cipher.salt) // write iv to packet header
	Logger.Fields(LogFields{
		"payload_len": len(payload),
		"payload": payload,
		"payload_string": string(payload),
	}).Info("Checking payload before encrypt")
	this.cipher.Encrypt(packet_data, payload) // encrypt true data and write encrypted data to rest of space in packet
	//this.cipher.Decrypt(packet_data, this.cipher.Payload)
	Logger.Fields(LogFields{
		"salt": string(this.cipher.salt),
		"payload_unpack_len": len(this.cipher.Payload),
		"payload_unpack": string(this.cipher.Payload),
	}).Info("Checking payload after encrypt")

	//this.packet = this.cipher.Payload
}

func (this *PacketAead) decrypt(data []byte) error {
	packet_data := make([]byte, leakyBufSize) // get packet data from buffer first
	//Logger.Fields(LogFields{
	//	//"buf": packet_data,
	//	//"buf_string": string(packet_data),
	//	"payload": data,
	//	"payload_string": string(data),
	//}).Info("Checking data before decrypt")
	//if len(data) < this.cipher.Dec.NonceSize() {
	//	return errors.New("data not encrypted")
	//}

	// assign packet size
	if len(data) > len(packet_data) { // if connect got new data
		packet_data = make([]byte, len(data))
	} else {
		//packet_data = packet_data[:len(data)]
	}
	//n, err := this.conn.Conn.Read(packet_data) // read data from connect
	//if err != nil {
	//	Logger.Fields(LogFields{
	//		"n": n,
	//		"packet_data": packet_data,
	//		"err": err,
	//	}).Fatal("shadowsocks: read packet data error")
	//	return err
	//}
	Logger.Fields(LogFields{
		"packet_data": string(packet_data),
	}).Info("Checking packet_data")

	if len(data) > this.cipher.Dec.NonceSize() { // if got any data from connect
		Logger.Fields(LogFields{
			"salt": this.cipher.salt,
			"payload": data,
			"payload_string": string(packet_data),
			"packet_data": packet_data,
		}).Info("Checking payload before decrypt")
		this.cipher.Decrypt(packet_data, data[len(this.cipher.salt):]) // decrypt packet data
		Logger.Fields(LogFields{
			"payload": this.cipher.Payload,
			"payload_string": string(this.cipher.Payload),
		}).Info("Checking payload after decrypt")
	} else {
		this.cipher.Payload = nil
	}

	return nil
}