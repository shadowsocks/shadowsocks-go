package shadowsocks

import (
	"io"
	"crypto/rand"
)

type Packet struct {
	conn *Conn
	buff []byte
	hold bool

	ptype DecOrEnc
	payload []byte
	payload_len int

	packet []byte // [IV][encrypted payload]
}

/*
 * [IV][encrypted payload]
 */
type PacketStream struct {
	Packet
	cipher *CipherStream

	//iv []byte
	//iv_len int
}

/*
 * [encrypted payload length][length tag][encrypted payload][payload tag]
 */
type PacketAead struct {
	*Packet

	tag []byte
	tag_len int
}

////////////////////////////////////////////////////////////////////////////////
func newPacketStream(conn *Conn, ptype DecOrEnc) *PacketStream {
	packetObj := &PacketStream{}

	packetObj.hold = false
	packetObj.ptype = ptype
	packetObj.conn = conn
	packetObj.cipher = conn.cipher.(*CipherStream)
	packetObj.packet = nil
	packetObj.buff = conn.buffer.Get()

	return packetObj
}
func (this *PacketStream) initPacket(data []byte) *PacketStream {
	if this.setIV() != nil {
		this.hold = true
	}

	this.setPacket(data)

	return this
}

func (this *PacketStream) initIV() (err error) {
	iv := make([]byte, this.cipher.info.ivLen)
	if this.ptype == Encrypt && this.cipher.enc == nil  {
		if this.cipher.iv == nil {
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				Logger.Fields(LogFields{
					"c.cipher.info": this.cipher.info,
					"err": err,
				}).Warn("new iv failed")
				return err
			}
			this.cipher.iv = iv
		}
	} else if this.ptype == Decrypt && this.cipher.dec == nil {
		if _, err := io.ReadFull(this.conn.Conn, iv); err != nil {
			Logger.Fields(LogFields{
				"iv": iv,
				"err": err,
			}).Warn("shadowsocks: read iv from connect error")
			return err
		}
		if len(this.cipher.iv) != 0 {
			Logger.Fields(LogFields{
				"c.cipher.iv": this.cipher.iv,
			}).Warn("shadowsocks: no need to update iv")
			return nil
		}
		this.cipher.iv = iv
	}

	return nil
}

func (this *PacketStream) setIV() error {
	if err := this.initIV(); err != nil {// generating a new iv
		return err
	}

	err := this.cipher.init(this.ptype) // init encrypt with iv generated previous
	if err != nil {
		return err
	}

	return nil
}

func (this *PacketStream) setPacket(data []byte) error {
	if this.hold {
		this.packet = nil
		return nil
	}

	if this.ptype == Encrypt {
		this.encrypt(data)
	} else if this.ptype == Decrypt {
		this.decrypt(data)
	}

	return nil
}

func (this *PacketStream) getPacket() ([]byte, error) {
	return this.packet, nil
}

func (this *PacketStream) encrypt(payload []byte) {
	iv_len := this.cipher.iv_len
	// assign packet size
	packet_data := this.buff
	dataSize := len(payload) + iv_len
	if dataSize > len(packet_data) {
		packet_data = make([]byte, dataSize)
	} else {
		packet_data = packet_data[:dataSize]
	}

	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	copy(packet_data, this.cipher.iv) // write iv to packet header

	this.cipher.encrypt(packet_data[iv_len:], payload) // encrypt true data and write encrypted data to rest of space in packet
	this.packet = packet_data
}

func (this *PacketStream) decrypt(data []byte) error {
	packet_data := this.buff // get packet data from buffer first

	// assign packet size
	if len(data) > len(packet_data) { // if connect got new data
		packet_data = make([]byte, len(data))
	} else {
		packet_data = packet_data[:len(data)]
	}
	n, err := this.conn.Conn.Read(packet_data) // read data from connect
	if err != nil {
		Logger.Fields(LogFields{
			"n": n,
			"packet_data": packet_data,
			"err": err,
		}).Warn("shadowsocks: read packet data error")
		return err
	}

	if n > 0 { // if got any data from connect
		this.cipher.decrypt(data[0:n], packet_data[0:n]) // decrypt packet data
	}

	this.packet = data[0:n]
	return nil
}