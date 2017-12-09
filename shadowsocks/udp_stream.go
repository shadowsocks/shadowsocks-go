package shadowsocks

import (
	"crypto/cipher"
	"net"
	"errors"
)

type UDPStreamCryptor struct {
	Cryptor
	cipher Cipher
}

func (this *UDPStreamCryptor) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(UDPStreamEnCryptor).Init(this.cipher, this.GetBuffer())
	} else {
		return new(UDPStreamDeCryptor).Init(this.cipher, this.GetBuffer())
	}
}
/////////////////////////////////////////////////////////////////////////////////////////
type UDPStreamEnCryptor struct {
	PacketEnCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	cipher.Stream
	net.PacketConn
}

func (this *UDPStreamEnCryptor) Init(c Cipher, b []byte) PacketEnCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *UDPStreamEnCryptor) initPacket(p net.PacketConn) PacketEnCryptor {
	this.PacketConn = p

	return this
}

func (this *UDPStreamEnCryptor) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	iv_offset := this.cipher.IVSize()

	if this.iv, err = this.cipher.NewIV(); err != nil { return }
	if err = this.cipher.Init(this.iv, Encrypt); err != nil { return }
	this.Stream = this.cipher.GetCryptor(Encrypt).(cipher.Stream)

	copy(this.buffer, this.iv)

	payload_len := len(b)
	payload := this.buffer[iv_offset:iv_offset+payload_len]
	Logger.Fields(LogFields{
		"b": b,
		"b_str": string(b),
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data before pack")
	this.Stream.XORKeyStream(payload, b)
	Logger.Fields(LogFields{
		"payload": payload,
		"iv": this.iv,
		"buffer": this.buffer[:iv_offset+payload_len],
		"addr": addr.String(),
	}).Info("check data after pack")

	return this.PacketConn.WriteTo(this.buffer[:iv_offset+payload_len], addr)
}

type UDPStreamDeCryptor struct {
	PacketDeCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	cipher.Stream
	net.PacketConn
}

func (this *UDPStreamDeCryptor) Init(c Cipher, b []byte) PacketDeCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *UDPStreamDeCryptor) initPacket(p net.PacketConn) PacketDeCryptor {
	this.PacketConn = p

	return this
}

func (this *UDPStreamDeCryptor) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = this.PacketConn.ReadFrom(b)
	if err != nil { return }

	iv_offset := this.cipher.IVSize()
	if n < iv_offset {
		err = errors.New("data seems no need to unpack")
		return
	}

	this.iv = b[:iv_offset]

	if err = this.cipher.Init(this.iv, Decrypt); err != nil { return }
	this.Stream = this.cipher.GetCryptor(Decrypt).(cipher.Stream)

	payload := b[iv_offset:n]
	Logger.Fields(LogFields{
		"b": b[:n],
		"n": n,
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data before unpack")
	this.Stream.XORKeyStream(payload, payload)
	copy(b, payload)
	n -= iv_offset
	Logger.Fields(LogFields{
		"payload": payload,
		"payload_str": string(payload),
		"addr": addr.String(),
		"iv": this.iv,
	}).Info("check data after unpack")

	return
}

/////////////////////////////////////////////////////////////////////////////////////////
func (this *UDPStreamCryptor) getPayloadSizeMask() int {
	return 1024
	//return 32*1024
}

func (this *UDPStreamCryptor) GetBuffer() ([]byte) {
	return make([]byte, this.getPayloadSizeMask())
}

func (this *UDPStreamCryptor) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}