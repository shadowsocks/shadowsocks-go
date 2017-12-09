package shadowsocks

import (
	"io"
	"crypto/cipher"
	"net"
	"errors"
)

type UDPAeadCryptor struct {
	Cryptor
	cipher Cipher
}

func (this *UDPAeadCryptor) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}

func (this *UDPAeadCryptor) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(UDPAeadEnCryptor).Init(this.cipher, this.GetBuffer())
	} else {
		return new(UDPAeadDeCryptor).Init(this.cipher, this.GetBuffer())
	}
}

func (this *UDPAeadCryptor) getPayloadSizeMask() int {
	return 0x3FFF // 16*1024 - 1
}

func (this *UDPAeadCryptor) GetBuffer() []byte {
	return make([]byte, this.getPayloadSizeMask())
}

/////////////////////////////////////////////////////////////////////////////////////////
type UDPAeadEnCryptor struct {
	PacketEnCryptor
	iv       []byte
	cipher   Cipher
	buffer   []byte
	cipher.AEAD
	nonce    []byte
	net.PacketConn
}

func (this *UDPAeadEnCryptor) Init(c Cipher, b []byte) PacketEnCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *UDPAeadEnCryptor) initPacket(p net.PacketConn) PacketEnCryptor {
	this.PacketConn = p

	return this
}

func (this *UDPAeadEnCryptor) setNonce(increment bool) {
	var size int
	size = this.AEAD.NonceSize()
	if !increment {
		this.nonce = make([]byte, size)
		return
	}
	for i := range this.nonce {
		this.nonce[i]++
		if this.nonce[i] != 0 {
			return
		}
	}
	return
}

func (this *UDPAeadEnCryptor) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	};
	return this.nonce
}

func (this *UDPAeadEnCryptor) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	iv_offset := this.cipher.IVSize()

	if this.iv, err = this.cipher.NewIV(); err != nil {
		return
	}
	if err = this.cipher.Init(this.iv, Encrypt); err != nil {
		return
	}

	this.AEAD = this.cipher.GetCryptor(Encrypt).(cipher.AEAD)
	this.nonce = nil

	if len(this.buffer) < iv_offset + len(b) + this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		return
	}

	copy(this.buffer, this.iv)
	Logger.Fields(LogFields{
		"payload": b,
		"payload_str": string(b),
		"payload_len": len(b),
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data before pack")
	this.AEAD.Seal(this.buffer[iv_offset:iv_offset], this.getNonce(), b, nil)
	Logger.Fields(LogFields{
		"buffer": this.buffer[:iv_offset+len(b)+this.AEAD.Overhead()],
		"payload_len": iv_offset+len(b)+this.AEAD.Overhead(),
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data after pack")

	return this.PacketConn.WriteTo(this.buffer[:iv_offset+len(b)+this.AEAD.Overhead()], addr)
}

type UDPAeadDeCryptor struct {
	PacketDeCryptor
	iv       []byte
	cipher   Cipher
	cipher.AEAD
	nonce    []byte
	buffer   []byte
	net.PacketConn
}

func (this *UDPAeadDeCryptor) Init(c Cipher, b []byte) PacketDeCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *UDPAeadDeCryptor) initPacket(p net.PacketConn) PacketDeCryptor {
	this.PacketConn = p

	return this
}

func (this *UDPAeadDeCryptor) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *UDPAeadDeCryptor) setNonce(increment bool) {
	var size int
	size = this.AEAD.NonceSize()
	if !increment {
		this.nonce = make([]byte, size)
		return
	}
	for i := range this.nonce {
		this.nonce[i]++
		if this.nonce[i] != 0 {
			return
		}
	}
	return
}

func (this *UDPAeadDeCryptor) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	}
	return this.nonce
}

func (this *UDPAeadDeCryptor) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = this.PacketConn.ReadFrom(b)
	if err != nil { return }

	iv_offset := this.cipher.IVSize()

	this.iv = b[:iv_offset]
	if err = this.cipher.Init(this.iv, Decrypt); err != nil {
		return
	}
	this.AEAD = this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
	this.nonce = nil

	if len(b) < iv_offset + this.AEAD.Overhead() {
		err = errors.New("packet size too small")
		return
	}

	if len(this.buffer) < n + this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		return
	}

	Logger.Fields(LogFields{
		"b": b[:n],
		"n": n,
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data before unpack")
	_, err = this.AEAD.Open(this.buffer[:0], this.getNonce(), b[iv_offset:n], nil)
	if err != nil {
		Logger.Fields(LogFields{
			"iv": this.iv,
			"err": err,
		}).Warn("unpack data error")
	}
	n -= iv_offset + this.AEAD.Overhead()
	copy(b, this.buffer[:n])
	Logger.Fields(LogFields{
		"buffer": this.buffer[:n],
		"n": n,
		"iv": this.iv,
		"addr": addr.String(),
	}).Info("check data after unpack")
	return
}