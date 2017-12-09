package shadowsocks

import (
	"io"
	"crypto/cipher"
	"net"
	"errors"
)

type PacketCryptorAead struct {
	Cryptor
	cipher Cipher
}

func (this *PacketCryptorAead) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}

func (this *PacketCryptorAead) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(PacketEnCryptorAead).Init(this.cipher, this.GetBuffer())
	} else {
		return new(PacketDeCryptorAead).Init(this.cipher, this.GetBuffer())
	}
}

func (this *PacketCryptorAead) getPayloadSizeMask() int {
	return 0x3FFF // 16*1024 - 1
}

func (this *PacketCryptorAead) GetBuffer() []byte {
	return make([]byte, this.getPayloadSizeMask())
}

/////////////////////////////////////////////////////////////////////////////////////////
type PacketEnCryptorAead struct {
	PacketEnCryptor
	iv     []byte
	cipher Cipher
	buffer []byte
	cipher.AEAD
	nonce  []byte
	net.PacketConn
}

func (this *PacketEnCryptorAead) Init(c Cipher, b []byte) PacketEnCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *PacketEnCryptorAead) initPacket(p net.PacketConn) PacketEnCryptor {
	this.PacketConn = p

	return this
}

func (this *PacketEnCryptorAead) setNonce(increment bool) {
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

func (this *PacketEnCryptorAead) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	};
	return this.nonce
}

func (this *PacketEnCryptorAead) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	iv_offset := this.cipher.IVSize()

	if this.iv, err = this.cipher.NewIV(); err != nil {
		return
	}
	if err = this.cipher.Init(this.iv, Encrypt); err != nil {
		return
	}

	this.AEAD = this.cipher.GetCryptor(Encrypt).(cipher.AEAD)
	this.nonce = nil

	if len(this.buffer) < iv_offset+len(b)+this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		return
	}

	copy(this.buffer, this.iv)

	this.AEAD.Seal(this.buffer[iv_offset:iv_offset], this.getNonce(), b, nil)

	return this.PacketConn.WriteTo(this.buffer[:iv_offset+len(b)+this.AEAD.Overhead()], addr)
}

type PacketDeCryptorAead struct {
	PacketDeCryptor
	iv     []byte
	cipher Cipher
	cipher.AEAD
	nonce  []byte
	buffer []byte
	net.PacketConn
}

func (this *PacketDeCryptorAead) Init(c Cipher, b []byte) PacketDeCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *PacketDeCryptorAead) initPacket(p net.PacketConn) PacketDeCryptor {
	this.PacketConn = p

	return this
}

func (this *PacketDeCryptorAead) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *PacketDeCryptorAead) setNonce(increment bool) {
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

func (this *PacketDeCryptorAead) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	}
	return this.nonce
}

func (this *PacketDeCryptorAead) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = this.PacketConn.ReadFrom(b)
	if err != nil {
		return
	}

	iv_offset := this.cipher.IVSize()

	this.iv = b[:iv_offset]
	if err = this.cipher.Init(this.iv, Decrypt); err != nil {
		return
	}
	this.AEAD = this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
	this.nonce = nil

	if len(b) < iv_offset+this.AEAD.Overhead() {
		err = errors.New("packet size too small")
		return
	}

	if len(this.buffer) < n+this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		return
	}

	_, err = this.AEAD.Open(this.buffer[:0], this.getNonce(), b[iv_offset:n], nil)
	if err != nil {
		Logger.Fields(LogFields{
			"iv":  this.iv,
			"err": err,
		}).Warn("unpack data error")
		return
	}
	n -= iv_offset + this.AEAD.Overhead()
	copy(b, this.buffer[:n])

	return
}
