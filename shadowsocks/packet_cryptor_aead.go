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
	}
	return this.nonce
}

func (this *PacketEnCryptorAead) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	iv_offset := this.cipher.IVSize()

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
	if err = this.cipher.Init(this.iv, Encrypt); err != nil {
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

	this.AEAD = this.cipher.GetCryptor(Encrypt).(cipher.AEAD)
	this.nonce = nil

	if len(this.buffer) < iv_offset+len(b)+this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"buffer_size": len(this.buffer),
				"size_atleast": iv_offset+len(b)+this.AEAD.Overhead(),
				"err": err,
			}).Warn("buffer size error")
		}
		///////////////////////////////////////////////
		return
	}

	copy(this.buffer, this.iv)

	this.AEAD.Seal(this.buffer[iv_offset:iv_offset], this.getNonce(), b, nil)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_src": b,
			"payload_ct": this.buffer,
			"iv": this.iv,
			"nonce": this.getNonce(),
		}).Debug("check encrypted data")
	}
	///////////////////////////////////////////////

	n, err = this.PacketConn.WriteTo(this.buffer[:iv_offset+len(b)+this.AEAD.Overhead()], addr)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		if err != nil {
			Logger.Fields(LogFields{
				"data": this.buffer[:iv_offset+len(b)+this.AEAD.Overhead()],
				"addr": addr.String(),
				"err": err,
			}).Warn("write encrypted data to connection error")
		}
	}
	///////////////////////////////////////////////

	return
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
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	var payload_ct []byte
	///////////////////////////////////////////////
	n, addr, err = this.PacketConn.ReadFrom(b)
	if err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("read data from connection error")
		}
		///////////////////////////////////////////////
		return
	}

	iv_offset := this.cipher.IVSize()

	this.iv = b[:iv_offset]
	if err = this.cipher.Init(this.iv, Decrypt); err != nil {
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
	this.AEAD = this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
	this.nonce = nil

	if len(b) < iv_offset+this.AEAD.Overhead() {
		err = errors.New("packet size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"size_atleast": iv_offset+this.AEAD.Overhead(),
				"packet_size": len(b),
				"err": err,
			}).Warn("packet size error")
		}
		///////////////////////////////////////////////
		return
	}

	if len(this.buffer) < n+this.AEAD.Overhead() {
		err = errors.New("buffer size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"size_atleast": n+this.AEAD.Overhead(),
				"buffer_size": len(this.buffer),
				"err": err,
			}).Warn("buffer size error")
		}
		///////////////////////////////////////////////
		return
	}

	if DebugLog {
		payload_ct = make([]byte, n-iv_offset)
		copy(payload_ct, b[iv_offset:n])
	}

	_, err = this.AEAD.Open(this.buffer[:0], this.getNonce(), b[iv_offset:n], nil)
	if err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"buffer_size": len(this.buffer),
				"buffer_size_atleast": n-iv_offset+this.AEAD.Overhead(),
				"payload_ct": b[iv_offset:n],
				"iv": this.iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("decrypt data error")
		}
		///////////////////////////////////////////////
		return
	}
	n -= iv_offset + this.AEAD.Overhead()
	copy(b, this.buffer[:n])
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_src": b[:n],
			"n": n,
			"payload_ct": payload_ct,
			"iv": this.iv,
			"nonce": this.getNonce(),
		}).Debug("check decrypted data")
	}
	///////////////////////////////////////////////

	return
}
