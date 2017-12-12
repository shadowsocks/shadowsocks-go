package shadowsocks

import (
	"io"
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
	cipher Cipher
	buffer []byte
	*CryptorAead
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

func (this *PacketEnCryptorAead) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var iv []byte
	iv_offset := this.cipher.IVSize()

	if iv, err = this.cipher.NewIV(); err != nil {
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
	if cryptor, err = this.cipher.Init(iv, Encrypt); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"iv": iv,
				"err": err,
			}).Warn("init encrypt cryptor error")
		}
		///////////////////////////////////////////////
		return
	}
	this.CryptorAead = cryptor.(*CryptorAead)
	this.nonce = nil

	if len(this.buffer) < iv_offset+len(b)+this.Overhead() {
		err = errors.New("buffer size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"buffer_size": len(this.buffer),
				"size_atleast": iv_offset+len(b)+this.Overhead(),
				"err": err,
			}).Warn("buffer size error")
		}
		///////////////////////////////////////////////
		return
	}

	copy(this.buffer, iv)

	this.Encrypt(this.buffer[iv_offset:iv_offset], b)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_src": b,
			"payload_ct": this.buffer,
			"iv": iv,
			"nonce": this.getNonce(),
		}).Debug("check encrypted data")
	}
	///////////////////////////////////////////////

	n, err = this.PacketConn.WriteTo(this.buffer[:iv_offset+len(b)+this.Overhead()], addr)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		if err != nil {
			Logger.Fields(LogFields{
				"data": this.buffer[:iv_offset+len(b)+this.Overhead()],
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
	cipher Cipher
	*CryptorAead
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

func (this *PacketDeCryptorAead) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	var iv []byte
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
	iv = b[:iv_offset]
	var cryptor interface{}
	if cryptor, err = this.cipher.Init(iv, Decrypt); err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"iv": iv,
				"err": err,
			}).Warn("init decrypt cryptor error")
		}
		///////////////////////////////////////////////
		return
	}
	this.CryptorAead = cryptor.(*CryptorAead)
	this.nonce = nil

	if len(b) < iv_offset+this.Overhead() {
		err = errors.New("packet size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"size_atleast": iv_offset+this.Overhead(),
				"packet_size": len(b),
				"err": err,
			}).Warn("packet size error")
		}
		///////////////////////////////////////////////
		return
	}

	if len(this.buffer) < n+this.Overhead() {
		err = errors.New("buffer size too small")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"size_atleast": n+this.Overhead(),
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

	err = this.Decrypt(this.buffer[:0], b[iv_offset:n])
	if err != nil {
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"buffer_size": len(this.buffer),
				"buffer_size_atleast": n-iv_offset+this.Overhead(),
				"payload_ct": b[iv_offset:n],
				"iv": iv,
				"nonce": this.getNonce(),
				"err": err,
			}).Warn("decrypt data error")
		}
		///////////////////////////////////////////////
		return
	}
	n -= iv_offset + this.Overhead()
	copy(b, this.buffer[:n])
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_src": b[:n],
			"n": n,
			"payload_ct": payload_ct,
			"iv": iv,
			"nonce": this.getNonce(),
		}).Debug("check decrypted data")
	}
	///////////////////////////////////////////////

	return
}
