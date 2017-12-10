package shadowsocks

import (
	"crypto/cipher"
	"net"
	"errors"
)

type PacketCryptorStream struct {
	Cryptor
	cipher Cipher
}

func (this *PacketCryptorStream) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(PacketEnCryptorStream).Init(this.cipher, this.GetBuffer())
	} else {
		return new(PacketDeCryptorStream).Init(this.cipher, this.GetBuffer())
	}
}

func (this *PacketCryptorStream) getPayloadSizeMask() int {
	return 1024
	//return 32*1024
}

func (this *PacketCryptorStream) GetBuffer() ([]byte) {
	return make([]byte, this.getPayloadSizeMask())
}

func (this *PacketCryptorStream) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}

/////////////////////////////////////////////////////////////////////////////////////////
type PacketEnCryptorStream struct {
	PacketEnCryptor
	iv     []byte
	cipher Cipher
	buffer []byte
	cipher.Stream
	net.PacketConn
}

func (this *PacketEnCryptorStream) Init(c Cipher, b []byte) PacketEnCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *PacketEnCryptorStream) initPacket(p net.PacketConn) PacketEnCryptor {
	this.PacketConn = p

	return this
}

func (this *PacketEnCryptorStream) WriteTo(b []byte, addr net.Addr) (n int, err error) {
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
	this.Stream = this.cipher.GetCryptor(Encrypt).(cipher.Stream)

	copy(this.buffer, this.iv)

	payload_len := len(b)
	payload := this.buffer[iv_offset:iv_offset+payload_len]

	this.Stream.XORKeyStream(payload, b)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_ct": payload,
			"payload_src": b,
			"payload_src_str": string(b),
			"iv": this.iv,
		}).Debug("check encrypted data")
	}
	///////////////////////////////////////////////

	n, err = this.PacketConn.WriteTo(this.buffer[:iv_offset+payload_len], addr)
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		if err != nil {
			Logger.Fields(LogFields{
				"data": this.buffer[:iv_offset+payload_len],
				"addr": addr.String(),
				"err": err,
			}).Warn("write encrypted data to connection error")
		}
	}
	///////////////////////////////////////////////

	return
}

type PacketDeCryptorStream struct {
	PacketDeCryptor
	iv     []byte
	cipher Cipher
	buffer []byte
	cipher.Stream
	net.PacketConn
}

func (this *PacketDeCryptorStream) Init(c Cipher, b []byte) PacketDeCryptor {
	this.cipher = c
	this.buffer = b

	return this
}

func (this *PacketDeCryptorStream) initPacket(p net.PacketConn) PacketDeCryptor {
	this.PacketConn = p

	return this
}

func (this *PacketDeCryptorStream) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	var payload_ct []byte // for debug
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
	if n < iv_offset {
		err = errors.New("data seems no need to unpack")
		//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		if DebugLog {
			Logger.Fields(LogFields{
				"data_size": n,
				"size_atleast": iv_offset,
				"err": err,
			}).Warn("data size too small error")
		}
		///////////////////////////////////////////////
		return
	}

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
	this.Stream = this.cipher.GetCryptor(Decrypt).(cipher.Stream)

	payload := b[iv_offset:n]
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		payload_ct = make([]byte, len(payload))
		copy(payload_ct, payload)
	}
	///////////////////////////////////////////////

	this.Stream.XORKeyStream(payload, payload)
	copy(b, payload)
	n -= iv_offset
	//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
	if DebugLog {
		Logger.Fields(LogFields{
			"payload_ct": payload_ct,
			"payload_src": payload,
			"payload_src_str": string(payload),
			"iv": this.iv,
		}).Debug("check decrypted data")
	}
	///////////////////////////////////////////////

	return
}
