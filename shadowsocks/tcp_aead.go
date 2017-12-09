package shadowsocks

import (
	"io"
	"crypto/cipher"
	"math"
	"errors"
)

type TCPAeadCryptor struct {
	Cryptor
	cipher Cipher
}

func (this *TCPAeadCryptor) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}

func (this *TCPAeadCryptor) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(TCPAeadEnCryptor).Init(this.cipher, this.GetBuffer())
	} else {
		return new(TCPAeadDeCryptor).Init(this.cipher, this.GetBuffer())
	}
}

func (this *TCPAeadCryptor) getPayloadSizeMask() int {
	return 0x3FFF // 16*1024 - 1
}

func (this *TCPAeadCryptor) GetBuffer() []byte {
	return make([]byte, this.getPayloadSizeMask())
}

/////////////////////////////////////////////////////////////////////////////////////////
type TCPAeadEnCryptor struct {
	EnCryptor
	iv       []byte
	cipher   Cipher
	buffer   []byte
	is_begin bool
	cipher.AEAD
	nonce    []byte
}

func (this *TCPAeadEnCryptor) Init(c Cipher, b []byte) EnCryptor {
	this.cipher = c
	this.buffer = b
	this.is_begin = true

	return this
}

func (this *TCPAeadEnCryptor) setNonce(increment bool) {
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

func (this *TCPAeadEnCryptor) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	};
	return this.nonce
}

func (this *TCPAeadEnCryptor) WriteTo(b []byte, w io.Writer) (n int, err error) {
	if this.is_begin {
		if this.iv, err = this.cipher.NewIV(); err != nil {
			return
		}
		if err = this.cipher.Init(this.iv, Encrypt); err != nil {
			return
		}
		if _, err = w.Write(this.iv); err != nil {
			return
		}
		this.AEAD = this.cipher.GetCryptor(Encrypt).(cipher.AEAD)
		this.nonce = nil
		this.is_begin = false
	}

	cryptor := this.AEAD
	size := len(this.buffer)
	packet_len := len(b)
	chunk_num := math.Ceil(float64(packet_len) / float64(size))
	overhead := cryptor.Overhead()
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

		// pack header
		cryptor.Seal(packet_buf[:0], this.getNonce(), packet_buf[:2], nil)
		this.setNonce(true)

		// get payload
		payload := b[:payload_len]

		// pack payload
		cryptor.Seal(payload_buf[:0], this.getNonce(), payload, nil)
		this.setNonce(true)

		if _, err = w.Write(packet_buf); err != nil {
			break
		}
		chunk_counter--
		packet_len -= payload_len
		b = b[payload_len:]
	}

	return
}

type TCPAeadDeCryptor struct {
	DeCryptor
	iv       []byte
	cipher   Cipher
	is_begin bool
	cipher.AEAD
	nonce    []byte
	buffer   []byte
}

func (this *TCPAeadDeCryptor) Init(c Cipher, b []byte) DeCryptor {
	this.cipher = c
	this.is_begin = true
	this.buffer = b

	return this
}

func (this *TCPAeadDeCryptor) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *TCPAeadDeCryptor) setNonce(increment bool) {
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

func (this *TCPAeadDeCryptor) getNonce() []byte {
	if this.nonce == nil {
		this.setNonce(false)
	}
	return this.nonce
}

func (this *TCPAeadDeCryptor) ReadTo(b []byte, r io.Reader) (n int, err error) {
	if this.is_begin {
		if this.iv, err = this.getIV(r); err != nil {
			return
		}
		if err = this.cipher.Init(this.iv, Decrypt); err != nil {
			return
		}
		this.AEAD = this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
		this.is_begin = false
		this.nonce = nil
	}
	/////////////////////////////////////////////////////////////////
	buffer_size := len(this.buffer)
	cryptor := this.cipher.GetCryptor(Decrypt).(cipher.AEAD)
	overhead := cryptor.Overhead()
	/// read header
	header_offset := 2 + overhead
	header := b[:header_offset]

	if _, err = io.ReadFull(r, header); err != nil {
		return
	}

	/// unpack header
	if _, err = this.AEAD.Open(header[:0], this.getNonce(), header, nil); err != nil { return }
	this.setNonce(true)

	/// get payload size
	payload_size := int(header[0])<<8 + int(header[1])&buffer_size
	if buffer_size < payload_size {
		err = errors.New("buffer size is too small")
		return
	}

	/// read payload encrypted data
	payload := make([]byte, payload_size+overhead)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}

	/// unpack payload
	if _, err = this.AEAD.Open(payload[:0], this.getNonce(), payload, nil); err != nil { return }
	this.setNonce(true)

	copy(b, payload[:payload_size])
	n = payload_size

	return
}