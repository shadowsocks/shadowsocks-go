package shadowsocks

import (
	"io"
	"crypto/cipher"
)

type StreamCryptorStream struct {
	Cryptor
	cipher Cipher
}

func (this *StreamCryptorStream) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(StreamEnCryptorStream).Init(this.cipher, this.GetBuffer())
	} else {
		return new(StreamDeCryptorStream).Init(this.cipher, this.GetBuffer())
	}
}

func (this *StreamCryptorStream) getPayloadSizeMask() int {
	return 1024
	//return 32*1024
}

func (this *StreamCryptorStream) GetBuffer() ([]byte) {
	return make([]byte, this.getPayloadSizeMask())
}

func (this *StreamCryptorStream) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}
/////////////////////////////////////////////////////////////////////////////////////////
type StreamEnCryptorStream struct {
	StreamEnCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	is_begin bool
	cipher.Stream
}

func (this *StreamEnCryptorStream) Init(c Cipher, b []byte) StreamEnCryptor {
	this.cipher = c
	this.buffer = b
	this.is_begin = true

	return this
}

func (this *StreamEnCryptorStream) WriteTo(b []byte, w io.Writer) (n int, err error) {
	if this.is_begin {
		if this.iv, err = this.cipher.NewIV(); err != nil { return }
		if err = this.cipher.Init(this.iv, Encrypt); err != nil { return }
		if _, err = w.Write(this.iv); err != nil { return }
		this.Stream = this.cipher.GetCryptor(Encrypt).(cipher.Stream)
		this.is_begin = false
	}

	payload_len := len(b)
	payload := this.buffer[:payload_len]
	this.Stream.XORKeyStream(payload, b)

	return w.Write(payload)
}

type StreamDeCryptorStream struct {
	StreamDeCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	is_begin bool
	cipher.Stream
}

func (this *StreamDeCryptorStream) Init(c Cipher, b []byte) StreamDeCryptor {
	this.cipher = c
	this.is_begin = true
	this.buffer = b

	return this
}

func (this *StreamDeCryptorStream) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *StreamDeCryptorStream) ReadTo(b []byte, r io.Reader) (n int, err error) {
	if this.is_begin {
		if this.iv, err = this.getIV(r); err != nil { return }
		if err = this.cipher.Init(this.iv, Decrypt); err != nil { return }
		this.Stream = this.cipher.GetCryptor(Decrypt).(cipher.Stream)
		this.is_begin = false
	}
	if n, err = r.Read(b); err != nil { return }
	if n > 0 {
		payload := b[:n]
		this.Stream.XORKeyStream(payload, payload)
	}
	return
}