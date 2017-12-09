package shadowsocks

import (
	"io"
	"crypto/cipher"
)

type TCPStreamCryptor struct {
	Cryptor
	cipher Cipher
}

func (this *TCPStreamCryptor) initCryptor(doe DecOrEnc) interface{} {
	if doe == Encrypt {
		return new(TCPStreamEnCryptor).Init(this.cipher, this.GetBuffer())
	} else {
		return new(TCPStreamDeCryptor).Init(this.cipher, this.GetBuffer())
	}
}
/////////////////////////////////////////////////////////////////////////////////////////
type TCPStreamEnCryptor struct {
	EnCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	is_begin bool
	cipher.Stream
}

func (this *TCPStreamEnCryptor) Init(c Cipher, b []byte) EnCryptor {
	this.cipher = c
	this.buffer = b
	this.is_begin = true

	return this
}

func (this *TCPStreamEnCryptor) WriteTo(b []byte, w io.Writer) (n int, err error) {
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

type TCPStreamDeCryptor struct {
	DeCryptor
	iv []byte
	cipher Cipher
	buffer []byte
	is_begin bool
	cipher.Stream
}

func (this *TCPStreamDeCryptor) Init(c Cipher, b []byte) DeCryptor {
	this.cipher = c
	this.is_begin = true
	this.buffer = b

	return this
}

func (this *TCPStreamDeCryptor) getIV(r io.Reader) (iv []byte, err error) {
	iv = make([]byte, this.cipher.IVSize())
	_, err = io.ReadFull(r, iv)
	return
}

func (this *TCPStreamDeCryptor) ReadTo(b []byte, r io.Reader) (n int, err error) {
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

/////////////////////////////////////////////////////////////////////////////////////////
func (this *TCPStreamCryptor) getPayloadSizeMask() int {
	return 1024
	//return 32*1024
}

func (this *TCPStreamCryptor) GetBuffer() ([]byte) {
	return make([]byte, this.getPayloadSizeMask())
}

func (this *TCPStreamCryptor) init(cipher Cipher) Cryptor {
	this.cipher = cipher

	return this
}