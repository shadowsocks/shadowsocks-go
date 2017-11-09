package stream

import (
	"crypto/cipher"
	"io"
	"crypto/rand"
	"net"
	"fmt"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
	maxPacketSize = 4096 // increase it if error occurs
)

var (
	errPacketTooSmall = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
)

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

type Stream struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}
/////////////////////////////////////////////////////////////////////////////
func (this *Stream) newStream(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

// Initializes the block cipher with CFB mode, returns IV.
func (this *Stream) initEncrypt() (iv []byte, err error) {
	if this.iv == nil {
		iv = make([]byte, this.info.ivLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		this.iv = iv
	} else {
		iv = this.iv
	}
	this.enc, err = this.info.newStream(this.key, iv, Encrypt)
	return
}

func (this *Stream) initDecrypt(iv []byte) (err error) {
	this.dec, err = this.info.newStream(this.key, iv, Decrypt)
	return
}

func (this *Stream) encrypt(dst, src []byte) {
	this.enc.XORKeyStream(dst, src)
}

func (this *Stream) decrypt(dst, src []byte) {
	this.dec.XORKeyStream(dst, src)
}
/////////////////////////////////////////////////////////////////////////////

func (this *Stream) PackTCP(b []byte, cipherData []byte) (d []byte, err error)  {
	var iv []byte
	if this.enc == nil {
		iv, err = this.initEncrypt()
		if err != nil {
			return
		}
	}

	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	this.encrypt(cipherData[len(iv):], b)

	return cipherData, nil
}

func (this *Stream) UnPackTCP(c net.Conn, b []byte, cipherData []byte) (n int, err error) {
	if this.dec == nil {
		iv := make([]byte, this.info.ivLen)
		if _, err = io.ReadFull(c, iv); err != nil {
			return
		}
		if err = this.initDecrypt(iv); err != nil {
			return
		}
		if len(this.iv) == 0 {
			this.iv = iv
		}
	}

	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Read(cipherData)
	if n > 0 {
		this.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (this *Stream) PackUDP(c net.PacketConn, b []byte, dst net.Addr) (n int, err error) {
	iv, err := this.initEncrypt()
	if err != nil {
		return
	}
	packetLen := len(b) + len(iv)
	cipherData := make([]byte, packetLen)
	copy(cipherData, iv)

	this.encrypt(cipherData[len(iv):], b)
	n, err = c.WriteTo(cipherData, dst)
	return
}

func (this *Stream) UnPackUDP(c net.PacketConn, b []byte) (n int, src net.Addr, err error) {
	buf := make([]byte, 4096)
	n, src, err = c.ReadFrom(buf)
	if err != nil {
		return
	}

	if n < this.info.ivLen {
		return 0, nil, errPacketTooSmall
	}

	if len(b) < n-this.info.ivLen {
		err = errBufferTooSmall // just a warning
	}

	iv := make([]byte, this.info.ivLen)
	copy(iv, buf[:this.info.ivLen])

	if err = this.initDecrypt(iv); err != nil {
		return
	}

	this.decrypt(b[0:], buf[this.info.ivLen:n])
	n -= this.info.ivLen

	return
}

// Copy creates a new cipher at it's initial state.
func (this *Stream) Copy() *Stream {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initizliation time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// maganitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	nc := *this
	nc.enc = nil
	nc.dec = nil
	return &nc
}