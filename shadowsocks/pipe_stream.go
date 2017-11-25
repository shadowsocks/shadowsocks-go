package shadowsocks

import (
	"net"
	"io"
	"bytes"
	"errors"
)

type PipeStream struct {
	Pipe
	Cipher *CipherStream
	data []byte
}

func (this *PipeStream) Init(c net.Conn, buf []byte) (err error) {
	// set iv or get iv and split payload from packet data
	SetReadTimeout(c)
	n, err := c.Read(buf)
	if err != nil {
		return
	}

	if n > 0 {
		this.data = buf[:n]
		return
	}

	err = errors.New("no data from connection")

	return
}

func (this *PipeStream) getIV() (iv []byte, err error) {
	iv = make([]byte, this.Cipher.Info.ivLen)
	if _, err = io.ReadFull(bytes.NewReader(this.data), iv); err != nil {
		Logger.Fields(LogFields{
			"iv": iv,
			"err": err,
		}).Warn("shadowsocks: read iv from connect error")
		return
	}

	return
}

func (this *PipeStream) Pack(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	offset := 0
	for {
		err := this.Init(src, buf)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("init ss connection error")
			return
		}

		iv_len := this.Cipher.Info.ivLen
		// assign packet size
		var data []byte
		dataSize := len(this.data) + iv_len
		if dataSize > len(data) {
			data = make([]byte, dataSize)
		} else {
			data = data[:dataSize]
		}

		if this.Cipher.Enc == nil {
			this.Cipher.Init(nil, Encrypt)
			offset = len(this.Cipher.iv)
			copy(data, this.Cipher.iv) // write iv to packet header
		} else {
			offset = 0
		}

		err = this.Cipher.Encrypt(data[offset:], this.data) // encrypt true data and write encrypted data to rest of space in packet
		if err != nil {
			Logger.Fields(LogFields{
				"data": data,
				"cipher.iv": this.Cipher.iv,
				"err": err,
			}).Warn("encrypt error")
			return
		}

		_, data = RemoveEOF(data)

		if data == nil {
			continue
		}

		_, err = dst.Write(data)
		if err != nil {
			Logger.Fields(LogFields{
				"data": data,
				"err": err,
			}).Warn("write data to connection error")
			return
		}
	}
}

func (this *PipeStream) UnPack(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	offset := 0
	for {
		err := this.Init(src, buf)
		if err != nil {
			Logger.Fields(LogFields{
				"err": err,
			}).Warn("init ss connection error")
			return
		}

		if this.Cipher.Dec == nil {
			iv, err := this.getIV()
			if err != nil {
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("get iv from connection error")
				return
			}

			offset = len(iv)
			err = this.Cipher.Init(iv, Decrypt)
			if err != nil {
				Logger.Fields(LogFields{
					"iv": iv,
					"this.cipher.iv": this.Cipher.iv,
					"err": err,
				}).Warn("decrypt init error")
				return
			}
		} else {
			offset = 0
		}

		payload := this.data[offset:]

		data := make([]byte, leakyBufSize) // get packet data from buffer first
		// assign packet size
		if len(payload) > len(data) { // if connect got new data
			data = make([]byte, len(payload))
		} else {
			data = data[:len(payload)]
		}

		err = this.Cipher.Decrypt(data, payload) // decrypt packet data
		if err != nil {
			Logger.Fields(LogFields{
				"payload": payload,
				"this.cipher.iv": this.Cipher.iv,
				"err": err,
			}).Warn("encrypt error")
			return
		}
		_, data = RemoveEOF(data)
		if data == nil {
			continue
		}

		_, err = dst.Write(data)
		if err != nil {
			Logger.Fields(LogFields{
				"data": data,
				"data_str": string(data),
				"err": err,
			}).Warn("write data to connection error")
			return
		}
	}
}