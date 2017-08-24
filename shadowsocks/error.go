package shadowsocks

import "errors"

var (
	ErrPacketTooSmall  = errors.New("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	ErrBufferTooSmall  = errors.New("[udp]read error: given buffer is too small to hold data")
	ErrInvalidHostname = errors.New("error invalid hostname")
	ErrInvalidPacket   = errors.New("invalid message received")
	ErrNilCipher       = errors.New("cipher should NOT be nil")
	ErrUnexpectedIO    = errors.New("error in IO, expect more data to write")
	//ErrInvalidPara     = errors.New("errInvalidPara")
)
