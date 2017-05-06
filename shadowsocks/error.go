package shadowsocks

import "errors"

var (
	errPacketTooSmall  = errors.New("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errBufferTooSmall  = errors.New("[udp]read error: given buffer is too small to hold data")
	ErrPacketOtaFailed = errors.New("read error: received packet has invalid ota")
	ErrInvalidHostname = errors.New("errInvalidHostname")
	ErrInvalidPacket   = errors.New("invalid message received.")
	//ErrInvalidPara     = errors.New("errInvalidPara")
	ErrNilCipher = errors.New("Cipher can't be nil")
)
