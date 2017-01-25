package shadowsocks

import (
	"errors"
	"fmt"
)

var (
	errPacketTooSmall  = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge  = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall  = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
	ErrPacketOtaFailed = fmt.Errorf("[udp]read error: received packet has invalid ota")
	errInvalidHostname = fmt.Errorf("errInvalidHostname")
	errInvalidPara     = fmt.Errorf("errInvalidPara")
	ErrNilCipher       = errors.New("Cipher can't be nil")
)
