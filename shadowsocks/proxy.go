package shadowsocks

import (
	"errors"
	"strings"
	"fmt"
)

type Dialer struct {
	cipher *Cipher
	server string
	support_udp bool
}

var ErrNilCipher = errors.New("cipher can't be nil.")

func NewDialer(server string, cipher *Cipher) (dialer *Dialer, err error) {
	// Currently shadowsocks-go do not support UDP
	if cipher == nil {
		return nil, ErrNilCipher
	}
	return &Dialer {
		cipher: cipher,
		server: server,
		support_udp: false,
	}, nil
}

func (d *Dialer) Dial(network, addr string) (c *Conn, err error) {
	if strings.HasPrefix(network, "tcp") {
		return Dial(addr, d.server, d.cipher)
	}
	return nil, fmt.Errorf("unsupported connection type: %s", network)
}
