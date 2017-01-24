package shadowsocks

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/shadowsocks/shadowsocks-go/encrypt"
)

// Dialer provides client side connection support
// and also implements the Dialer interface described in golang.org/x/net/proxy
type Dialer struct {
	cipher *encrypt.Cipher
	server string
	ota    bool
}

// ErrNilCipher occurs when the cipher is nil
var ErrNilCipher = errors.New("Cipher can't be nil")

// NewDialer initializes a new Dialer
func NewDialer(server string, cipher *encrypt.Cipher, ota bool) (dialer *Dialer, err error) {
	// Currently shadowsocks-go supports UDP
	// But you should not use Dialer to open an UDP connection
	if cipher == nil {
		return nil, ErrNilCipher
	}
	return &Dialer{
		cipher: cipher,
		server: server,
		ota:    ota,
	}, nil
}

// Dial is intended for the Dialer interface described in golang.org/x/net/proxy
func (d *Dialer) Dial(network, addr string) (c net.Conn, err error) {
	if strings.HasPrefix(network, "tcp") {
		ra, err := rawAddr(addr)
		if err != nil {
			return nil, err
		}
		c, err = d.DialWithRawAddr(ra)
		if err != nil {
			return nil, err
		}
		return c, err
	}
	return nil, fmt.Errorf("unsupported connection type: %s", network)
}

// DialWithRawAddr is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func (d *Dialer) DialWithRawAddr(rawaddr []byte) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", d.server)
	if err != nil {
		return
	}
	c := NewSecureConn(conn, d.cipher.Copy(), d.ota, false)
	if d.ota {
		if c.EncInited() {
			if _, err = c.InitEncrypt(); err != nil {
				conn.Close()
				return
			}
		}
		// since we have initEncrypt, we must send iv manually
		conn.Write(c.GetIV())
		rawaddr[idType] |= OneTimeAuthMask
		rawaddr = otaConnectAuth(c.GetIV(), c.GetKey(), rawaddr)
	}
	if _, err = c.write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return c, err
}
