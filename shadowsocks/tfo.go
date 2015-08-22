package shadowsocks

import (
	"errors"
	"net"
)

var ENotImpl = errors.New("function not implemented")

// delegate dialing and listening to platform-specific functions

type tfoDialDeleg interface {
	Dial(net, addr string, data []byte) (net.Conn, error)
}

type tfoListenDeleg interface {
	Listen(net, laddr string) (net.Listener, error)
}

// these gets set in platform-specific init functions
var tfoDialDel tfoDialDeleg
var tfoListenDel tfoListenDeleg

func TfoDial(net, addr string, data []byte) (net.Conn, error) {
	if tfoDialDel != nil {
		// platform-specific tfo dial
		return tfoDialDel.Dial(net, addr, data)
	}
	return nil, ENotImpl
}

func TfoListen(net, addr string) (net.Listener, error) {
	if tfoListenDel != nil {
		// platform-specific tfo listen
		return tfoListenDel.Listen(net, addr)
	}
	return nil, ENotImpl
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func TfoDialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	if tfoDialDel != nil {
		c := &Conn{
			Conn:     nil, //leave it nil for now
			Cipher:   cipher,
			readBuf:  leakyBuf.Get(),
			writeBuf: leakyBuf.Get()}
		// get the request payload encrypted and send along with the sync packet
		cipherData, err := c.encryptData(rawaddr)
		if err != nil {
			c.Close()
			return nil, err
		}
		// platform-specific tfo dial
		conn, err := tfoDialDel.Dial("tcp", server, cipherData)
		if err != nil {
			c.Close()
			return nil, err
		}
		c.Conn = conn
		return c, nil
	}
	return nil, ENotImpl
}
