package shadowsocks

import (
	"net"
	"io"
	"strconv"
	"encoding/binary"
)

type ServerTCP struct {
	Server
}

func (this *ServerTCP) getRequest() {

}

type LocalTCP struct {
	Server
	conn net.Conn
	rawaddr []byte
	host string
}

// accpted a connection
func (this *LocalTCP) Accept(ln net.Listener) (err error) { this.conn, err = ln.Accept(); return }

// handle connection
func (this *LocalTCP) Serve() (err error) {
	if err = this.handShake(); err != nil { return }
	if err = this.getRequest(); err != nil { return }
	if err = this.send([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43}); err != nil { return }
	if err = this.connectServer(); err != nil { return }

	// do piping

	return
}

func (this *LocalTCP) connectServer() (err error) {

	return
}

func (this *LocalTCP) getRequest() (err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	if n, err = io.ReadAtLeast(this.conn, buf, idDmLen+1); err != nil { return }
	if buf[idVer] != socksVer5 { err = errVer; return }
	if buf[idCmd] != socksCmdConnect { err = errCmd; return }
	reqLen := -1;
	switch buf[idType] {
	case typeIPv4: reqLen = lenIPv4
	case typeIPv6: reqLen = lenIPv6
	case typeDm: reqLen = int(buf[idDmLen]) + lenDmBase
	default: err = errAddrType; return }
	if n < reqLen { if _, err = io.ReadFull(this.conn, buf[n:reqLen]); err != nil { return } } else { err = errReqExtraData; return }
	this.rawaddr = buf[idType:reqLen]

	if DebugLog {
		switch buf[idType] {
		case typeIPv4: this.host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6: this.host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm: this.host = string(buf[idDm0 : idDm0+buf[idDmLen]]) }
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		this.host = net.JoinHostPort(this.host, strconv.Itoa(int(port))) }

	return
}

func (this *LocalTCP) handShake() (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)
	var n int
	if n, err = io.ReadAtLeast(this.conn, buf, idNmethod+1); err != nil { return }
	if buf[idVer] != socksVer5 { err = errVer; return }
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n < msgLen { if _, err = io.ReadFull(this.conn, buf[n:msgLen]); err != nil { return } } else { err = errAuthExtraData; return }
	err = this.send([]byte{socksVer5, 0})

	return
}

func (this *LocalTCP) send(b []byte) (err error) {
	_, err = this.conn.Write(b); return
}