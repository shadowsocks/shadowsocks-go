package shadowsocks

import (
	"fmt"
	"net"
	"strings"
	"syscall"
)

const (
	SoOriginalDst = 80

	DefaultPortForHttp = 80
	DefaultPortForTls  = 443

	ServerNameLen               = 256
	TLSHeaderLen                = 5
	TLSHandshakeContentType     = 0x16
	TLSHandshakeTypeClientHello = 0x01
)

// ParseHTTPHeader tries to find 'Host' header.
func ParseHTTPHeader(buf string) string {
	for _, l := range strings.Split(buf, "\r\n") {
		if strings.HasPrefix(l, "Host:") {
			return strings.TrimSpace(l[5:])
		}
	}

	return ""
}

// ParseTLSHeader tries to find 'Host' extension.
func ParseTLSHeader(buf string) string {
	slen := len(buf)
	if slen < TLSHeaderLen {
		return ""
	}

	if buf[0] != TLSHandshakeContentType {
		return ""
	}

	tlsVersionMajor, tlsVersionMinor := buf[1], buf[2]
	if tlsVersionMajor < 3 {
		return ""
	}

	l := int(uint(buf[3])<<8 + uint(buf[4]) + TLSHeaderLen)
	if slen < l {
		return ""
	}

	buf = buf[:l]
	slen = len(buf)
	pos := TLSHeaderLen
	if slen < pos+1 {
		return ""
	}

	if buf[pos] != TLSHandshakeTypeClientHello {
		return ""
	}

	/* Skip past fixed length records:
	 * 1	Handshake Type
	 * 3	Length
	 * 2	Version (again)
	 * 32	Random
	 * to	Session ID Length
	 */
	pos += 38

	if pos+1 > slen {
		return ""
	}
	pos += int(1 + uint(buf[pos]))

	if pos+2 > slen {
		return ""
	}
	pos += int(2 + uint(buf[pos])<<8 + uint(buf[pos+1]))

	if pos+1 > slen {
		return ""
	}
	pos += int(1 + uint(buf[pos]))

	if pos == slen && tlsVersionMajor == 3 && tlsVersionMinor == 0 {
		return ""
	}

	if pos+2 > slen {
		return ""
	}
	l = int(uint(buf[pos])<<8 + uint(buf[pos+1]))
	pos += 2
	if pos+l > slen {
		return ""
	}

	return parseExtensions(buf[pos : pos+l])
}

func parseExtensions(buf string) string {
	var pos, l int
	slen := len(buf)

	for pos+4 <= slen {
		l = int(uint(buf[pos+2])<<8 + uint(buf[pos+3]))
		if buf[pos] == 0x00 && buf[pos+1] == 0x00 {
			if pos+4+l > slen {
				return ""
			}

			return parseServerNameExtension(buf[pos+4 : pos+4+l])
		}
		pos += 4 + l
	}

	return ""
}

func parseServerNameExtension(buf string) string {
	var l int
	slen := len(buf)
	pos := 2

	for pos+3 < slen {
		l = int(uint(buf[pos+1])<<8 + uint(buf[pos+2]))
		if pos+3+l > slen {
			return ""
		}

		switch buf[pos] {
		case 0x00:
			return buf[pos+3 : pos+3+l]
		default:
		}
		pos += 3 + l
	}

	return ""
}

// GetOriginalDst gets the raw address.
func GetOriginalDst(conn *net.Conn, buf string) (rawaddr []byte, addr string) {
	tcpConn := (*conn).(*net.TCPConn)
	// connection => file, will make a copy
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		panic(err)
	} else {
		tcpConn.Close()
	}

	defer func() {
		// file => connection
		(*conn), err = net.FileConn(tcpConnFile)
		if err != nil {
			panic(err)
		}
		tcpConnFile.Close()
	}()

	fd := int(tcpConnFile.Fd())
	req, err := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SoOriginalDst)
	if err != nil {
		_, err := syscall.GetsockoptIPMreq(fd, syscall.SOL_IP, SoOriginalDst)
		if err != nil {
			println(err.Error())
		}
		// TODO(me): I don't where the port is saved.
		return nil, ""
	}

	ip := net.IPv4(req.Multiaddr[4], req.Multiaddr[5], req.Multiaddr[6], req.Multiaddr[7])
	port := uint16(req.Multiaddr[2])<<8 + uint16(req.Multiaddr[3])
	dstaddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return nil, ""
	}
	addr = dstaddr.String()
	var s string
	if dstaddr.Port == DefaultPortForHttp {
		s = ParseHTTPHeader(buf)
	} else if dstaddr.Port == DefaultPortForTls {
		s = ParseTLSHeader(buf)
	}

	if s != "" {
		addr = s
		rawaddr = append(rawaddr, byte(3))
		rawaddr = append(rawaddr, byte(len(s)))
		rawaddr = append(rawaddr, []byte(s)...)
		rawaddr = append(rawaddr, req.Multiaddr[2:4]...)
		return
	}

	rawaddr = append(rawaddr, byte(1))
	rawaddr = append(rawaddr, req.Multiaddr[4:8]...)
	rawaddr = append(rawaddr, req.Multiaddr[2:4]...)
	return
}
