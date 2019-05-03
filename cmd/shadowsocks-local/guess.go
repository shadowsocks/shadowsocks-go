package main

import (
	"strings"
)

const (
	DefaultPortForHttp = 80
	DefaultPortForTls  = 443

	SERVER_NAME_LEN                 = 256
	TLS_HEADER_LEN                  = 5
	TLS_HANDSHAKE_CONTENT_TYPE      = 0x16
	TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
)

func parseHttpHeader(buf string) string {
	for _, l := range strings.Split(buf, "\r\n") {
		if strings.HasPrefix(l, "Host:") {
			return strings.TrimSpace(l[5:])
		}
	}

	return ""
}

func parseTlsHeader(buf string) string {
	slen := len(buf)
	if slen < TLS_HEADER_LEN {
		return ""
	}

	if buf[0] != TLS_HANDSHAKE_CONTENT_TYPE {
		return ""
	}

	tlsVersionMajor, tlsVersionMinor := buf[1], buf[2]
	if tlsVersionMajor < 3 {
		return ""
	}

	l := int(uint(buf[3])<<8 + uint(buf[4]) + TLS_HEADER_LEN)
	if slen < l {
		return ""
	}

	buf = buf[:l]
	slen = len(buf)
	pos := TLS_HEADER_LEN
	if slen < pos+1 {
		return ""
	}

	if buf[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
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

