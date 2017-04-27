package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// OneTimeAuthMask is the mask for OTA table bit
	OneTimeAuthMask byte = 0x10
	// AddrMask is used to mask the AddrType
	AddrMask byte = 0xf

	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	headerLenIPv4   = 1 + net.IPv4len + 2      // 1addrType + ipv4 + 2port
	headerLenIPv6   = 1 + net.IPv6len + 2      // 1addrType + ipv6 + 2port
	headerLenDmBase = 1 + 1 + 2                // 1addrType + 1addrLen + 2port, plus addrLen
	lenHmacSha1     = 10                       // iv lenth is 10
	lenDataLen      = 2                        // the length about data length
	idOTAData0      = lenDataLen + lenHmacSha1 // data with OTA start offset
)

// PrintVersion prints the current version of shadowsocks-go
func PrintVersion() {
	const version = "2.0.0"
	fmt.Println("shadowsocks-go version", version)
}

// IsFileExists returns true if the file exists
func IsFileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		if stat.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.New(path + " exists but is not regular file")
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// HmacSha1 implements HmacSha1
func HmacSha1(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

// rawAddr split the addr into a byte based buffer catch all info
func rawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	len := headerLenDmBase + hostLen // addrType + lenByte + address + port
	buf = make([]byte, len)
	buf[idType] = typeDm         // 3 means the address is domain name
	buf[idDmLen] = byte(hostLen) // host address length  followed by host address
	copy(buf[idDm0:], host)
	binary.BigEndian.PutUint16(buf[idDm0+hostLen:idDm0+hostLen+2], uint16(port))
	return
}

// read full will read until got b length buffer
func readFull(c *SecureConn, b []byte) (n int, err error) {
	min := len(b)
	for n < min {
		var nn int
		nn, err = c.Read(b[n:])
		n += nn
	}

	// only get hmacsha1
	if n >= min {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

// GetRequest can handler the ss request header and decryption for ss protocol
func GetRequest(ss *SecureConn) (host string, err error) {
	// read till we get possible domain length field
	buf := make([]byte, 269)

	// read the type of the addr first
	if _, err = readFull(ss, buf[:idType+1]); err != nil {
		return
	}

	// reqstart & end hold the start and end about the request header
	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv4-1
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv6-1
	case typeDm:
		if _, err = readFull(ss, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+headerLenDmBase-2
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&AddrMask)
		return
	}

	// read the host & port
	if _, err = readFull(ss, buf[reqStart:reqEnd]); err != nil {
		panic(err)
		return
	}

	switch addrType & AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
		if strings.ContainsRune(host, 0x00) {
			return "", errInvalidHostname
		}
	}

	// get the port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	// the request host and port
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

// connectToServer
func requestForServe() {}
