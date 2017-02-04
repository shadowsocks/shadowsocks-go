package shadowsocks

import (
	"bytes"
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

// PrintVersion prints the current version of shadowsocks-go
func PrintVersion() {
	const version = "1.2.1"
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

func otaConnectAuth(iv, key, data []byte) []byte {
	return append(data, HmacSha1(append(iv, key...), data)...)
}

func otaReqChunkAuth(iv []byte, chunkID uint32, data []byte) (header []byte) {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIDBytes, chunkID)
	header = append(nb, HmacSha1(append(iv, chunkIDBytes...), data)...)
	return
}

func methodOTAEnabled(method string) bool {
	if strings.HasSuffix(strings.ToLower(method), "-auth") {
		method = method[:len(method)-5] // len("-auth") = 5
		return true
	}
	return false
}

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

func readFull(c *SecureConn, b []byte) (n int, err error) {
	min := len(b)
	for n < min {
		var nn int
		nn, err = c.read(b[n:])
		n += nn
	}
	if n >= min {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func getRequets(ss *SecureConn, auth bool) (host string, err error) {
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = readFull(ss, buf[:idType+1]); err != nil {
		return
	}
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
	if _, err = readFull(ss, buf[reqStart:reqEnd]); err != nil {
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

	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	ota := addrType&OneTimeAuthMask > 0
	if auth {
		if !ota {
			err = ErrPacketOtaFailed
			return
		}
	}
	if ota {
		if _, err = readFull(ss, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := ss.GetIV()
		key := ss.GetKey()
		actualHmacSha1Buf := HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = ErrPacketOtaFailed
			return
		}
		ss.EnableOta()
	}
	return
}
