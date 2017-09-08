package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

var (
	ErrPacketTooSmall       = errors.New("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	ErrBufferTooSmall       = errors.New("[udp]read error: given buffer is too small to hold data")
	ErrInvalidHostname      = errors.New("error invalid hostname")
	ErrInvalidPacket        = errors.New("invalid message received")
	ErrInvalidServerAddress = errors.New("invalid server ip address, can not be parsed")
	ErrNilPasswd            = errors.New("password should NOT be nil")
	ErrParesConfigfile      = errors.New("can not parse the config fire")
	ErrNilCipher            = errors.New("cipher should NOT be nil")
	ErrInvalidCipher        = errors.New("cipher method invalid or not supported")
	ErrUnexpectedIO         = errors.New("error in IO, expect more data than we get")
	ErrInvalidConfig        = errors.New("error in config check, config fields invalid")

	requestBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 269)
		},
	}
)

// PrintVersion prints the current version of shadowsocks-go
func PrintVersion() {
	const version = "2.0.0 alpha"
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

// GetRequest can handler the ss request header and decryption for ss protocol
func GetRequest(ss net.Conn) (host string, err error) {
	// read the type of the addr first
	// read till we get possible domain length field
	buf := requestBufferPool.Get().([]byte)
	defer requestBufferPool.Put(buf)

	//if n, err := io.ReadFull(ss, buf[:idType+1]); err != nil {
	if n, err := ss.Read(buf[:idType+1]); err != nil {
		Logger.Error("ss get the encrypted request packet error", zap.Error(err), zap.Int("n", n))
	}

	// the reqStart and the reqEnd hold the start and end index about the request header
	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv4-1
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+headerLenIPv6-1
	case typeDm:
		//if _, err = io.ReadFull(ss, buf[idType+1:idDmLen+1]); err != nil {
		if _, err = ss.Read(buf[idType+1 : idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+headerLenDmBase-2
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&AddrMask)
		return
	}

	// read the host & port
	//if _, err = io.ReadFull(ss, buf[reqStart:reqEnd]); err != nil {
	if _, err = ss.Read(buf[reqStart:reqEnd]); err != nil {
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
			return "", ErrInvalidHostname
		}
	}

	// get the port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	// the request host and port
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

// GetUDPRequest can handler the ss request header and decryption for ss protocol
func GetUDPRequest(req []byte) (dst string, length int, err error) {
	// dst should be the ip:port, host should be resolved here
	// reqstart & end hold the start and end about the request header
	var host string
	addrType := req[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		length = idIP0 + headerLenIPv4
		host = net.IP(req[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		length = idIP0 + headerLenIPv6
		host = net.IP(req[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		length = idDm0 + int(req[idDmLen]) + headerLenDmBase - 1
		host = string(req[idDm0 : idDm0+int(req[idDmLen])])
		if strings.ContainsRune(host, 0x00) {
			return "", -1, ErrInvalidHostname
		}
		// resolve the host for ip
		ip, err := net.LookupIP(host)
		if err != nil || len(ip) == 0 {
			return "", -1, ErrInvalidHostname
		}
		host = ip[0].To4().String()
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&AddrMask)
		return "", -1, err
	}

	// get the port
	port := binary.BigEndian.Uint16(req[length-2 : length])
	// the request host and port
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return host, length + 2, nil
}
