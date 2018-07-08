package main

import (
	"net"
	"fmt"
	"os"
	"errors"
	"strconv"
	"io"
	"encoding/binary"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

func sanitizeAddr(addr net.Addr) string {
	if sanitizeIps {
		return "x.x.x.x:zzzz"
	} else {
		return addr.String()
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func parsePortNum(in interface{}) string {
	var port string
	switch in.(type) {
	case string:
		// try to convert to number then convert back, to ensure valid value
		portNum, err := strconv.Atoi(in.(string))
		if portNum == 0 || err != nil {
			return ""
		}
		port = strconv.Itoa(portNum)
	case float64:
		port = strconv.Itoa(int(in.(float64)))
	default:
		return ""
	}
	return port
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

func getRequest(conn *ss.Conn) (host string, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}
