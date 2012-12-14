package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"log"
	"net"
	"strconv"
)

var debug ss.DebugLog

var (
	errAddr   = errors.New("socks addr type not supported")
	errVer    = errors.New("socks version not supported")
	errMethod = errors.New("socks only support 1 method now")
	errAuth   = errors.New("socks authentication not required")
	errCmd    = errors.New("socks command not supported")
)

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved)

	buf := make([]byte, 258-2, 258-2) // reuse the buf to read nmethod field

	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[idVer] != 5 {
		return errVer
	}
	nmethod := buf[idNmethod]
	if _, err = io.ReadFull(conn, buf[:nmethod]); err != nil {
		return
	}
	// version 5, no authentication required
	_, err = conn.Write([]byte{5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, extra []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIP = 1 // type is ip address
		typeDm = 3 // type is domain address

		lenIP     = 3 + 1 + 4 + 2 // 3(ver+cmd+rsv) + 1addrType + 4ip + 2port
		lenDmBase = 3 + 1 + 1 + 2 // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263, 263)
	cur := 0 // current location in buf
	reqLen := 0

	for {
		var n int
		// usually need to read only once
		if n, err = conn.Read(buf[cur:]); err != nil {
			// debug.Println("read request error:", err)
			return
		}
		cur += n
		if cur < idType+1 { // read till we get addr type
			continue
		}
		// check version and cmd
		if buf[idVer] != 5 {
			err = errVer
			return
		}
		if buf[idCmd] != 1 {
			err = errCmd
			return
		}
		// TODO following code is copied from server.go, fix code duplication?
		if buf[idType] == typeIP {
			if cur >= lenIP {
				// debug.Println("ip request complete, cur:", cur)
				reqLen = lenIP
				break
			}
		} else if buf[idType] == typeDm {
			if cur < idDmLen+1 { // read until we get address length byte
				continue
			}
			if cur >= lenDmBase+int(buf[idDmLen]) {
				// debug.Println("domain request complete, cur:", cur)
				reqLen = lenDmBase + int(buf[idDmLen])
				break
			}
		} else {
			err = errAddr
			return
		}
		// debug.Println("request not complete, cur:", cur)
	}

	rawaddr = buf[idType:reqLen]
	if cur > reqLen {
		extra = buf[reqLen:cur]
		// debug.Println("extra:", string(extra))
	}

	if debug {
		if buf[idType] == typeIP {
			addrIp := make(net.IP, 4)
			copy(addrIp, buf[idIP0:idIP0+4])
			host = addrIp.String()
		} else if buf[idType] == typeDm {
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		var port int16
		sb := bytes.NewBuffer(buf[reqLen-2 : reqLen])
		binary.Read(sb, binary.BigEndian, &port)
		host += ":" + strconv.Itoa(int(port))
	}
	return
}

func handleConnection(conn net.Conn, server string, encTbl *ss.EncryptTable) {
	if debug {
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	defer conn.Close()

	var err error = nil
	if err = handShake(conn); err != nil {
		log.Println("socks handshack:", err)
		return
	}
	rawaddr, extra, addr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// TODO should send error code to client if connect to server failed
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}

	debug.Println("connecting to", addr)
	remote, err := ss.DialWithRawAddr(rawaddr, server, encTbl)
	if err != nil {
		log.Println("error connect to shadowsocks server:", err)
		return
	}
	defer remote.Close()
	if extra != nil {
		debug.Println("writing extra content to remote, len", len(extra))
		if _, err = remote.Write(extra); err != nil {
			debug.Println("write request extra error:", err)
			return
		}
	}

	c := make(chan byte, 2)
	go ss.Pipe(conn, remote, c)
	go ss.Pipe(remote, conn, c)
	<-c // close the other connection whenever one connection is closed
	debug.Println("closing")
}

func run(port, password, server string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	encTbl := ss.GetTable(password)
	log.Printf("starting server at port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn, server, encTbl)
	}
}

func main() {
	config := ss.ParseConfig("config.json")
	debug = ss.Debug
	run(strconv.Itoa(config.LocalPort), config.Password,
		config.Server+":"+strconv.Itoa(config.ServerPort))
}
