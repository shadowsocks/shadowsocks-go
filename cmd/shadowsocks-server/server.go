package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

var debug ss.DebugLog

var errAddr = errors.New("addr type not supported")

func getRequest(conn *ss.Conn) (host string, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIP = 1 // type is ip address
		typeDm = 3 // type is domain address

		lenIP     = 1 + 4 + 2 // 1addrType + 4ip + 2port
		lenDmBase = 1 + 1 + 2 // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 260, 260)
	cur := 0 // current location in buf

	// first read the complete request, may read extra bytes
	for {
		// hopefully, we should only need one read to get the complete request
		// this read normally will read just the request, no extra data
		ss.SetReadTimeout(conn)
		var n int
		if n, err = conn.Read(buf[cur:]); err != nil {
			// debug.Println("read request error:", err)
			return
		}
		cur += n
		if buf[idType] == typeIP {
			if cur >= lenIP {
				// debug.Println("ip request complete, cur:", cur)
				break
			}
		} else if buf[idType] == typeDm {
			if cur < idDmLen+1 { // read until we get address length byte
				continue
			}
			if cur >= lenDmBase+int(buf[idDmLen]) {
				// debug.Println("domain request complete, cur:", cur)
				break
			}
		} else {
			err = errAddr
			return
		}
		// debug.Println("request not complete, cur:", cur)
	}

	reqLen := lenIP // default to IP request length
	if buf[idType] == typeIP {
		addrIp := make(net.IP, 4)
		copy(addrIp, buf[idIP0:idIP0+4])
		host = addrIp.String()
	} else if buf[idType] == typeDm {
		reqLen = lenDmBase + int(buf[idDmLen])
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	var port int16
	sb := bytes.NewBuffer(buf[reqLen-2 : reqLen])
	binary.Read(sb, binary.BigEndian, &port)

	// debug.Println("requesting:", host, "header len", reqLen)
	host += ":" + strconv.Itoa(int(port))
	if cur > reqLen {
		extra = buf[reqLen:cur]
		// debug.Println("extra:", string(extra))
	}
	return
}

func handleConnection(conn *ss.Conn) {
	if debug {
		// function arguments are always evaluated, so surround debug
		// statement with if statement
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	defer conn.Close()

	host, extra, err := getRequest(conn)
	if err != nil {
		debug.Println("error getting request:", err)
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		debug.Println("error connecting to:", host, err)
		return
	}
	defer remote.Close()
	// write extra bytes read from 
	if extra != nil {
		debug.Println("writing extra content to remote, len", len(extra))
		if _, err = remote.Write(extra); err != nil {
			debug.Println("write request extra error:", err)
			return
		}
	}
	debug.Println("piping", host)
	c := make(chan byte, 2)
	go ss.Pipe(conn, remote, c)
	go ss.Pipe(remote, conn, c)
	<-c // close the other connection whenever one connection is closed
	debug.Println("closing", host)
	return
}

// Add a encrypt table cache to save memory and startup time in case of many
// same password.
// If startup time becomes an issue, save the encrypt table on disk.
var tableCache = map[string]*ss.EncryptTable{}
var tableGetCnt int32

func getTable(password string) (tbl *ss.EncryptTable) {
	tbl, ok := tableCache[password]
	if ok {
		debug.Println("table cache hit for password:", password)
		return
	}
	tbl = ss.GetTable(password)
	tableCache[password] = tbl
	return
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	encTbl := getTable(password)
	atomic.AddInt32(&tableGetCnt, 1)
	log.Printf("starting server at port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(ss.NewConn(conn, encTbl))
	}
}

func main() {
	config := ss.ParseConfig("config.json")
	debug = ss.Debug
	if len(config.PortPassword) == 0 {
		run(strconv.Itoa(config.ServerPort), config.Password)
	} else {
		if config.ServerPort != 0 {
			log.Println("ignoring server_port and password option, only uses port_password")
		}
		for port, password := range config.PortPassword {
			go run(port, password)
		}
		// Wait all ports have get it's encryption table
		for int(tableGetCnt) != len(config.PortPassword) {
			time.Sleep(1 * time.Second)
		}
		log.Println("all ports ready")
		tableCache = nil // release memory
		c := make(chan byte)
		<-c // block forever
	}
}
