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

func handleConnection(conn *ss.Conn) {
	if debug {
		// function arguments are always evaluated, so surround debug
		// statement with if statement
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	defer conn.Close()

	var addr string
	var port int16
	var addrType byte
	var remote net.Conn
	var c chan byte
	var err error

	buf := make([]byte, 1)
	if _, err = conn.Read(buf); err != nil {
		goto onError
	}
	addrType = buf[0]
	if addrType == 1 {
		buf = make([]byte, 6)
		if _, err = conn.Read(buf); err != nil {
			goto onError
		}
		sb := bytes.NewBuffer(buf[4:6])
		binary.Read(sb, binary.BigEndian, &port)
		addrIp := make(net.IP, 4)
		copy(addrIp, buf[0:4])
		addr = addrIp.String()
	} else if addrType == 3 {
		if _, err = conn.Read(buf); err != nil {
			goto onError
		}
		addrLen := buf[0]
		buf = make([]byte, addrLen+2)
		if _, err = conn.Read(buf); err != nil {
			goto onError
		}
		sb := bytes.NewBuffer(buf[addrLen : addrLen+2])
		binary.Read(sb, binary.BigEndian, &port)
		addr = string(buf[0:addrLen])
	} else {
		log.Println("unsurpported addr type")
		err = errAddr
		goto onError
	}
	debug.Println("connecting", addr)
	if remote, err = net.Dial("tcp", addr+":"+strconv.Itoa(int(port))); err != nil {
		goto onError
	}
	defer remote.Close()
	debug.Println("piping", addr)
	c = make(chan byte, 2)
	go ss.Pipe(conn, remote, c)
	go ss.Pipe(remote, conn, c)
	<-c // close the other connection whenever one connection is closed
	debug.Println("closing", addr)
	return

onError:
	debug.Println("error", addr, err)
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
		c := make(chan byte)
		for port, password := range config.PortPassword {
			go run(port, password)
		}
		// Wait all ports have get it's encryption table
		for int(tableGetCnt) != len(config.PortPassword) {
			time.Sleep(1 * time.Second)
		}
		log.Println("all ports ready")
		tableCache = nil // release memory
		<-c              // block forever
	}
}
