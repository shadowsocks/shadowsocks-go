package main

import (
	"bytes"
	"encoding/binary"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

var debug ss.DebugLog

func handleConnection(conn *ss.Conn) {
	debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	var err error = nil
	var hasError = false
	for {
		var _ int
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			hasError = true
			break
		}
		addrType := buf[0]
		var addr string
		var port int16
		if addrType == 1 {
			buf = make([]byte, 6)
			_, err = conn.Read(buf)
			if err != nil {
				hasError = true
				break
			}
			var addrIp net.IP = make(net.IP, 4)
			copy(addrIp, buf[0:4])
			addr = addrIp.String()
			sb := bytes.NewBuffer(buf[4:6])
			binary.Read(sb, binary.BigEndian, &port)
		} else if addrType == 3 {
			_, err = conn.Read(buf)
			if err != nil {
				hasError = true
				break
			}
			addrLen := buf[0]
			buf = make([]byte, addrLen+2)
			_, err = conn.Read(buf)
			if err != nil {
				hasError = true
				break
			}
			sb := bytes.NewBuffer(buf[0:addrLen])
			addr = sb.String()
			sb = bytes.NewBuffer(buf[addrLen : addrLen+2])
			binary.Read(sb, binary.BigEndian, &port)
		} else {
			hasError = true
			log.Println("unsurpported addr type")
			break
		}
		debug.Println("connecting ", addr)
		var remote net.Conn
		remote, err = net.Dial("tcp", addr+":"+strconv.Itoa(int(port)))
		if err != nil {
			hasError = true
			break
		}
		if err != nil {
			hasError = true
			break
		}
		c := make(chan int, 2)
		go ss.Pipe(conn, remote, c)
		go ss.Pipe(remote, conn, c)
		<-c // close the other connection whenever one connection is closed
		debug.Println("closing")
		err = conn.Close()
		err1 := remote.Close()
		if err == nil {
			err = err1
		}
		break
	}
	if err != nil || hasError {
		if err != nil {
			debug.Println("error:", err)
		}
		err = conn.Close()
		if err != nil {
			debug.Println("close:", err)
		}
		return
	}

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
