package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"log"
	"net"
)

var config *shadowsocks.Config
var encTbl *shadowsocks.EncryptTable

func handleConnection(conn *shadowsocks.Conn) {
	log.Printf("socks connect from %s\n", conn.RemoteAddr().String())
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
		log.Println("connecting ", addr)
		var remote net.Conn
		remote, err = net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			hasError = true
			break
		}
		if err != nil {
			hasError = true
			break
		}
		c := make(chan int, 2)
		go shadowsocks.Pipe(conn, remote, c)
		go shadowsocks.Pipe(remote, conn, c)
		<-c // close the other connection whenever one connection is closed
		log.Println("closing")
		err = conn.Close()
		err1 := remote.Close()
		if err == nil {
			err = err1
		}
		break
	}
	if err != nil || hasError {
		if err != nil {
			log.Println("error ", err)
		}
		err = conn.Close()
		if err != nil {
			log.Println("close:", err)
		}
		return
	}

}

func run(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting server at port %d ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(shadowsocks.NewConn(conn, encTbl))
	}
}

func main() {
	config = shadowsocks.ParseConfig("config.json")
	encTbl = shadowsocks.GetTable(config.Password)
	run(config.ServerPort)
}
