package main

import (
	"fmt"
	"log"
	"net"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

func handleConnection(conn net.Conn, server string) {
	log.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	b := make([]byte, 262)
	var err error = nil
	var hasError = false
	for {
		var _ int
		buf := make([]byte, 4096)
		_, err = conn.Read(b)
		if err != nil {
			hasError = true
			break
		}
		conn.Write([]byte{0x05, 0x00})
		_, err = conn.Read(buf)
		mode := buf[1]
		if mode != 1 {
			hasError = true
			log.Println("mode != 1")
			break
		}
		var addr string
		addrType := buf[3]
		var addrToSend []byte
		if addrType == 1 {
			var addrIp net.IP = make(net.IP, 4)
			copy(addrIp, buf[4:8])
			addr = addrIp.String()
			addrToSend = buf[3:10]
		} else if addrType == 3 {
			addrLen := buf[4]
			addr = string(buf[5 : 5+addrLen])
			addrToSend = buf[3 : 5+addrLen+2]
		} else {
			hasError = true
			log.Println("unsurpported addr type")
			break
		}
		log.Println("connecting ", addr)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})

		remote, err := shadowsocks.DialWithAddrBuf(addrToSend, server)
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

func run(port int, server string) {
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
		go handleConnection(conn, server)
	}
}

func main() {
	config := shadowsocks.ParseConfig()
	shadowsocks.InitTable(config.Password)
	run(config.LocalPort, fmt.Sprintf("%s:%d", config.Server, config.ServerPort))
}
