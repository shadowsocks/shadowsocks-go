package main

import (
	"shadowsocks"
	"net"
	"bytes"
	"log"
	"fmt"
)

func handleConnection(conn net.Conn, encryptTable, decryptTable []byte, server string) {
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
			sb := bytes.NewBuffer(buf[5:5 + addrLen])
			addr = sb.String()
			addrToSend = buf[3:5 + addrLen + 2]
		} else {
			hasError = true
			log.Println("unsurpported addr type")
			break
		}
		log.Println("connecting ", addr)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		var remote net.Conn
		remote, err = net.Dial("tcp", server)
		if err != nil {
			hasError = true
			break
		}
		_, err = remote.Write(shadowsocks.Encrypt(encryptTable, addrToSend))
		if err != nil {
			hasError = true
			break
		}
		c := make(chan int, 2)
		go shadowsocks.Pipe(conn, remote, encryptTable, c)
		go shadowsocks.Pipe(remote, conn, decryptTable, c)
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

func run(encryptTable, decryptTable []byte, port int, server string) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("starting server at port %d ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(net.Conn(conn), encryptTable, decryptTable, server)
	}
}

func main() {
	encyrptTable, decryptTable := shadowsocks.GetTable("foobar!")
	run(encyrptTable, decryptTable, 1080, "127.0.0.1:8388")

}
