package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

type httpProxyHandler struct {
}

const (
	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address
)

// RawAddr used in Shadowsocks follows the SOCKS5 address format: https://tools.ietf.org/html/rfc1928
type rawAddrBuilder struct {
	addrType byte
	varAddr  []byte
	port     int16
}

func buildRawAddrByDomain(domain string, port string) (*rawAddrBuilder, error) {
	if len(domain) > 255 {
		return nil, errors.New("domain length larger than 255")
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, errors.New("port error")
	}

	b := &rawAddrBuilder{}
	b.addrType = typeDm
	b.varAddr = append(b.varAddr, byte(len(domain)))
	b.varAddr = append(b.varAddr, []byte(domain)...)
	b.port = int16(portInt)
	return b, nil
}

func (addr *rawAddrBuilder) RawAddr() []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(addr.addrType)
	buf.Write(addr.varAddr)
	binary.Write(buf, binary.BigEndian, addr.port)
	return buf.Bytes()
}

func (h *httpProxyHandler) GetHostPort(in string) (host string, port string) {
	var err error
	host, port, err = net.SplitHostPort(in)
	if err != nil {
		host = in
		port = "80"
	}

	return
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if debug {
		debug.Printf("socks connect from %s\n", r.RemoteAddr)
	}

	closed := false

	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	clientConn, _, e := hij.Hijack()
	if e != nil {
		panic("Cannot hijack connection" + e.Error())
	}

	host, port := h.GetHostPort(r.Host)
	addrBuilder, err := buildRawAddrByDomain(host, port)
	if err != nil {
		panic(fmt.Sprintf("invalid hostname, %s, %s", r.Host, err))
	}

	rawaddr := addrBuilder.RawAddr()
	debug.Printf("debug: host=%s, rawAddr=%x", host, rawaddr)
	remote, err := createServerConn(rawaddr, r.Host)
	if err != nil {
		if len(servers.srvCipher) > 1 {
			log.Println("Failed connect to all avaiable shadowsocks server")
		}
		return
	}

	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	if r.Method == "CONNECT" { // http tunnel, for proxy https request
		clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	} else {
		r.Write(remote) // replay the first http request
	}

	go ss.PipeThenClose(clientConn, remote)
	ss.PipeThenClose(remote, clientConn)
	closed = true
	debug.Printf("connection closed, %s->%s, %s->%s\n", clientConn.RemoteAddr(), clientConn.LocalAddr(),
		remote.LocalAddr(), remote.RemoteAddr())
}
