package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	ss "github.com/bonafideyan/shadowsocks-go/shadowsocks"
)

var config struct {
	server string
	port   int
	passwd string
	method string
	core   int
	nconn  int
	nreq   int
	// nsec   int
}

var debug ss.DebugLog

func doOneRequest(client *http.Client, uri string, buf []byte) (err error) {
	resp, err := client.Get(uri)
	if err != nil {
		fmt.Printf("GET %s error: %v\n", uri, err)
		return err
	}
	for err == nil {
		_, err = resp.Body.Read(buf)
		if debug {
			debug.Println(string(buf))
		}
	}
	if err != io.EOF {
		fmt.Printf("Read %s response error: %v\n", uri, err)
	} else {
		err = nil
	}
	return
}

func get(connid int, uri, serverAddr string, rawAddr []byte, cipher *ss.Cipher, done chan []time.Duration) {
	reqDone := 0
	reqTime := make([]time.Duration, config.nreq)
	defer func() {
		done <- reqTime[:reqDone]
	}()
	tr := &http.Transport{
		Dial: func(_, _ string) (net.Conn, error) {
			if cipher != nil {
				return ss.DialWithRawAddr(rawAddr, serverAddr, cipher.Copy())
			}

			return dialSocks5(string(rawAddr), serverAddr)
		},
	}

	buf := make([]byte, 8192)
	client := &http.Client{Transport: tr}
	for ; reqDone < config.nreq; reqDone++ {
		start := time.Now()
		if err := doOneRequest(client, uri, buf); err != nil {
			return
		}
		reqTime[reqDone] = time.Now().Sub(start)

		if (reqDone+1)%1000 == 0 {
			fmt.Printf("conn %d finished %d get requests\n", connid, reqDone+1)
		}
	}
}

func dialSocks5(targetAddr, proxy string) (conn net.Conn, err error) {
	readAll := func(conn net.Conn) (resp []byte, err error) {
		resp = make([]byte, 1024)
		Timeout := 5 * time.Second
		if err := conn.SetReadDeadline(time.Now().Add(Timeout)); err != nil {
			return nil, err
		}
		n, err := conn.Read(resp)
		resp = resp[:n]
		return
	}
	sendReceive := func(conn net.Conn, req []byte) (resp []byte, err error) {
		Timeout := 5 * time.Second
		if err := conn.SetWriteDeadline(time.Now().Add(Timeout)); err != nil {
			return nil, err
		}
		_, err = conn.Write(req)
		if err != nil {
			return
		}
		resp, err = readAll(conn)
		return
	}

	conn, err = net.Dial("tcp", proxy)
	if err != nil {
		return
	}

	// version identifier/method selection request
	req := []byte{
		5, // version number
		1, // number of methods
		0, // method 0: no authentication (only anonymous access supported for now)
	}
	resp, err := sendReceive(conn, req)
	if err != nil {
		return
	} else if len(resp) != 2 {
		err = errors.New("server does not respond properly")
		return
	} else if resp[0] != 5 {
		err = errors.New("server does not support Socks 5")
		return
	} else if resp[1] != 0 { // no auth
		err = errors.New("socks method negotiation failed")
		return
	}

	// detail request
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	port := uint16(portInt)

	req = []byte{
		5,               // version number
		1,               // connect command
		0,               // reserved, must be zero
		3,               // address type, 3 means domain name
		byte(len(host)), // address length
	}
	req = append(req, []byte(host)...)
	req = append(req, []byte{
		byte(port >> 8), // higher byte of destination port
		byte(port),      // lower byte of destination port (big endian)
	}...)
	resp, err = sendReceive(conn, req)
	if err != nil {
		return
	} else if len(resp) != 10 {
		err = errors.New("server does not respond properly")
	} else if resp[1] != 0 {
		err = errors.New("can't complete SOCKS5 connection")
	}

	return
}

func main() {
	server := flag.String("s", "127.0.0.1", "server:port")
	proxy := flag.String("ss", "127.0.0.1", "proxy:port")
	flag.IntVar(&config.port, "p", 0, "port")
	flag.IntVar(&config.core, "core", 1, "number of CPU cores to use")
	flag.StringVar(&config.passwd, "k", "", "password")
	flag.StringVar(&config.method, "m", "", "encryption method, use empty string or rc4")
	flag.IntVar(&config.nconn, "nc", 1, "number of connection to server")
	flag.IntVar(&config.nreq, "nr", 1, "number of request for each connection")
	// flag.IntVar(&config.nsec, "ns", 0, "run how many seconds for each connection")
	flag.BoolVar((*bool)(&debug), "d", false, "print http response body for debugging")

	flag.Parse()

	config.server = "127.0.0.1"
	var connectProxy bool
	if *server != config.server {
		config.server = *server
	} else {
		config.server = *proxy
		connectProxy = true
	}

	if config.port == 0 || !connectProxy && config.passwd == "" || len(flag.Args()) != 1 {
		fmt.Printf("Usage: %s -s[s] <server> -p <port> -k <password> <url>\n", os.Args[0])
		os.Exit(1)
	}

	runtime.GOMAXPROCS(config.core)
	uri := flag.Arg(0)
	if strings.HasPrefix(uri, "https://") {
		fmt.Println("https not supported")
		os.Exit(1)
	}
	if !strings.HasPrefix(uri, "http://") {
		uri = "http://" + uri
	}

	serverAddr := net.JoinHostPort(config.server, strconv.Itoa(config.port))

	parsedURL, err := url.Parse(uri)
	if err != nil {
		fmt.Println("Error parsing url:", err)
		os.Exit(1)
	}
	host, _, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		host = net.JoinHostPort(parsedURL.Host, "80")
	} else {
		host = parsedURL.Host
	}

	rawAddr := []byte(host)
	var cipher *ss.Cipher
	if !connectProxy {
		if config.method == "" {
			config.method = "aes-256-cfb"
		}

		cipher, err = ss.NewCipher(config.method, config.passwd)
		if err != nil {
			fmt.Println("Error creating cipher:", err)
			os.Exit(1)
		}
		rawAddr, err = ss.RawAddr(host)
		if err != nil {
			panic("Error getting raw address.")
		}
	}

	done := make(chan []time.Duration)
	for i := 1; i <= config.nconn; i++ {
		go get(i, uri, serverAddr, rawAddr, cipher, done)
	}

	// collect request finish time
	reqTime := make([]int64, config.nconn*config.nreq)
	reqDone := 0
	for i := 1; i <= config.nconn; i++ {
		rt := <-done
		for _, t := range rt {
			reqTime[reqDone] = int64(t)
			reqDone++
		}
	}

	fmt.Println("number of total requests:", config.nconn*config.nreq)
	fmt.Println("number of finished requests:", reqDone)
	if reqDone == 0 {
		return
	}

	// calculate average an standard deviation
	reqTime = reqTime[:reqDone]
	var sum int64
	for _, d := range reqTime {
		sum += d
	}
	avg := float64(sum) / float64(reqDone)

	varSum := float64(0)
	for _, d := range reqTime {
		di := math.Abs(float64(d) - avg)
		di *= di
		varSum += di
	}
	stddev := math.Sqrt(varSum / float64(reqDone))
	fmt.Println("\naverage time per request:", time.Duration(avg))
	fmt.Println("standard deviation:", time.Duration(stddev))
}
