package main

import (
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

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
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
			return ss.DialWithRawAddr(rawAddr, serverAddr, cipher.Copy())
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

func main() {
	flag.StringVar(&config.server, "s", "127.0.0.1", "server:port")
	flag.IntVar(&config.port, "p", 0, "server:port")
	flag.IntVar(&config.core, "core", 1, "number of CPU cores to use")
	flag.StringVar(&config.passwd, "k", "", "password")
	flag.StringVar(&config.method, "m", "", "encryption method, use empty string or rc4")
	flag.IntVar(&config.nconn, "nc", 1, "number of connection to server")
	flag.IntVar(&config.nreq, "nr", 1, "number of request for each connection")
	// flag.IntVar(&config.nsec, "ns", 0, "run how many seconds for each connection")
	flag.BoolVar((*bool)(&debug), "d", false, "print http response body for debugging")

	flag.Parse()

	if config.server == "" || config.port == 0 || config.passwd == "" || len(flag.Args()) != 1 {
		fmt.Printf("Usage: %s -s <server> -p <port> -k <password> <url>\n", os.Args[0])
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

	cipher, err := ss.NewCipher(config.method, config.passwd)
	if err != nil {
		fmt.Println("Error creating cipher:", err)
		os.Exit(1)
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
	// fmt.Println(host)
	rawAddr, err := ss.RawAddr(host)
	if err != nil {
		panic("Error getting raw address.")
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
