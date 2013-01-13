package main

import (
	"flag"
	"fmt"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var config struct {
	server string
	port   int
	passwd string
	core   int
	nconn  int
	nreq   int
	// nsec   int
}

var debug ss.DebugLog

func doOneRequest(client *http.Client, url string, buf []byte) (err error) {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("GET %s error: %v\n", url, err)
		return err
	}
	for err == nil {
		_, err = resp.Body.Read(buf)
		if debug {
			debug.Println(string(buf))
		}
	}
	if err != io.EOF {
		fmt.Printf("Read %s response error: %v\n", url, err)
	}
	return
}

func get(connid int, url, serverAddr string, enctbl *ss.EncryptTable, done chan byte) {
	defer func() {
		done <- 1
	}()
	tr := &http.Transport{
		Dial: func(net, addr string) (c net.Conn, err error) {
			return ss.Dial(addr, serverAddr, enctbl)
		},
	}

	buf := make([]byte, 8192)
	client := &http.Client{Transport: tr}
	for i := 1; i <= config.nreq; i++ {
		doOneRequest(client, url, buf)
		if i%1000 == 0 {
			fmt.Printf("conn %d finished %d get request\n", connid, i)
		}
	}
}

func main() {
	flag.StringVar(&config.server, "s", "127.0.0.1", "server:port")
	flag.IntVar(&config.port, "p", 0, "server:port")
	flag.IntVar(&config.core, "core", 1, "number of CPU cores to use")
	flag.StringVar(&config.passwd, "k", "", "password")
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
	url := flag.Arg(0)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	enctbl := ss.GetTable(config.passwd)
	serverAddr := net.JoinHostPort(config.server, strconv.Itoa(config.port))

	done := make(chan byte)
	for i := 1; i <= config.nconn; i++ {
		go get(i, url, serverAddr, enctbl, done)
	}
	for i := 1; i <= config.nconn; i++ {
		<-done
	}
}
