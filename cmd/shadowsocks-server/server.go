package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"flag"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var debug ss.DebugLog

var errAddrType = errors.New("addr type not supported")

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
	var n int
	// read till we get possible domain length field
	ss.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	reqLen := lenIP
	if buf[idType] == typeDm {
		reqLen = int(buf[idDmLen]) + lenDmBase
	} else if buf[idType] != typeIP {
		err = errAddrType
		return
	}

	if n < reqLen { // rare case
		ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// TODO add ipv6 support
	if buf[idType] == typeDm {
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	} else if buf[idType] == typeIP {
		addrIp := make(net.IP, 4)
		copy(addrIp, buf[idIP0:idIP0+4])
		host = addrIp.String()
	}
	// parse port
	var port int16
	sb := bytes.NewBuffer(buf[reqLen-2 : reqLen])
	binary.Read(sb, binary.BigEndian, &port)

	host += ":" + strconv.Itoa(int(port))
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
		log.Println("error getting request:", err)
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			debug.Println("error connecting to:", host, err)
		}
		return
	}
	defer remote.Close()
	// write extra bytes read from 
	if extra != nil {
		debug.Println("getRequest read extra data, writing to remote, len", len(extra))
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

const tableCacheFile = "table.cache"

var table struct {
	cache  map[string]*ss.EncryptTable
	getCnt int32
	hitCnt int32
}

func initTableCache(config *ss.Config) {
	var exists bool
	var err error
	if !config.CacheEncTable {
		goto emptyCache
	}
	exists, err = ss.IsFileExists(tableCacheFile)
	if exists {
		// load table cache from file
		f, err := os.Open(tableCacheFile)
		if err != nil {
			log.Println("error opening table cache:", err)
			goto emptyCache
		}
		defer f.Close()

		dec := gob.NewDecoder(bufio.NewReader(f))
		if err = dec.Decode(&table.cache); err != nil {
			log.Println("error loading table cache:", err)
			goto emptyCache
		}
		debug.Println("table cache loaded from disk")
		return
	}
	if err != nil {
		log.Println("table cache:", err)
	}

emptyCache:
	debug.Println("creating empty table cache")
	table.cache = map[string]*ss.EncryptTable{}
}

func storeTableCache(config *ss.Config) {
	if !config.CacheEncTable || table.getCnt == table.hitCnt {
		return
	}

	const tmpPath = "tmp.cache"
	f, err := os.Create(tmpPath)
	if err != nil {
		log.Println("can't create tmp table cache")
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := gob.NewEncoder(w)
	if err = enc.Encode(table.cache); err != nil {
		log.Println("error saving tmp table cache:", err)
		return
	}
	if err = w.Flush(); err != nil {
		log.Println("error flushing table cache:", err)
		return
	}
	if err = os.Rename(tmpPath, tableCacheFile); err != nil {
		log.Printf("error renaming %s to %s: %v\n", tmpPath, tableCacheFile, err)
		return
	}
	debug.Println("table cache saved")
}

func getTable(password string) (tbl *ss.EncryptTable) {
	if table.cache != nil {
		var ok bool
		tbl, ok = table.cache[password]
		if ok {
			atomic.AddInt32(&table.hitCnt, 1)
			debug.Println("table cache hit for password:", password)
			return
		}
		tbl = ss.GetTable(password)
		table.cache[password] = tbl
	} else {
		tbl = ss.GetTable(password)
	}
	return
}

type PortListener struct {
	password string
	listener net.Listener
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	pm.Unlock()
}

func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password)
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port, _ := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("try listening port %v: %v\n", port, err)
		return
	}
	passwdManager.add(port, password, ln)
	encTbl := getTable(password)
	atomic.AddInt32(&table.getCnt, 1)
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		go handleConnection(ss.NewConn(conn, encTbl))
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			log.Println("must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			log.Println("given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config

func main() {
	var cmdConfig ss.Config

	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 60, "connection timeout (in seconds)")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")

	flag.Parse()
	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		enough := enoughOptions(&cmdConfig)
		if !(enough && os.IsNotExist(err)) {
			log.Printf("error reading %s: %v\n", configFile, err)
		}
		if !enough {
			return
		}
		log.Println("using all options from command line")
		config = &cmdConfig
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}

	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}

	initTableCache(config)
	for port, password := range config.PortPassword {
		go run(port, password)
	}
	// Wait all ports have get it's encryption table
	for int(table.getCnt) != len(config.PortPassword) {
		time.Sleep(1 * time.Second)
	}
	storeTableCache(config)
	log.Println("all ports ready")

	table.cache = nil // release memory
	waitSignal()
}
