package main

import (
	"net"
	"time"
	"os"
	"strings"
	"bytes"
	"fmt"
	"encoding/json"
	"log"
)

func managerDaemon(conn *net.UDPConn) {
	// add a report address set for ping response
	// according to https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users#example-code
	ctx := make(chan bool, 1)
	defer close(ctx)
	reportConnSet := make(map[string]*net.UDPAddr, 1024)
	go func() {
		timer := time.Tick(10 * time.Second)
		for {
			<-timer
			switch {
			case <-ctx:
				return
			default:
				for _, addr := range reportConnSet {
					res := reportStat()
					if len(res) == 0 {
						continue
					}
					conn.WriteToUDP(res, addr)
				}
			}
		}
	}()

	for {
		data := make([]byte, 300)
		_, remote, err := conn.ReadFromUDP(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read UDP manage msg, error: ", err.Error())
			continue
		}
		command := string(data)
		var res []byte
		switch {
		case strings.HasPrefix(command, "add:"):
			res = handleAddPort(bytes.Trim(data[4:], "\x00\r\n "))
		case strings.HasPrefix(command, "remove:"):
			res = handleRemovePort(bytes.Trim(data[7:], "\x00\r\n "))
		case strings.HasPrefix(command, "ping"):
			conn.WriteToUDP(handlePing(), remote)
			reportConnSet[remote.String()] = remote // append the host into the report list
		case strings.HasPrefix(command, "ping-stop"): // add the stop ping command
			conn.WriteToUDP(handlePing(), remote)
			delete(reportConnSet, remote.String())
		}
		if len(res) == 0 {
			continue
		}
		_, err = conn.WriteToUDP(res, remote)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write UDP manage msg, error: ", err.Error())
			continue
		}
	}
}

func handleAddPort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
		Password   string      `json:"password"`
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil || params.Password == "" {
		fmt.Fprintln(os.Stderr, "Failed to parse add req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	passwdManager.updatePortPasswd(port, params.Password)
	return []byte("ok")
}

func handleRemovePort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse remove req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	log.Printf("closing port %s\n", port)
	passwdManager.del(port)
	return []byte("ok")
}

func handlePing() []byte {
	return []byte("pong")
}

// reportStat get the stat:trafficStat and return every 10 sec as for the protocol
// https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users
func reportStat() []byte {
	stats := passwdManager.getTrafficStats()
	var buf bytes.Buffer
	buf.WriteString("stat: ")
	ret, _ := json.Marshal(stats)
	buf.Write(ret)
	return buf.Bytes()
}
