package shadowsocks

import (
	"net"
	"log"
)

func Pipe(src net.Conn, dst net.Conn, table []byte, end chan int) {
	buf := make([]byte, 4096)
	for {
		num, err := src.Read(buf)
		if err == nil {
			_, err := dst.Write(Encrypt(table, buf[0:num]))
			if err != nil {
				log.Println("write:", err)
				end <- 1
				return
			}
		} else {
			log.Println("read:", err)
			end <- 1
			return
		}
		if num == 0 {
			end <- 1
			return
		}
	}
}

