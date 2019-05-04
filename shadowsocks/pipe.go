package shadowsocks

import (
	"io"
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn, addTraffic func(int), buf []byte, n int) {
	defer dst.Close()
	if buf != nil {
		if n > 0 {
			if _, err := dst.Write(buf[0:n]); err != nil {
				Debug.Println("write:", err)
				leakyBuf.Put(buf)
				return
			}
		}
		leakyBuf.Put(buf)
	}

	io.Copy(src, dst)
	return
}
