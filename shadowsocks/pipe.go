package shadowsocks

import (
	// "io"
	"net"
	"time"
)

const (
	NO_TIMEOUT = iota
	SET_TIMEOUT
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

const bufSize = 4096
const nBuf = 2048

var pipeBuf = NewLeakyBuf(nBuf, bufSize)

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn, timeoutOpt int) {
	defer dst.Close()
	buf := pipeBuf.Get()
	defer pipeBuf.Put(buf)
	for {
		if timeoutOpt == SET_TIMEOUT {
			SetReadTimeout(src)
		}
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			if _, err = dst.Write(buf[0:n]); err != nil {
				Debug.Println("write:", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}
