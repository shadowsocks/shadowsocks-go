package shadowsocks

import (
	// "io"
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

// Pipe copies data between c1 and c2. Closes c1 and c2 when done.
func Pipe(c1, c2 net.Conn) {
	go pipeClose(c1, c2)
	pipeClose(c2, c1)
}

// pipeClose copies data from src to dst. Closes dst when done.
func pipeClose(src, dst net.Conn) {
	defer dst.Close()
	buf := make([]byte, 4096)
	for {
		SetReadTimeout(src)
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
