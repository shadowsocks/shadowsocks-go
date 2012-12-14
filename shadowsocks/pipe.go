package shadowsocks

import (
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(readTimeout))
}

func Pipe(src, dst net.Conn, end chan byte) {
	// Should not use io.Copy here.
	// io.Copy will try to use the ReadFrom interface of TCPConn, but the src
	// here is not a regular file, so sendfile is not applicable.
	// io.Copy will fallback to the normal copy after discovering this,
	// introducing unnecessary overhead.
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
			Debug.Println("read:", err)
			break
		}
	}
	end <- 1
}
