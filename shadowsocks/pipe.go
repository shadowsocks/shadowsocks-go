package shadowsocks

import (
	"net"
)

func Pipe(src, dst net.Conn, end chan byte) {
	// Should not use io.Copy here.
	// io.Copy will try to use the ReadFrom interface of TCPConn, but the src
	// here is not a regular file, so sendfile is not applicable.
	// io.Copy will fallback to the normal copy after discovering this,
	// introducing unnecessary overhead.
	buf := make([]byte, 4096)
	for {
		num, err := src.Read(buf)
		// read may return EOF with num > 0
		// should always process num > 0 bytes before handling error
		if num > 0 {
			if _, err = dst.Write(buf[0:num]); err != nil {
				Debug.Println("write:", err)
				break
			}
		}
		if num == 0 { // num == 0 should associate with EOF
			break
		}
		if err != nil {
			Debug.Println("read:", err)
			break
		}
	}
	end <- 1
}
