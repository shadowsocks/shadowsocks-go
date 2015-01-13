package shadowsocks

import (
	"io"
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

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn, timeoutOpt int) {
	defer dst.Close()
	if timeoutOpt == SET_TIMEOUT {
		SetReadTimeout(src)
	}
	_, e := io.Copy(dst, src)
	if e != nil {
		Debug.Println("Copy:", e)
	}
}
