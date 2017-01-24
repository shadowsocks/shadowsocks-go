package shadowsocks

import (
	"net"
	"time"
)

type deadable interface {
	SetDeadline(time.Time) error
}

func setDeadline(d deadable) {
	if readTimeout != 0 {
		d.SetDeadline(time.Now().Add(readTimeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		setDeadline(src)
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
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
			if err == errBufferTooSmall {
				// unlikely
				Debug.Println("read:", err)
			} else if err == errPacketOtaFailed {
				Debug.Println("read:", err)
			}
			break
		}
	}
}
