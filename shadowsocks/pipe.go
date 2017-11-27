package shadowsocks

import (
	"net"
	"io"
)

type Pipe interface {
	Pack(src, dst net.Conn)
	UnPack(src, dst net.Conn)
}

//func Piping(local, remote net.Conn, cipher *Cipher) {
//	if cipher.CType == C_STREAM {
//		p := &PipeStream{Cipher: cipher.Inst.(*CipherStream)}
//		go p.Pack(local, remote)
//		p.UnPack(remote, local)
//	} else if cipher.CType == C_AEAD {
//		p := &PipeAead{Cipher: cipher.Inst.(*CipherAead)}
//		go p.Pack(local, remote)
//		p.UnPack(remote, local)
//	}
//}
// chanFromConn creates a channel from a Conn object, and sends everything it
//  Read()s from the socket to the channel.
func chanFromConn(conn net.Conn) chan []byte {
	b := leakyBuf.Get()
	defer leakyBuf.Put(b)
	c := make(chan []byte)

	go func() {
		//b := leakyBuf.Get()

		for {
			n, err := conn.Read(b)
			if n > 0 {
				//res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				//copy(res, b[:n])
				//c <- res
				c <- b[:n]
			}
			if err != nil {
				//c <- nil
				break
			}
		}
	}()

	return c
}

//func Piping(conn1 net.Conn, conn2 net.Conn) {
//	defer conn1.Close()
//	defer conn2.Close()
//	chan1 := chanFromConn(conn1)
//	chan2 := chanFromConn(conn2)
//
//	for {
//		select {
//		case b1 := <-chan1:
//			if b1 == nil {
//				break
//			} else {
//				conn2.Write(b1)
//			}
//		case b2 := <-chan2:
//			if b2 == nil {
//				break
//			} else {
//				conn1.Write(b2)
//			}
//		}
//	}
//}

// PipeThenClose copies data from src to dst, closes dst when done.
func Piping(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		//SetReadTimeout(src)
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			//Logger.Fields(LogFields{
			//	"buf": buf[0:n],
			//	"buf_str": string(buf[0:n]),
			//}).Warn("Check write buffer")
			if _, err := dst.Write(buf[0:n]); err != nil {
				//Debug.Println("write:", err)
				dst.Close()
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
			if err != io.EOF {
				src.Close()
			}
			break
		}
	}
}