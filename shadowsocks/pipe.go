package shadowsocks

import (
	"net"
	"io"
)
// chanFromConn creates a channel from a Conn object, and sends everything it
//  Read()s from the socket to the channel.
func chanFromConn(conn net.Conn, b []byte) chan []byte {
	c := make(chan []byte)

	go func() {
		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("Read data error")
				break
			}
		}
	}()

	return c
}

// Pipe creates a full-duplex pipe between the two sockets and transfers data from one to the other.
func Pipe(conn1 net.Conn, conn2 net.Conn, buffer []byte) {
	chan1 := chanFromConn(conn1, buffer)
	chan2 := chanFromConn(conn2, buffer)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				if _, err := conn2.Write(b1); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				if _, err := conn1.Write(b2); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		}
	}
}
///////////////////////////////////////////////////////////////////////
//func Pack(src net.Conn, dst *Conn) { defer dst.Close(); for { if _, err := dst.Packing(src); err != nil { Logger.Warn(err); dst.Close(); break } } }
//func UnPack(src *Conn, dst net.Conn) { defer dst.Close(); for { if _, err := src.UnPacking(dst); err != nil { Logger.Warn(err); dst.Close(); break } } }

func Piping(src, dst net.Conn, buf []byte) {
	defer dst.Close()

	Logger.Fields(LogFields{
		"LocalAddr": src.LocalAddr(),
		"RemoteAddr": src.RemoteAddr(),
	}).Info("check src connection")

	Logger.Fields(LogFields{
		"LocalAddr": dst.LocalAddr(),
		"RemoteAddr": dst.RemoteAddr(),
	}).Info("check dst connection")
	//buf := leakyBuf.Get()
	//defer leakyBuf.Put(buf)
	for {
		SetReadTimeout(src)
		// when src is type of Conn, UnPack data from src.Conn.Read and write to buf;
		// when src is type of net.Conn, it means data come from client, just read to buf
		n, err := src.Read(buf)
		if err != nil {
			//Logger.Fields(LogFields{
			//	//"buf": buf,
			//	"n": n,
			//	"err": err,
			//}).Warn("read error")
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			if err != io.EOF {
				//src.Close()
			}
			break
		}
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			// when dst is type of Conn, just write data from buf to dst.Conn, that is going to send to client
			// when dst is type of net.Conn, Pack data from buf and write to dst.Conn, it means data is going to send to ss server
			if _, err := dst.Write(buf[0:n]); err != nil {
				Logger.Fields(LogFields{
					"buf": buf,
					"n": n,
					"err": err,
				}).Warn("write error")
				//Debug.Println("write:", err)
				//dst.Close()
				break
			}
		}
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
//func Piping(src, dst net.Conn) {
//	defer dst.Close()
//	buf := leakyBuf.Get()
//	defer leakyBuf.Put(buf)
//	for {
//		//SetReadTimeout(src)
//		n, err := src.Read(buf)
//		// read may return EOF with n > 0
//		// should always process n > 0 bytes before handling error
//		if n > 0 {
//			// Note: avoid overwrite err returned by Read.
//			if _, err := dst.Write(buf[0:n]); err != nil {
//				Logger.Fields(LogFields{
//					"buf": buf,
//					"n": n,
//					"err": err,
//				}).Warn("write error")
//				//Debug.Println("write:", err)
//				//dst.Close()
//				break
//			}
//		}
//		if err != nil {
//			// Always "use of closed network connection", but no easy way to
//			// identify this specific error. So just leave the error along for now.
//			// More info here: https://code.google.com/p/go/issues/detail?id=4373
//			/*
//				if bool(Debug) && err != io.EOF {
//					Debug.Println("read:", err)
//				}
//			*/
//			if err != io.EOF {
//				//src.Close()
//			}
//			break
//		}
//	}
//}