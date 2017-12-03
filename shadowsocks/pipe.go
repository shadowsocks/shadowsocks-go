package shadowsocks

import (
	"net"
)

func Pack(src net.Conn, dst *Conn) { defer dst.Close(); for { if _, err := dst.Packing(src); err != nil { Logger.Warn(err); break } } }
func UnPack(src *Conn, dst net.Conn) { defer dst.Close(); for { if _, err := src.UnPacking(dst); err != nil { Logger.Warn(err); break } } }

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