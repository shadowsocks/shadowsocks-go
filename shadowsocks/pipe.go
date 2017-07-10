package shadowsocks

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// NetConnection inmlements the net.Conn & net.TcpConn with Shutdown liked function
type NetConnection interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

// PipeThenClose copies data from src to dst, close dst when done.
func PipeThenClose(src, dst NetConnection, timeout int, done func()) {
	defer done()
	if timeout > 0 {
		src.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		dst.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}

	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	connInfo := fmt.Sprintf("src conn: %v <---> %v, dst conn: %v <---> %v",
		src.LocalAddr().String(), src.RemoteAddr().String(), dst.LocalAddr().String(), dst.RemoteAddr().String())

	for {
		n, err := src.Read(buf)
		if n > 0 {
			nn, err := dst.Write(buf[0:n])
			if nn < n {
				Logger.Error("error in write dst, nn < n", zap.String("conn info", connInfo), zap.Error(err))
			}
			if err != nil {
				Logger.Error("error in pipe then close, dst write, closing dst write", zap.String("conn info", connInfo), zap.Error(err))
				if err = dst.CloseWrite(); err != nil {
					Logger.Error("error in close dst write", zap.String("conn info", connInfo), zap.Error(err))
				}
			}
		}

		if err != nil {
			// IOTimeout is a common error while using the http-socks5 proxy
			src.CloseRead()
			dst.CloseWrite()
			if err == io.EOF {
				Logger.Info("src connection was closed, shutdown", zap.String("conn info", connInfo), zap.Error(err))
			} else {
				// tell another goroutine to write all and then close, no more data will send
				Logger.Error("error in copy from src to dest", zap.String("conn info", connInfo), zap.Error(err))
			}
			break
		}
		Logger.Debug("write n from src to dest", zap.Int("n", n), zap.String("conn info", connInfo))
	}

	// Abandoned code: cause can not distinguish the error occoured on src or dst connection
	//for {
	//	n, err := io.Copy(dst, src)
	//	if err != nil {
	//		if err == io.EOF {
	//			Logger.Info("src connection was closed, shutdown", zap.String("src", fmt.Sprintf("%v <---> %v", src.LocalAddr().String(), src.RemoteAddr().String())),
	//				zap.String("dst", fmt.Sprintf("%v <---> %v", dst.LocalAddr().String(), dst.RemoteAddr().String())), zap.Error(err))
	//		} else {
	//			Logger.Error("error in copy from src to dest", zap.String("src", fmt.Sprintf("%v <---> %v", src.LocalAddr().String(), src.RemoteAddr().String())),
	//				zap.String("dst", fmt.Sprintf("%v <---> %v", dst.LocalAddr().String(), dst.RemoteAddr().String())), zap.Error(err))
	//		}
	//		//err = src.CloseRead()
	//		//if err != nil {
	//		//	Logger.Error("error in close the read for src connection", zap.String("src", fmt.Sprintf("%v <---> %v", src.LocalAddr().String(),
	//		//		src.RemoteAddr().String())), zap.String("dst", fmt.Sprintf("%v <---> %v", dst.LocalAddr().String(), dst.RemoteAddr().String())), zap.Error(err))
	//		//}
	//		//err = dst.CloseWrite()
	//		//if err != nil {
	//		//	Logger.Error("error in close the read for src connection", zap.String("src", fmt.Sprintf("%v <---> %v", src.LocalAddr().String(),
	//		//		src.RemoteAddr().String())), zap.String("dst", fmt.Sprintf("%v <---> %v", dst.LocalAddr().String(), dst.RemoteAddr().String())), zap.Error(err))
	//		//}
	//		return
	//	} else {
	//		Logger.Debug("copy n from src to dest", zap.Int64("n", n), zap.String("src", fmt.Sprintf("%v <---> %v", src.LocalAddr().String(), src.RemoteAddr().String())),
	//			zap.String("dst", fmt.Sprintf("%v <---> %v", dst.LocalAddr().String(), dst.RemoteAddr().String())))
	//	}
	//}
}

func PipeUDPThenClose(src net.Conn, dst net.PacketConn, dstaddr string, timeout int) {
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	raddr, err := net.ResolveUDPAddr("udp", dstaddr)
	if err != nil {
		return
	}

	// TODO
	for {
		n, err := src.Read(buf)
		if n > 0 {
			nn, err := dst.WriteTo(buf[:n], raddr)
			if nn < n || err != nil {
				Logger.Error("[E] error write to the packet connection", zap.Stringer("local", dst.LocalAddr()), zap.Stringer("dst", raddr))
			}
		}

		if err != nil {
			if err == io.EOF {
				return
			}
			Logger.Error("[E] error write to the packet connection", zap.Stringer("local", dst.LocalAddr()), zap.Stringer("dst", raddr))
			return
		}
	}
}

func PipeThenCloseFromUDP(src net.PacketConn, dst net.Conn, timeout int) {
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		src.SetDeadline(time.Now().Add(udpTimeout))
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(*net.OpError); ok {
				if ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE {
					// log too many open file error
					// EMFILE is process reaches open file limits, ENFILE is system limit
					Logger.Error("error in UDP client receive then close, read error:", zap.Error(err))
				}
			}
			Logger.Info("[udp]closed pipe ", zap.Stringer("WriteTo", dst.RemoteAddr()), zap.String("ReadFrom", src.LocalAddr().String()))
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			Logger.Error("error in pipe to the tcp", zap.Stringer("remote", dst.RemoteAddr()))
		}
	}
}

func UDPReceiveThenClose(write net.PacketConn, writeAddr net.Addr, readClose net.PacketConn) {
	// write is the connection, writeAddr is the destionation connection, readclose the local listen package
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	defer readClose.Close()
	for {
		readClose.SetDeadline(time.Now().Add(udpTimeout))
		n, raddr, err := readClose.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(*net.OpError); ok {
				if ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE {
					// log too many open file error
					// EMFILE is process reaches open file limits, ENFILE is system limit
					Logger.Error("error in UDP client receive then close, read error:", zap.Error(err))
				}
			}
			Logger.Info("[udp]closed pipe ", zap.String("WriteTo", writeAddr.String()), zap.String("ReadFrom", readClose.LocalAddr().String()))
			return
		}

		header := parseHeaderFromAddr(raddr)
		write.WriteTo(append(header, buf[:n]...), writeAddr)
	}
}
