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
func PipeThenClose(src, dst NetConnection, done func()) {
	defer done()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	connInfo := fmt.Sprintf("src conn: %v <---> %v, dst conn: %v <---> %v",
		src.RemoteAddr().String(), src.LocalAddr().String(), dst.LocalAddr().String(), dst.RemoteAddr().String())

	for {
		n, err := src.Read(buf)
		if n > 0 {
			Logger.Debug("read n from src", zap.Int("n", n), zap.String("conn info", connInfo))
			var start int
			for start != n {
				// XXX retry may cause the data repeated
				nn, errR := dst.Write(buf[start:n])
				if errR != nil {
					//if errR.(*net.OpError).Timeout() {
					//	Logger.Warn("write into dest TimeOut, retry", zap.String("conn info", connInfo), zap.Error(errR))
					//}

					if err == io.EOF {
						Logger.Info("write meet EOF, close the write", zap.String("conn info", connInfo))
					} else {
						Logger.Error("error in copy from src to dest, write into dest", zap.String("conn info", connInfo), zap.Error(errR))
					}
					dst.CloseWrite()
					return
				}
				Logger.Debug("write n to dest", zap.Int("n", nn), zap.String("conn info", connInfo))
				start += nn
				if nn < n {
					Logger.Info("write dst, nn < n", zap.Int("read n", n), zap.Int("write n", nn), zap.Int("buffer", start), zap.String("conn info", connInfo))
				}
			}
		}

		if err != nil {
			//if err.(*net.OpError).Timeout() {
			//	Logger.Warn("read src TimeOut, retry", zap.String("conn info", connInfo), zap.Error(err))
			//	continue
			//} else if err == io.EOF {

			if err == io.EOF {
				Logger.Info("src connection was closed, shutdown", zap.String("conn info", connInfo), zap.Error(err))
			} else {
				// tell another goroutine to write all and then close, no more data will send
				Logger.Error("error in copy from src to dest", zap.String("conn info", connInfo), zap.Error(err))
			}
			dst.CloseWrite()
			return
		}
	}
}

func PipeUDPThenClose(src net.Conn, dst net.PacketConn, dstaddr string, timeout int) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	raddr, err := net.ResolveUDPAddr("udp", dstaddr)
	if err != nil {
		return
	}

	// TODO
	for {
		n, err := src.Read(buf)
		if n > 0 {
			nn, err := dst.WriteTo(buf[:n], raddr)
			if nn < n {
				Logger.Warn("[UDP] write to the packet connection less than expect", zap.Int("read", n), zap.Int("write", nn),
					zap.Stringer("local", dst.LocalAddr()), zap.Stringer("dst", raddr))
			}
			if err != nil {
				Logger.Error("[UDP] error write to the packet connection", zap.Stringer("local", dst.LocalAddr()), zap.Stringer("dst", raddr))
				dst.Close()
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				return
			}
			Logger.Error("[UDP] error write to the packet connection", zap.Stringer("local", dst.LocalAddr()), zap.Stringer("dst", raddr))
			return
		}
	}
}

func PipeThenCloseFromUDP(src net.PacketConn, dst net.Conn, timeout int) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

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

//func UDPReceiveThenClose(write net.PacketConn, writeAddr net.Addr, readClose net.PacketConn) {
//	// write is the connection, writeAddr is the destionation connection, readclose the local listen package
//	buf := leakyBuf.Get()
//	defer leakyBuf.Put(buf)
//	defer readClose.Close()
//	for {
//		readClose.SetDeadline(time.Now().Add(udpTimeout))
//		n, raddr, err := readClose.ReadFrom(buf)
//		if err != nil {
//			if ne, ok := err.(*net.OpError); ok {
//				if ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE {
//					// log too many open file error
//					// EMFILE is process reaches open file limits, ENFILE is system limit
//					Logger.Error("error in UDP client receive then close, read error:", zap.Error(err))
//				}
//			}
//			Logger.Info("[udp]closed pipe ", zap.String("WriteTo", writeAddr.String()), zap.String("ReadFrom", readClose.LocalAddr().String()))
//			return
//		}
//
//		header := parseHeaderFromAddr(raddr)
//		write.WriteTo(append(header, buf[:n]...), writeAddr)
//	}
//}
