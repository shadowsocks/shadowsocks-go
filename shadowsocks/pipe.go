package shadowsocks

import (
	"io"
	"net"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// PipeThenClose copies data from src to dst, close dst when done.
func PipeThenClose(src, dst net.Conn, timeout int, done func()) {
	defer done()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	if timeout > 0 {
		src.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		dst.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}

	n, err := io.Copy(dst, src)
	if err != nil {
		Logger.Error("error in copy from src to dest", zap.Int64("n", n), zap.Stringer("src", src.LocalAddr()), zap.Stringer("dst", dst.RemoteAddr()), zap.Error(err))
		return
	} else {
		Logger.Debug("copy n from src to dest", zap.Int64("n", n), zap.Stringer("src", src.LocalAddr()), zap.Stringer("dst", dst.RemoteAddr()))
	}
}

//func UDPClientReceiveThenClose(write net.PacketConn, writeAddr net.Addr, readClose net.PacketConn) {
//	buf := make([]byte, 4096)
//	defer readClose.Close()
//	for {
//		readClose.SetDeadline(time.Now().Add(udpTimeout))
//		n, _, err := readClose.ReadFrom(buf)
//		if err != nil {
//			if ne, ok := err.(*net.OpError); ok {
//				if ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE {
//					// log too many open file error
//					// EMFILE is process reaches open file limits, ENFILE is system limit
//					Logger.Error("erro in UDP client receive then close, read error:", zap.Error(err))
//				}
//			}
//			//Logger.Info("[udp]closed pipe ", zap.String("msg", fmt.Sprintf("%s<-%s\n", writeAddr, readClose.LocalAddr())))
//			Logger.Info("[udp]closed pipe ", zap.String("WriteTo", writeAddr.String()), zap.String("ReadFrom", readClose.LocalAddr().String()))
//			return
//		}
//		write.WriteTo(buf[:n], writeAddr) //	}
//}

func UDPReceiveThenClose(write net.PacketConn, writeAddr net.Addr, readClose net.PacketConn) {
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
		// need improvement here
		if req, ok := reqList.Get(raddr.String()); ok {
			write.WriteTo(append(req, buf[:n]...), writeAddr)
		} else {
			header := parseHeaderFromAddr(raddr)
			write.WriteTo(append(header, buf[:n]...), writeAddr)
		}
	}
}
