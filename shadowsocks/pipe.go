package shadowsocks

import (
	"io"
	"net"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// PipeThenClose copies data from src to dst, close dst when done.
func PipeThenClose(src, dst net.Conn, timeout int) {
	// FIXME when to close the connection
	//defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		if timeout > 0 {
			src.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			dst.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		}
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				Logger.Error("erro in pipe then close, dst write", zap.Error(err))
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			if err != io.EOF {
				Logger.Error("read error form src", zap.Stringer("src", src.LocalAddr()), zap.Stringer("dst", dst.RemoteAddr()), zap.Error(err))
			}
			if err == errBufferTooSmall || err == ErrPacketOtaFailed {
				Logger.Error("erro in pipe then close", zap.Error(err))
			}
			break
		}
		Logger.Debug("write n from src to dest", zap.Int("n", n), zap.Stringer("src", src.LocalAddr()),
			zap.Stringer("dst", dst.RemoteAddr()), zap.Error(err))
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

// XXX is this suould be here?
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
