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
			}
		}

		if err != nil {
			if err == io.EOF {
				return
			}
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
