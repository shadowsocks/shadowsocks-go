package shadowsocks

import (
	"net"
	"time"

	"sync"
	"reflect"
)

const udpBufSize = 64 * 1024

// Listen on laddr for UDP packets, encrypt and send to server to reach target.
//func UDPLocal(laddr, server, target string, shadow func(net.PacketConn) net.PacketConn) {
//	srvAddr, err := net.ResolveUDPAddr("udp", server)
//	if err != nil {
//		Logger.Warnf("UDP server address error: %v", err)
//		return
//	}
//
//	tgt := ParseAddr(target)
//	if tgt == nil {
//		err = fmt.Errorf("invalid target address: %q", target)
//		Logger.Warnf("UDP target address error: %v", err)
//		return
//	}
//
//	c, err := net.ListenPacket("udp", laddr)
//	if err != nil {
//		Logger.Warnf("UDP local listen error: %v", err)
//		return
//	}
//	defer c.Close()
//
//	nm := NewNATmap(Timeout)
//	buf := make([]byte, udpBufSize)
//	copy(buf, tgt)
//
//	Logger.Infof("UDP tunnel %s <-> %s <-> %s", laddr, server, target)
//	for {
//		n, raddr, err := c.ReadFrom(buf[len(tgt):])
//		if err != nil {
//			Logger.Warnf("UDP local read error: %v", err)
//			continue
//		}
//
//		pc := nm.Get(raddr.String())
//		if pc == nil {
//			pc, err = net.ListenPacket("udp", "")
//			if err != nil {
//				Logger.Warnf("UDP local listen error: %v", err)
//				continue
//			}
//
//			pc = shadow(pc)
//			nm.Add(raddr, c, pc, false)
//		}
//
//		_, err = pc.WriteTo(buf[:len(tgt)+n], srvAddr)
//		if err != nil {
//			Logger.Warnf("UDP local write error: %v", err)
//			continue
//		}
//	}
//}

// Listen on addr for encrypted packets and basically do UDP NAT.
//func udpRemote(addr string, shadow func(net.PacketConn) net.PacketConn) {
//	c, err := net.ListenPacket("udp", addr)
//	if err != nil {
//		Logger.Warnf("UDP remote listen error: %v", err)
//		return
//	}
//	defer c.Close()
//	c = shadow(c)
//
//	nm := NewNATmap(config.UDPTimeout)
//	buf := make([]byte, udpBufSize)
//
//	Logger.Infof("listening UDP on %s", addr)
//	for {
//		n, raddr, err := c.ReadFrom(buf)
//		if err != nil {
//			Logger.Warnf("UDP remote read error: %v", err)
//			continue
//		}
//
//		tgtAddr := SplitAddr(buf[:n])
//		if tgtAddr == nil {
//			Logger.Warnf("failed to split target address from packet: %q", buf[:n])
//			continue
//		}
//
//		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
//		if err != nil {
//			Logger.Warnf("failed to resolve target UDP address: %v", err)
//			continue
//		}
//
//		payload := buf[len(tgtAddr):n]
//
//		pc := nm.Get(raddr.String())
//		if pc == nil {
//			pc, err = net.ListenPacket("udp", "")
//			if err != nil {
//				Logger.Warnf("UDP remote listen error: %v", err)
//				continue
//			}
//
//			nm.Add(raddr, c, pc, true)
//		}
//
//		_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
//		if err != nil {
//			Logger.Warnf("UDP remote write error: %v", err)
//			continue
//		}
//	}
//}

// Packet NAT table
type Natmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func NewNATmap(timeout time.Duration) *Natmap {
	m := &Natmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *Natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *Natmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *Natmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *Natmap) Add(peer net.Addr, dst, src net.PacketConn, srcIncluded bool) {
	m.Set(peer.String(), src)

	go func() {
		timedCopy(dst, peer, src, m.timeout, srcIncluded)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(dst net.PacketConn, target net.Addr, src net.PacketConn, timeout time.Duration, srcIncluded bool) error {
	buf := make([]byte, udpBufSize)

	for {
		//src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			Logger.Fields(LogFields{
				"src_type": reflect.TypeOf(src).String(),
				"err": err,
			}).Warn("src read data error")
			return err
		}

		if srcIncluded { // server -> client: add original packet source
			srcAddr := ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)+n], target)
		} else { // client -> user: strip original packet source
			srcAddr := SplitAddr(buf[:n])
			Logger.Fields(LogFields{
				"n": n,
				"buf": buf[:n],
				//"srcAddr": srcAddr.String(),
			}).Info("check srcAddr")
			_, err = dst.WriteTo(buf[len(srcAddr):n], target)
		}

		if err != nil {
			Logger.Fields(LogFields{
				"target": target,
				"err": err,
			}).Warn("dst write data error")
			return err
		}
	}
}
