package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
	lenIPv6     = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
	lenDmBase   = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

var (
	reqList            = newReqList()
	natlist            = newNatTable()
	udpTimeout         = 30 * time.Second
	reqListRefreshTime = 5 * time.Minute
)

type natTable struct {
	sync.Mutex
	conns map[string]net.PacketConn
}

func newNatTable() *natTable {
	return &natTable{conns: map[string]net.PacketConn{}}
}

func (table *natTable) DeleteAndClose(index string) {
	table.Lock()
	defer table.Unlock()
	c, ok := table.conns[index]
	if ok {
		c.Close()
		delete(table.conns, index)
	}
}

func (table *natTable) Get(index string) (c net.PacketConn, ok bool, err error) {
	table.Lock()
	defer table.Unlock()
	c, ok = table.conns[index]
	if !ok {
		c, err = net.ListenPacket("udp", "")
		if err != nil {
			return nil, false, err
		}
		table.conns[index] = c
	}
	return
}

type ReqList struct {
	sync.Mutex
	List map[string]([]byte)
}

func newReqList() *ReqList {
	ret := &ReqList{List: map[string]([]byte){}}
	go func() {
		for {
			time.Sleep(reqListRefreshTime)
			ret.Refresh()
		}
	}()
	return ret
}

func (r *ReqList) Refresh() {
	r.Lock()
	defer r.Unlock()
	for k, _ := range r.List {
		delete(r.List, k)
	}
}

func (r *ReqList) Get(dstaddr string) (req []byte, ok bool) {
	r.Lock()
	defer r.Unlock()
	req, ok = r.List[dstaddr]
	return
}

func (r *ReqList) Put(dstaddr string, req []byte) {
	r.Lock()
	defer r.Unlock()
	r.List[dstaddr] = req
	return
}

func ParseHeader(addr net.Addr) ([]byte, int) {
	// if the request address type is domain, it cannot be reverselookuped
	ip, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0
	}
	buf := make([]byte, 20)
	IP := net.ParseIP(ip)
	b1 := IP.To4()
	iplen := 0
	if b1 == nil { //ipv6
		b1 = IP.To16()
		buf[0] = typeIPv6
		iplen = net.IPv6len
	} else { //ipv4
		buf[0] = typeIPv4
		iplen = net.IPv4len
	}
	copy(buf[1:], b1)
	port_i, _ := strconv.Atoi(port)
	binary.BigEndian.PutUint16(buf[1+iplen:], uint16(port_i))
	return buf[:1+iplen+2], 1 + iplen + 2
}

func Pipeloop(ss *SecurePacketConn, addr net.Addr, in net.PacketConn, compatiblemode bool) {
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	defer in.Close()
	for {
		in.SetDeadline(time.Now().Add(udpTimeout))
		n, raddr, err := in.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(*net.OpError); ok {
				if ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE {
					// log too many open file error
					// EMFILE is process reaches open file limits, ENFILE is system limit
					Debug.Println("[udp]read error:", err)
				}
			}
			Debug.Printf("[udp]closed pipe %s<-%s\n", addr, in.LocalAddr())
			return
		}
		// need improvement here
		if req, ok := reqList.Get(raddr.String()); ok {
			if compatiblemode {
				ss.ForceOTAWriteTo(append(req, buf[:n]...), addr)
			} else {
				ss.WriteTo(append(req, buf[:n]...), addr)
			}
		} else {
			header, hlen := ParseHeader(raddr)
			if compatiblemode {
				ss.ForceOTAWriteTo(append(header[:hlen], buf[:n]...), addr)
			} else {
				ss.WriteTo(append(header[:hlen], buf[:n]...), addr)
			}

		}
	}
}

func handleUDPConnection(handle *SecurePacketConn, n int, src net.Addr, receive []byte) {
	var dstIP net.IP
	var reqLen int
	var ota bool
	addrType := receive[idType]
	defer leakyBuf.Put(receive)

	if addrType&OneTimeAuthMask > 0 {
		ota = true
	}
	if handle.IsOta() && !ota {
		Debug.Println("[udp]incoming connection dropped, due to ota enforcement")
		return
	}
	compatiblemode := !handle.IsOta() && ota

	switch addrType & AddrMask {
	case typeIPv4:
		reqLen = lenIPv4
		if len(receive) < reqLen {
			Debug.Println("[udp]invalid received message.")
		}
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv4len])
	case typeIPv6:
		reqLen = lenIPv6
		if len(receive) < reqLen {
			Debug.Println("[udp]invalid received message.")
		}
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv6len])
	case typeDm:
		reqLen = int(receive[idDmLen]) + lenDmBase
		if len(receive) < reqLen {
			Debug.Println("[udp]invalid received message.")
		}
		name := string(receive[idDm0 : idDm0+int(receive[idDmLen])])
		// avoid panic: syscall: string with NUL passed to StringToUTF16 on windows.
		if strings.ContainsRune(name, 0x00) {
			fmt.Println("[udp]invalid domain name.")
			return
		}
		dIP, err := net.ResolveIPAddr("ip", name) // carefully with const type
		if err != nil {
			Debug.Printf("[udp]failed to resolve domain name: %s\n", string(receive[idDm0:idDm0+receive[idDmLen]]))
			return
		}
		dstIP = dIP.IP
	default:
		Debug.Printf("[udp]addrType %d not supported", addrType)
		return
	}
	dst := &net.UDPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(receive[reqLen-2 : reqLen])),
	}
	if _, ok := reqList.Get(dst.String()); !ok {
		req := make([]byte, reqLen)
		copy(req, receive)
		reqList.Put(dst.String(), req)
	}

	remote, exist, err := natlist.Get(src.String())
	if err != nil {
		return
	}
	if !exist {
		Debug.Printf("[udp]new client %s->%s via %s ota=%v\n", src, dst, remote.LocalAddr(), ota)
		go func() {
			Pipeloop(handle, src, remote, compatiblemode)
			natlist.DeleteAndClose(src.String())
		}()
	} else {
		Debug.Printf("[udp]using cached client %s->%s via %s ota=%v\n", src, dst, remote.LocalAddr(), ota)
	}
	if remote == nil {
		fmt.Println("WTF")
	}
	remote.SetDeadline(time.Now().Add(udpTimeout))
	_, err = remote.WriteTo(receive[reqLen:n], dst)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Debug.Println("[udp]write error:", err)
		} else {
			Debug.Println("[udp]error connecting to:", dst, err)
		}
		natlist.DeleteAndClose(src.String())
	}
	// Pipeloop
	return
}

func ReadAndHandleUDPReq(c *SecurePacketConn) {
	buf := leakyBuf.Get()
	n, src, err := c.ReadFrom(buf[0:])
	if err != nil {
		return
	}
	go handleUDPConnection(c, n, src, buf)
}
