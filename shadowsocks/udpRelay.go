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
	// OneTimeAuthMask is the mask for OTA table bit
	OneTimeAuthMask byte = 0x10
	// AddrMask is used to mask the AddrType
	AddrMask byte = 0xf

	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	headerLenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
	headerLenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
	headerLenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	lenHmacSha1     = 10
	lenDataLen      = 2
	idOTAData0      = lenDataLen + lenHmacSha1
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

func (table *natTable) Delete(index string) net.PacketConn {
	table.Lock()
	defer table.Unlock()
	c, ok := table.conns[index]
	if ok {
		delete(table.conns, index)
		return c
	}
	return nil
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

type requestHeaderList struct {
	sync.Mutex
	List map[string]([]byte)
}

func newReqList() *requestHeaderList {
	ret := &requestHeaderList{List: map[string]([]byte){}}
	go func() {
		for {
			time.Sleep(reqListRefreshTime)
			ret.Refresh()
		}
	}()
	return ret
}

func (r *requestHeaderList) Refresh() {
	r.Lock()
	defer r.Unlock()
	for k := range r.List {
		delete(r.List, k)
	}
}

func (r *requestHeaderList) Get(dstaddr string) (req []byte, ok bool) {
	r.Lock()
	defer r.Unlock()
	req, ok = r.List[dstaddr]
	return
}

func (r *requestHeaderList) Put(dstaddr string, req []byte) {
	r.Lock()
	defer r.Unlock()
	r.List[dstaddr] = req
	return
}

func parseHeaderFromAddr(addr net.Addr) []byte {
	// if the request address type is domain, it cannot be reverselookuped
	ip, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
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
	iPort, _ := strconv.Atoi(port)
	binary.BigEndian.PutUint16(buf[1+iplen:], uint16(iPort))
	return buf[:1+iplen+2]
}

func receiveThenClose(write net.PacketConn, writeAddr net.Addr, readClose net.PacketConn) {
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
					Debug.Println("[udp]read error:", err)
				}
			}
			Debug.Printf("[udp]closed pipe %s<-%s\n", writeAddr, readClose.LocalAddr())
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

// ForwardUDPConn forwards the payload (should with header) to the dst.
// meanwhile, the request header is cached and the connection is alse cached for futher use.
func ForwardUDPConn(handle net.PacketConn, src net.Addr, host string, payload []byte, headerLen int) error {
	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}
	dIP, err := net.ResolveIPAddr("ip", hostname)
	if err != nil {
		return fmt.Errorf("[udp]Failed to solve domain name(%s): %v", hostname, err)
	}
	dstIP := dIP.IP
	dstPort, _ := strconv.Atoi(portStr)
	dst := &net.UDPAddr{
		IP:   dstIP,
		Port: dstPort,
	}
	if _, ok := reqList.Get(dst.String()); !ok {
		req := make([]byte, headerLen)
		copy(req, payload)
		req[0] &= ^OneTimeAuthMask
		reqList.Put(dst.String(), req)
	}

	remote, exist, err := natlist.Get(src.String())
	if err != nil {
		return err
	}
	if !exist {
		Debug.Printf("[udp]new client %s->%s via %s\n", src, dst, remote.LocalAddr())
		go func() {
			receiveThenClose(handle, src, remote)
			natlist.Delete(src.String())
		}()
	} else {
		Debug.Printf("[udp]using cached client %s->%s via %s\n", src, dst, remote.LocalAddr())
	}
	setDeadline(remote)
	_, err = remote.WriteTo(payload[headerLen:], dst)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Debug.Println("[udp]write error:", err)
		} else {
			Debug.Println("[udp]error connecting to:", dst, err)
		}
		if conn := natlist.Delete(src.String()); conn != nil {
			conn.Close()
		}
	}
	return nil
}

// UDPGetRequest deocde the request header from buffer
func UDPGetRequest(buf []byte, auth bool) (host string, headerLen int, compatibleMode bool, err error) {
	addrType := buf[idType]
	ota := addrType&OneTimeAuthMask > 0
	compatibleMode = !auth && ota
	switch addrType & AddrMask {
	case typeIPv4:
		headerLen = headerLenIPv4
		if len(buf) < headerLen {
			Debug.Println("[udp]invalid received message.")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeIPv6:
		headerLen = headerLenIPv6
		if len(buf) < headerLen {
			Debug.Println("[udp]invalid received message.")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeDm:
		headerLen = int(buf[idDmLen]) + headerLenDmBase
		if len(buf) < headerLen {
			Debug.Println("[udp]invalid received message.")
		}
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
		// avoid panic: syscall: string with NUL passed to StringToUTF16 on windows.
		if strings.ContainsRune(host, 0x00) {
			err = errInvalidHostname
			return
		}
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	default:
		Debug.Printf("[udp]addrType %d not supported", addrType)
		return
	}
	return
}
