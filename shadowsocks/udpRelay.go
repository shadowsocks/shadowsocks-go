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

	"go.uber.org/zap"
)

const (
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
)

var (
	reqList            = newReqList()
	natlist            = NewNatTable()
	udpTimeout         = 30 * time.Second
	reqListRefreshTime = 5 * time.Minute
)

// NatTable is intended to help handling UDP
type NatTable struct {
	sync.Mutex
	conns map[string]net.PacketConn
}

// NewNatTable returns an empty NatTable
func NewNatTable() *NatTable {
	return &NatTable{conns: map[string]net.PacketConn{}}
}

// Delete deletes an item from the table
func (table *NatTable) Delete(index string) net.PacketConn {
	table.Lock()
	defer table.Unlock()
	c, ok := table.conns[index]
	if ok {
		delete(table.conns, index)
		return c
	}
	return nil
}

// Get returns an item from the table
func (table *NatTable) Get(index string) (c net.PacketConn, ok bool) {
	table.Lock()
	defer table.Unlock()
	c, ok = table.conns[index]
	return
}

// Put puts an item into the table
func (table *NatTable) Put(index string, c net.PacketConn) {
	table.Lock()
	defer table.Unlock()
	table.conns[index] = c
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
		reqList.Put(dst.String(), req)
	}

	remote, exist := natlist.Get(src.String())
	if !exist {
		c, err := net.ListenPacket("udp", "")
		if err != nil {
			return err
		}
		remote = c
		natlist.Put(src.String(), remote)
		Logger.Info("[udp]new client", zap.Stringer("src", src), zap.Stringer("dst", dst), zap.Stringer("remote", remote.LocalAddr()))
		go func() {
			// FIXME XXX TODO
			//	udpReceiveThenClose(handle, src, remote)
			natlist.Delete(src.String())
		}()
	} else {
		Logger.Debug("[udp]using cached client", zap.Stringer("src", src), zap.Stringer("dst", dst), zap.Stringer("remote", remote.LocalAddr()))
	}
	_, err = remote.WriteTo(payload[headerLen:], dst)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Logger.Error("[udp]write error:", zap.Error(err))
		} else {
			Logger.Error("[udp]error connecting to:", zap.Error(err))
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
	switch addrType & AddrMask {
	case typeIPv4:
		headerLen = headerLenIPv4
		if len(buf) < headerLen {
			Logger.Error("[udp]invalid message received, ipv4 len invalid")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeIPv6:
		headerLen = headerLenIPv6
		if len(buf) < headerLen {
			Logger.Error("[udp]invalid message received, ipv6 len invalid")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeDm:
		headerLen = int(buf[idDmLen]) + headerLenDmBase
		if len(buf) < headerLen {
			Logger.Error("[udp]invalid message received, domain len invalid")
		}
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
		// avoid panic: syscall: string with NUL passed to StringToUTF16 on windows.
		if strings.ContainsRune(host, 0x00) {
			return "", -1, false, ErrInvalidHostname
		}
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	default:
		Logger.Error("[udp]addrType d not supported", zap.Int("addr type", int(addrType)))
		return
	}
	return
}
