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

// make up the ss address block
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

// ForwardUDPConn forwards the payload (should with header) to the dst with UDP.
// meanwhile, the request header is cached and the connection is alse cached for futher use.
func ForwardUDPConn(income net.PacketConn, incomeaddr net.Addr, host string, payload []byte, headerLen int) error {
	// resolve the host into dst ip
	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}
	dIP, err := net.ResolveIPAddr("ip", hostname)
	if err != nil {
		return fmt.Errorf("[UDP]Failed to solve domain name(%s): %v", hostname, err)
	}
	dstIP := dIP.IP
	dstPort, _ := strconv.Atoi(portStr)
	dst := &net.UDPAddr{
		IP:   dstIP,
		Port: dstPort,
	}

	// check if the destination address request header has been cached
	// TODO
	//if _, ok := reqList.Get(dst.String()); !ok {
	//	req := make([]byte, headerLen)
	//	copy(req, payload)
	//	reqList.Put(dst.String(), req)
	//}

	// natlist is to reserve the net connection to source if connected
	// to avoid connect to source each packate
	remote, exist := natlist.Get(incomeaddr.String())
	if !exist {
		c, err := net.ListenPacket("udp", "")
		if err != nil {
			return err
		}
		remote = c
		natlist.Put(incomeaddr.String(), remote)
		Logger.Info("[UDP] new client", zap.Stringer("source", incomeaddr), zap.Stringer("dest", dst),
			zap.Stringer("via", remote.LocalAddr()))
		go func() {
			UDPReceiveThenClose(income, incomeaddr, remote)
			defer func() {
				remote.Close()
				natlist.Delete(incomeaddr.String())
			}()
		}()
	} else {
		Logger.Info("[UDP] using cached client", zap.Stringer("source", incomeaddr), zap.Stringer("dest", dst),
			zap.Stringer("via", remote.LocalAddr()))
	}

	_, err = remote.WriteTo(payload[headerLen:], dst)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Logger.Error("[UDP]write error: too many open fd in system", zap.Error(err))
		} else {
			Logger.Error("[UDP]error connecting to:", zap.Stringer("dest", dst), zap.Error(err))
		}
		if conn := natlist.Delete(incomeaddr.String()); conn != nil {
			conn.Close()
		}
	}
	return nil
}

// UDPGetRequest deocde the request header from buffer
// the Header is the SS address header
func UDPGetRequest(buf []byte) (host string, headerLen int, err error) {
	addrType := buf[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		headerLen = headerLenIPv4
		if len(buf) < headerLen {
			Logger.Error("[UDP]invalid received message.")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeIPv6:
		headerLen = headerLenIPv6
		if len(buf) < headerLen {
			Logger.Error("[UDP]invalid received message.")
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeDm:
		headerLen = int(buf[idDmLen]) + headerLenDmBase
		if len(buf) < headerLen {
			Logger.Error("[UDP]invalid received message.")
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
		Logger.Error("[UDP]addrType not supported", zap.String("address type", fmt.Sprint(addrType)))
		return
	}
	return
}
