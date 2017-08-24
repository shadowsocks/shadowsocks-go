package shadowsocks

import (
	"encoding/binary"
	"io"
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
	//reqList            = newReqList()
	natTable           = NewNatTable()
	natTableLock       = sync.Mutex{}
	udpTimeout         = 30 * time.Second
	reqListRefreshTime = 5 * time.Minute
	UDPBufferPool      = NewLeakyBuf(1024, UDPMaxSize)
)

// BackwardInfo is defined for the backword packet to the src address
type BackwardInfo struct {
	srcAddr net.Addr
	payload []byte
}

type NatPacketUnit struct {
	net.PacketConn
	cancleller chan int
}

// NatTable used to map the incomming packet to the outgoing packet listener
type NatTable struct {
	sync.RWMutex
	//nat map[string]net.PacketConn
	nat map[string]*NatPacketUnit
}

// NewNatTable returns an empty NatTable
func NewNatTable() *NatTable {
	//return &NatTable{nat: make(map[string]net.PacketConn, 256)}
	return &NatTable{nat: make(map[string]*NatPacketUnit, 256)}
}

func (table *NatTable) Get(src net.Addr) (*NatPacketUnit, bool) {
	table.RLock()
	defer table.RUnlock()
	packetListen, ok := table.nat[src.String()]
	return packetListen, ok
}

func (table *NatTable) Put(src net.Addr, packetln net.PacketConn) {
	table.Lock()
	defer table.Unlock()
	cancel := make(chan int, 1)
	natTable.nat[src.String()] = &NatPacketUnit{packetln, cancel}
}

// Delete deletes an item from the table
// can be called parallel
func (table *NatTable) Delete(src string) {
	table.Lock()
	defer table.Unlock()
	if ln, ok := table.nat[src]; ok {
		ln.Close()
		close(ln.cancleller)
		delete(table.nat, src)
	}
}

//type requestHeaderList struct {
//	sync.RWMutex
//	List map[string]([]byte)
//}
//
//func newReqList() *requestHeaderList {
//	ret := &requestHeaderList{List: map[string]([]byte){}}
//	go func() {
//		for {
//			time.Sleep(reqListRefreshTime)
//			ret.Refresh()
//		}
//	}()
//	return ret
//}
//
//func (r *requestHeaderList) Refresh() {
//	r.Lock()
//	defer r.Unlock()
//	for k := range r.List {
//		delete(r.List, k)
//	}
//}
//
//func (r *requestHeaderList) Get(dstaddr string) (req []byte, ok bool) {
//	r.Lock()
//	defer r.Unlock()
//	req, ok = r.List[dstaddr]
//	return
//}
//
//func (r *requestHeaderList) Put(dstaddr string, req []byte) {
//	r.Lock()
//	defer r.Unlock()
//	r.List[dstaddr] = req
//	return
//}
//
//// make up the ss address block
//func parseHeaderFromAddr(addr net.Addr) []byte {
//	// if the request address type is domain, it cannot be reverselookuped
//	ip, port, err := net.SplitHostPort(addr.String())
//	if err != nil {
//		return nil
//	}
//	buf := make([]byte, 20)
//	IP := net.ParseIP(ip)
//	b1 := IP.To4()
//	iplen := 0
//	if b1 == nil { //ipv6
//		b1 = IP.To16()
//		buf[0] = typeIPv6
//		iplen = net.IPv6len
//	} else { //ipv4
//		buf[0] = typeIPv4
//		iplen = net.IPv4len
//	}
//	copy(buf[1:], b1)
//	iPort, _ := strconv.Atoi(port)
//	binary.BigEndian.PutUint16(buf[1+iplen:], uint16(iPort))
//	return buf[:1+iplen+2]
//}

// ForwardUDPConn forwards the payload (should with header) to the dst with UDP.
// meanwhile, the request header is cached and the connection is else cached for further use.
func ForwardUDPConn(serverIn *SecurePacketConn, src net.Addr, payload []byte) error {
	// unpacket the incomming request and get the dest host and payload
	dstHost, headerLen, err := UDPGetRequest(payload)
	if err != nil {
		Logger.Error("[UDP] failed to get request", zap.Error(err))
		return err
	}
	dstAddr, err := net.ResolveUDPAddr("udp", dstHost)
	if err != nil {
		Logger.Error("[UDP] error in resolve dest addr", zap.Error(err))
		return err
	}

	// check if the destination address request header has been cached
	// cache the request header for the incomming packet connecion which will be prepend to the backward payload
	reqHeader := make([]byte, headerLen)
	copy(reqHeader, payload)

	// TODO here used to have a timer to remove the cache when timeout, should this request header be equal?
	//if _, ok := reqList.Get(dstHost); !ok {
	//	req := make([]byte, headerLen)
	//	copy(req, payload)
	//	reqList.Put(dstHost, req)
	//}

	// put src into the NAT forward table
	// packetln is used to serve the src packet connection to write out packet with
	forwardPacketln, ok := natTable.Get(src)
	if !ok {
		// initialize the packet listener into the nat table
		packetln, err := net.ListenPacket("udp", "")
		if err != nil {
			Logger.Error("[UDP] error in listen outgoing packet listener", zap.Error(err))
			return err
		}

		natTableLock.Lock()
		if packetListen, ok := natTable.nat[src.String()]; ok {
			// other goroutine has creat the packet connection
			forwardPacketln = packetListen
		} else {
			natTable.Put(src, packetln)

			// Set up the backward worker gorotine for this packetln
			// this is the key logical for backward UDP request to ss-local
			go func() {
				defer natTable.Delete(src.String())

				buf := UDPBufferPool.Get()
				defer UDPBufferPool.Put(buf)

				pktUnit, ok := natTable.Get(src)
				if !ok {
					Logger.Error("[UDP] error in get packet goroutine", zap.Error(err))
					return
				}

				for {
					select {
					case <-pktUnit.cancleller:
						Logger.Info("[UDP] Received the close, shutdown the forwarder goroutine", zap.Stringer("incomming conn addr", src),
							zap.Stringer("forwarder local addr", pktUnit.LocalAddr()))
						return
					default:
						n, raddr, err := packetln.ReadFrom(buf)
						if err != nil {
							if n > 0 {
								serverIn.WriteTo(append(reqHeader, buf[:n]...), src)
							}
							if err != io.EOF {
								Logger.Error("[UDP] error in udp backward read", zap.Stringer("remote_addr", raddr),
									zap.Stringer("dest_addr", src), zap.Error(err))
							}
							Logger.Info("[UDP] in udp backward read EOF", zap.Stringer("remote_addr", raddr),
								zap.Stringer("dest_addr", src), zap.Error(err))
							return
						}
						nn, err := serverIn.WriteTo(append(reqHeader, buf[:n]...), src)
						if err != nil {
							Logger.Error("[UDP] error in udp backward write", zap.Stringer("remote_addr", raddr),
								zap.Stringer("dest_addr", src), zap.Error(err))
						}
						if nn != n {
							Logger.Error("[UDP] error in udp backward write", zap.Stringer("remote_addr", raddr),
								zap.Stringer("dest_addr", src), zap.Error(err))
						}
					}
				}
			}()

			natTableLock.Unlock()
		}
	}

	_, err = forwardPacketln.WriteTo(payload[headerLen:], dstAddr)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			Logger.Error("[UDP] write error: too many open fd in system", zap.Stringer("dst", dstAddr), zap.Error(err))
		} else {
			Logger.Error("[UDP] error in forward to the dest address", zap.Stringer("dst", dstAddr), zap.Error(err))
		}
		natTable.Delete(src.String())
		//FIXME goroutine was not terminate
		return err
	}
	Logger.Info("[UDP] forward UDP connecion", zap.Stringer("source", src), zap.Stringer("dest", dstAddr),
		zap.Stringer("via", forwardPacketln.LocalAddr()))

	return nil
}

// UDPGetRequest parse the request header from buffer
// the Header is the SS address header
// TODO need a unit test
func UDPGetRequest(buf []byte) (host string, headerLen int, err error) {
	addrType := buf[idType]
	switch addrType & AddrMask {
	case typeIPv4:
		headerLen = headerLenIPv4
		if len(buf) < headerLen {
			return "", -1, ErrInvalidPacket
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeIPv6:
		headerLen = headerLenIPv6
		if len(buf) < headerLen {
			return "", -1, ErrInvalidPacket
		}
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	case typeDm:
		headerLen = int(buf[idDmLen]) + headerLenDmBase
		if len(buf) < headerLen {
			return "", -1, ErrInvalidPacket
		}
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
		// avoid panic: syscall: string with NUL passed to StringToUTF16 on windows.
		if strings.ContainsRune(host, 0x00) {
			return "", -1, ErrInvalidHostname
		}

		// look up host for request
		ip, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return "", -1, err
		}
		host = ip.String()

		// FIXME return the first record of domain could cause error?
		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	default:
		return "", -1, ErrInvalidPacket
	}

	return host, headerLen, nil
}

//// NatTable is intended to help handling UDP
//type NatTable struct {
//	sync.Mutex
//	conns map[string]net.PacketConn
//}
//
//// NewNatTable returns an empty NatTable
//func NewNatTable() *NatTable {
//	return &NatTable{conns: map[string]net.PacketConn{}}
//}
//
//// Delete deletes an item from the table
//func (table *NatTable) Delete(index string) net.PacketConn {
//	table.Lock()
//	defer table.Unlock()
//	c, ok := table.conns[index]
//	if ok {
//		delete(table.conns, index)
//		return c
//	}
//	return nil
//}
//
//// Get returns an item from the table
//func (table *NatTable) Get(index string) (c net.PacketConn, ok bool) {
//	table.Lock()
//	defer table.Unlock()
//	c, ok = table.conns[index]
//	return
//}
//
//// Put puts an item into the table
//func (table *NatTable) Put(index string, c net.PacketConn) {
//	table.Lock()
//	defer table.Unlock()
//	table.conns[index] = c
//}
//
//type requestHeaderList struct {
//	sync.Mutex
//	List map[string]([]byte)
//}
//
//func newReqList() *requestHeaderList {
//	ret := &requestHeaderList{List: map[string]([]byte){}}
//	go func() {
//		for {
//			time.Sleep(reqListRefreshTime)
//			ret.Refresh()
//		}
//	}()
//	return ret
//}
//
//func (r *requestHeaderList) Refresh() {
//	r.Lock()
//	defer r.Unlock()
//	for k := range r.List {
//		delete(r.List, k)
//	}
//}
//
//func (r *requestHeaderList) Get(dstaddr string) (req []byte, ok bool) {
//	r.Lock()
//	defer r.Unlock()
//	req, ok = r.List[dstaddr]
//	return
//}
//
//func (r *requestHeaderList) Put(dstaddr string, req []byte) {
//	r.Lock()
//	defer r.Unlock()
//	r.List[dstaddr] = req
//	return
//}
//
//func parseHeaderFromAddr(addr net.Addr) []byte {
//	// if the request address type is domain, it cannot be reverselookuped
//	ip, port, err := net.SplitHostPort(addr.String())
//	if err != nil {
//		return nil
//	}
//	buf := make([]byte, 20)
//	IP := net.ParseIP(ip)
//	b1 := IP.To4()
//	iplen := 0
//	if b1 == nil { //ipv6
//		b1 = IP.To16()
//		buf[0] = typeIPv6
//		iplen = net.IPv6len
//	} else { //ipv4
//		buf[0] = typeIPv4
//		iplen = net.IPv4len
//	}
//	copy(buf[1:], b1)
//	iPort, _ := strconv.Atoi(port)
//	binary.BigEndian.PutUint16(buf[1+iplen:], uint16(iPort))
//	return buf[:1+iplen+2]
//}
//
//// ForwardUDPConn forwards the payload (should with header) to the dst.
//// meanwhile, the request header is cached and the connection is alse cached for futher use.
//func ForwardUDPConn(handle net.PacketConn, src net.Addr, host string, payload []byte, headerLen int) error {
//	hostname, portStr, err := net.SplitHostPort(host)
//	if err != nil {
//		return err
//	}
//	dIP, err := net.ResolveIPAddr("ip", hostname)
//	if err != nil {
//		return fmt.Errorf("[udp]Failed to solve domain name(%s): %v", hostname, err)
//	}
//	dstIP := dIP.IP
//	dstPort, _ := strconv.Atoi(portStr)
//	dst := &net.UDPAddr{
//		IP:   dstIP,
//		Port: dstPort,
//	}
//	if _, ok := reqList.Get(dst.String()); !ok {
//		req := make([]byte, headerLen)
//		copy(req, payload)
//		reqList.Put(dst.String(), req)
//	}
//
//	remote, exist := natlist.Get(src.String())
//	if !exist {
//		c, err := net.ListenPacket("udp", "")
//		if err != nil {
//			return err
//		}
//		remote = c
//		natlist.Put(src.String(), remote)
//		Logger.Info("[udp]new client", zap.Stringer("src", src), zap.Stringer("dst", dst), zap.Stringer("remote", remote.LocalAddr()))
//		go func() {
//			// FIXME XXX TODO
//			//	udpReceiveThenClose(handle, src, remote)
//			natlist.Delete(src.String())
//		}()
//	} else {
//		Logger.Debug("[udp]using cached client", zap.Stringer("src", src), zap.Stringer("dst", dst), zap.Stringer("remote", remote.LocalAddr()))
//	}
//	_, err = remote.WriteTo(payload[headerLen:], dst)
//	if err != nil {
//		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
//			// log too many open file error
//			// EMFILE is process reaches open file limits, ENFILE is system limit
//			Logger.Error("[udp]write error:", zap.Error(err))
//		} else {
//			Logger.Error("[udp]error connecting to:", zap.Error(err))
//		}
//		if conn := natlist.Delete(src.String()); conn != nil {
//			conn.Close()
//		}
//	}
//	return nil
//}
//
//// UDPGetRequest deocde the request header from buffer
//func UDPGetRequest(buf []byte, auth bool) (host string, headerLen int, compatibleMode bool, err error) {
//	addrType := buf[idType]
//	switch addrType & AddrMask {
//	case typeIPv4:
//		headerLen = headerLenIPv4
//		if len(buf) < headerLen {
//			Logger.Error("[udp]invalid message received, ipv4 len invalid")
//		}
//		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
//		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
//		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
//	case typeIPv6:
//		headerLen = headerLenIPv6
//		if len(buf) < headerLen {
//			Logger.Error("[udp]invalid message received, ipv6 len invalid")
//		}
//		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
//		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
//		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
//	case typeDm:
//		headerLen = int(buf[idDmLen]) + headerLenDmBase
//		if len(buf) < headerLen {
//			Logger.Error("[udp]invalid message received, domain len invalid")
//		}
//		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
//		// avoid panic: syscall: string with NUL passed to StringToUTF16 on windows.
//		if strings.ContainsRune(host, 0x00) {
//			return "", -1, false, ErrInvalidHostname
//		}
//		port := binary.BigEndian.Uint16(buf[headerLenIPv4-2 : headerLenIPv4])
//		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
//	default:
//		Logger.Error("[udp]addrType d not supported", zap.Int("addr type", int(addrType)))
//		return
//	}
//	return
//}
