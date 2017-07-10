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
	UDPMaxSize = 65507 // max udp packet size1
)

var (
	reqList            = newReqList()
	natTable           = NewNatTable()
	udpTimeout         = 30 * time.Second
	reqListRefreshTime = 5 * time.Minute
	UDPBufferPool      = NewLeakyBuf(1024, UDPMaxSize)
)

// BackwardInfo is defined for the backword packet to the src address
type BackwardInfo struct {
	srcAddr net.Addr
	payload []byte
}

// NatTable used to map the incomming packet to the outgoing packet listener
type NatTable struct {
	sync.RWMutex
	nat map[string]net.PacketConn
}

// NewNatTable returns an empty NatTable
func NewNatTable() *NatTable {
	return &NatTable{nat: make(map[string]net.PacketConn, 256)}
}

func (table *NatTable) Get(src net.Addr) (net.PacketConn, bool) {
	table.RLock()
	defer table.RUnlock()
	packetListen, ok := table.nat[src.String()]
	return packetListen, ok
}

func (table *NatTable) Put(src net.Addr, packetln net.PacketConn) {
	table.Lock()
	defer table.Unlock()
	natTable.nat[src.String()] = packetln
}

// Delete deletes an item from the table
func (table *NatTable) Delete(src string) {
	table.Lock()
	defer table.Unlock()
	if ln, ok := table.nat[src]; ok {
		ln.Close()
		delete(table.nat, src)
	}
}

type requestHeaderList struct {
	sync.RWMutex
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
func ForwardUDPConn(serverIn *SecurePacketConn, src net.Addr, payload []byte) error {
	// unpacket the incomming request and get the dest host and payload
	dstHost, headerLen, err := UDPGetRequest(payload)
	if err != nil {
		Logger.Error("[UDP] failed to get request", zap.Error(err))
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
	forwardPacketln, ok := natTable.Get(src)
	if !ok {
		// initialize the packet listener into the nat table
		packetln, err := net.ListenPacket("udp", "")
		if err != nil {
			Logger.Error("[UDP] error in listen outgoing packet listener", zap.Error(err))
			return err
		}

		natTable.Lock()
		if packetListen, ok := natTable.nat[src.String()]; ok {
			// other goroutine has creat the packet connection
			forwardPacketln = packetListen
		} else {
			natTable.nat[src.String()] = packetln
			natTable.Unlock()

			// Set up the backward worker gorotine for this packetln
			// this is the key logical for backward UDP request to ss-local
			go func() {
				defer natTable.Delete(src.String())

				buf := UDPBufferPool.Get()
				defer UDPBufferPool.Put(buf)

				//buf := make([]byte, UDPMaxSize)
				for {
					n, raddr, err := packetln.ReadFrom(buf)
					if err != nil && err != io.EOF {
						Logger.Error("[UDP] error in udp backward read", zap.Stringer("remote_addr", raddr),
							zap.Stringer("dest_addr", src), zap.Error(err))
						return
					}
					serverIn.WriteTo(append(reqHeader, buf[:n]...), src)
				}
			}()
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
