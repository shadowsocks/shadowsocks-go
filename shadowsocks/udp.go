package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
	"syscall"
	"sync"
)

const (
	idType    = 0 // address type index
	idIP0     = 1 // ip addres start index
	idDmLen   = 1 // domain address length index
	idDm0     = 2 // domain address start index

	typeIPv4  = 1 // type is ipv4 address
	typeDm    = 3 // type is domain address
	typeIPv6  = 4 // type is ipv6 address

	lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
	lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
	lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
)

var (
	reqList   = ReqList{List:map[string]*ReqNode{}}
	nl        = NATlist{Conns: map[string]*CachedUDPConn{}}
)

type UDP interface {
	ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error)
	Read(b []byte) (n int, err error)
	WriteToUDP(b []byte, src *net.UDPAddr) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	SetWriteDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ReadFrom(b []byte) (int, net.Addr, error)
}

type UDPConn struct {
	UDP
	*Cipher
}

func NewUDPConn(cn UDP, cipher *Cipher) *UDPConn {
	return &UDPConn{cn, cipher}
}

type CachedUDPConn struct {
	timer *time.Timer
	UDP
	i string // scraddr
}

func NewCachedUDPConn(cn UDP) *CachedUDPConn {
	return &CachedUDPConn{nil, cn, ""}
}

func (c *CachedUDPConn) Check() {
	go nl.Delete(c.i)
}

func (c *CachedUDPConn) Close() error{
	c.timer.Stop()
	return c.UDP.Close()
}

func (c *CachedUDPConn) SetTimer(index string) {
	c.i = index
	c.timer = time.AfterFunc(120*time.Second, c.Check)
}

func (c *CachedUDPConn) Refresh() bool {
	return c.timer.Reset(120*time.Second)
}

type NATlist struct {
	sync.Mutex
	Conns map[string]*CachedUDPConn
	AliveConns int
}

func (nl *NATlist) Delete(srcaddr string) {
	nl.Lock()
	c , ok := nl.Conns[srcaddr]
	if ok {
		c.Close()
		delete(nl.Conns, srcaddr)
		nl.AliveConns -= 1
	}
	reqList.Refresh()
	defer nl.Unlock()
}

func (nl *NATlist) Get(srcaddr *net.UDPAddr, ss *UDPConn) (c *CachedUDPConn, ok bool, err error){
	nl.Lock()
	defer nl.Unlock()
	index := srcaddr.String()
	_ , ok = nl.Conns[index]
	if !ok {
		//NAT not exists or expired
		nl.AliveConns += 1
		delete(nl.Conns, index)
		ok = false
		//full cone
		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		})
		if err != nil {
			return nil, false, err
		}
		nl.Conns[index] = NewCachedUDPConn(conn)
		c , _ = nl.Conns[index]
		c.SetTimer(index)
		go Pipeloop(ss, srcaddr, c)
	} else {
		//NAT exists
		c , _ = nl.Conns[index]
		c.Refresh()
	}
	err = nil
	return
}

type ReqNode struct {
	Req []byte
	ReqLen int
}

type ReqList struct {
	List map[string]*ReqNode
	sync.Mutex
}

func (r *ReqList) Refresh() {
	r.Lock()
	defer r.Unlock()
	for k, _  := range r.List {
		delete(r.List, k)
	}
}

func (r *ReqList) Get(dstaddr string) (req *ReqNode, ok bool) {
	r.Lock()
	defer r.Unlock()
	req, ok = r.List[dstaddr]
	return
}

func (r *ReqList) Put(dstaddr string, req *ReqNode) {
	r.Lock()
	defer r.Unlock()
	r.List[dstaddr] = req
	return
}

func ParseHeader(addr net.Addr) ([]byte, int) {
//what if the request address type is domain???
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
	return buf[:1+iplen+2], 1+iplen+2
}

func Pipeloop(ss *UDPConn, srcaddr *net.UDPAddr, remote UDP) {
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	defer nl.Delete(srcaddr.String())
	for{
		remote.SetReadDeadline(time.Now().Add(readTimeout))
		n, raddr, err := remote.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
				// log too many open file error
				// EMFILE is process reaches open file limits, ENFILE is system limit
				fmt.Println("[udp]read error:", err)
			} else if ne.Err.Error() == "use of closed network connection" {
				fmt.Println("[udp]Connection Closing:", remote.LocalAddr())
			} else {
				fmt.Println("[udp]error reading from:", remote.LocalAddr(), err)
			}
			return
		}
		// need improvement here
		if N, ok := reqList.Get(raddr.String()); ok {
			go ss.WriteToUDP(append(N.Req[:N.ReqLen], buf[:n]...), srcaddr)
		}	else {
			header, hlen := ParseHeader(raddr)
			go ss.WriteToUDP(append(header[:hlen], buf[:n]...), srcaddr)
		}
	}
}

func (c *UDPConn) handleUDPConnection(n int, src *net.UDPAddr, receive []byte) {
	var dstIP net.IP
	var reqLen int
	defer leakyBuf.Put(receive)

	switch receive[idType] {
	case typeIPv4:
		reqLen = lenIPv4
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv4len])
	case typeIPv6:
		reqLen = lenIPv6
		dstIP = net.IP(receive[idIP0 : idIP0+net.IPv6len])
	case typeDm:
		reqLen = int(receive[idDmLen]) + lenDmBase
		dIP, err := net.ResolveIPAddr("ip" ,string(receive[idDm0 : idDm0+receive[idDmLen]]))
		if err != nil{
			fmt.Sprintf("[udp]failed to resolve domain name: %s\n", string(receive[idDm0 : idDm0+receive[idDmLen]]))
			return
		}
		dstIP = dIP.IP
	default:
		fmt.Sprintf("[udp]addr type %d not supported", receive[idType])
		return
	}
	dst := &net.UDPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(receive[reqLen-2 : reqLen])),
	}
	if _, ok := reqList.Get(dst.String()); !ok {
		req := make([]byte, reqLen)
		for i:=0;i<reqLen;i++ {
			req[i] = receive[i]
		}
		reqList.Put(dst.String(), &ReqNode{req, reqLen})
	}

	remote, _, err := nl.Get(src, c)
	if err != nil {
		return
	}
	remote.SetWriteDeadline(time.Now().Add(readTimeout))
	_, err = remote.WriteToUDP(receive[reqLen:n], dst)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			fmt.Println("[udp]write error:", err)
		} else {
			fmt.Println("[udp]error connecting to:", dst, err)
		}
		return
	}
	// Pipeloop
	return
}

func (c *UDPConn) ReadAndHandleUDPReq()  {
	buf := leakyBuf.Get()
	n, src, err := c.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	go c.handleUDPConnection(n, src, buf)
}

//n is the size of the payload
func (c *UDPConn) ReadFromUDP(b []byte) (n int, src *net.UDPAddr, err error) {
	buf := leakyBuf.Get()
	n, src, err = c.UDP.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}
	defer leakyBuf.Put(buf)

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	if n < c.info.ivLen {
		return 0, nil, fmt.Errorf("[udp]write error: cannot decrypt")
	}
	c.decrypt(b[0:n - c.info.ivLen], buf[c.info.ivLen : n])
	n = n - c.info.ivLen
	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	buf := leakyBuf.Get()
	n, err = c.UDP.Read(buf[0:])
	if err != nil {
		return
	}
	defer leakyBuf.Put(buf)

	iv := buf[:c.info.ivLen]
	if err = c.initDecrypt(iv); err != nil {
		return
	}
	c.decrypt(b[0:n - c.info.ivLen], buf[c.info.ivLen : n])
	n = n - c.info.ivLen
	return
}

//n = iv + payload
func (c *UDPConn) WriteToUDP(b []byte, src *net.UDPAddr) (n int, err error) {
	var cipherData []byte
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData = make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)
	
	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDP.WriteToUDP(cipherData, src)
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	var cipherData []byte
	dataStart := 0

	var iv []byte
	iv, err = c.initEncrypt()
	if err != nil {
		return
	}
	// Put initialization vector in buffer, do a single write to send both
	// iv and data.
	cipherData = make([]byte, len(b)+len(iv))
	copy(cipherData, iv)
	dataStart = len(iv)
	
	c.encrypt(cipherData[dataStart:], b)
	n, err = c.UDP.Write(cipherData)
	return
}
