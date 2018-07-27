// +build linux,!cgo

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	// SO_ORIGINAL_DST in linux/netfilter_ipv4.h
	soOriginalDst = 80
)

func getOriginDst(c net.Conn) (net.Addr, error) {

	cc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("only tcp socket supported")
	}

	f, err := cc.File()
	if err != nil {
		return nil, err
	}

	defer f.Close()

	remoteIP := c.RemoteAddr().(*net.TCPAddr).IP
	if remoteIP.To4() == nil {
		// ipv6
		// not supported, just return local socket address
		return c.LocalAddr(), nil
	}

	// get original ip destination, in C like this
	//
	// struct sockaddr addr;
	// memset(&addr, 0, sizeof(addr);
	// int len = sizeof(addr);
	// getsocketopt(fd, SOL_IP, SO_ORIGINAL_DST, &addr, &len);
	//
	//_, _, errno := syscall.Syscall6(sysGetSockOpt, f.Fd(),
	//	uintptr(level), uintptr(soOriginalDst),
	//	uintptr(unsafe.Pointer(&sockaddr)),
	//	uintptr(unsafe.Pointer(&len)), 0)
	maddr, err := syscall.GetsockoptIPv6Mreq(int(f.Fd()), syscall.SOL_IP, soOriginalDst)

	if err != nil {
		return nil, err
	}

	var port uint16
	var ip net.IP
	rawaddr := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&maddr.Multiaddr))
	ip = net.IP(rawaddr.Addr[0:])
	port = ntohs(rawaddr.Port)

	addr := &net.TCPAddr{IP: ip, Port: int(port)}
	return addr, nil
}

func ntohs(a uint16) uint16 {
	if isLittleEndian {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, a)
		c := binary.LittleEndian.Uint16(b)
		return c
	}
	return a
}

var isLittleEndian = isHostLittleEndian()

func isHostLittleEndian() bool {
	// determine the byte order

	var num uint16 = 0x1234

	buf := make([]byte, 2)

	binary.BigEndian.PutUint16(buf, num)
	p := (*[2]byte)(unsafe.Pointer(&num))
	if p[0] != buf[0] {
		// little endian
		return true
	}
	// big endian
	return false
}
