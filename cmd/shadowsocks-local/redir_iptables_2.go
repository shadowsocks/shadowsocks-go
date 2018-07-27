// +build linux,cgo

package main

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

// the RPI toolchain does not have this macro
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

int get_original_dst4(int fd, void *addr);
int get_original_dst6(int fd, void *addr);

unsigned short _ntohs(unsigned short a);

int get_original_dst4(int fd, void *addr){
	int ret;
	int l = sizeof(struct sockaddr_in);
	ret = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
		(struct sockaddr_in *)addr, &l);
	return ret;
}

int get_original_dst6(int fd, void *addr){
	int ret;
	int l = sizeof(struct sockaddr_in6);
	ret = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST,
		(struct sockaddr_in6 *)addr, &l);
	return ret;
}

unsigned short _ntohs(unsigned short a) {
	return ntohs(a);
}

*/
import "C"

import (
	"fmt"
	//"log"
	"net"
	"syscall"
	"unsafe"
)

func getOriginDst(c net.Conn) (net.Addr, error) {
	var addr net.Addr
	var err error

	if _, ok := c.(*net.TCPConn); !ok {
		return nil, fmt.Errorf("only tcp socket supported")
	}

	ip := c.LocalAddr().(*net.TCPAddr).IP

	if ip.To4() != nil { // ipv4
		addr, err = getOriginDst4(c)
	} else {
		addr, err = getOriginDst6(c)
	}
	return addr, err
}

func getOriginDst4(c net.Conn) (net.Addr, error) {

	c1 := c.(*net.TCPConn)

	f, _ := c1.File()

	defer f.Close()

	var addr4 syscall.RawSockaddrInet4

	ret := C.get_original_dst4(C.int(f.Fd()), unsafe.Pointer(&addr4))
	if int(ret) != 0 {
		return nil, fmt.Errorf("ipv4 getsockopt SO_ORIGINAL_DST return %v", int(ret))
	}

	port := int(C._ntohs(C.ushort(addr4.Port)))
	ip := net.IP(addr4.Addr[0:])

	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func getOriginDst6(c net.Conn) (net.Addr, error) {

	c1 := c.(*net.TCPConn)

	f, _ := c1.File()

	defer f.Close()

	var addr6 syscall.RawSockaddrInet6

	ret := C.get_original_dst6(C.int(f.Fd()), unsafe.Pointer(&addr6))
	if int(ret) != 0 {
		return nil, fmt.Errorf("ipv6 getsockopt IP6T_ORIGINAL_DST return %v", int(ret))
	}

	port := int(C._ntohs(C.ushort(addr6.Port)))
	ip := net.IP(addr6.Addr[0:])

	return &net.TCPAddr{IP: ip, Port: port}, nil
}
