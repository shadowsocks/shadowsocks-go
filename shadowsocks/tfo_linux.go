package shadowsocks

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
)

// implements tfoDialDeleg
type tfoDialer struct{}

// implements tfoListenDeleg
type tfoListener struct{}

func (tfoDialer) Dial(net, addr string, data []byte) (net.Conn, error) {
	return tfoDial(addr, data)
}

func (tfoListener) Listen(net, addr string) (net.Listener, error) {
	return tfoListen(addr)
}

func init() {
	tfoDialDel = &tfoDialer{}
	tfoListenDel = &tfoListener{}
}

func zoneToInt(zone string) int {
	if zone == "" {
		return 0
	}

	if ifi, err := net.InterfaceByName(zone); err == nil {
		return ifi.Index
	}

	n, _, _ := dtoi(zone, 0)
	return n
}

const big = 0xFFFFFF

func dtoi(s string, i0 int) (n int, i int, ok bool) {
	n = 0
	for i = i0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return 0, i, false
		}
	}
	if i == i0 {
		return 0, i, false
	}
	return n, i, true
}

func tcpAddrToSockaddr(addr string) (sa unix.Sockaddr, err error) {
	if len(addr) > 0 && addr[0] == ':' {
		addr = "0.0.0.0" + addr
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)

	if err != nil {
		return
	}
	if ip := tcpAddr.IP.To4(); ip != nil {
		sa := new(unix.SockaddrInet4)
		sa.Port = tcpAddr.Port
		copy(sa.Addr[:], ip)
		return sa, nil
	} else if ip := tcpAddr.IP.To16(); ip != nil {
		sa := new(unix.SockaddrInet6)
		sa.Port = tcpAddr.Port
		copy(sa.Addr[:], ip)
		sa.ZoneId = uint32(zoneToInt(tcpAddr.Zone))
		return sa, nil
	}
	return nil, net.InvalidAddrError("unknown address")
}

// TfoDial dials to addr using tcp protocol with fast open option set,
// addr should be in the form of "addr:port",
// the data is sent along with the first syn packet of tcp handshake.
// It returns a established connection and an error if any.
func tfoDial(addr string, data []byte) (conn net.Conn, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	sa, err := tcpAddrToSockaddr(addr)
	if err != nil {
		return
	}

	err = unix.Sendto(fd, data, unix.MSG_FASTOPEN, sa)
	if err != nil {
		return
	}

	f := os.NewFile(uintptr(fd), "TFODial")
	defer f.Close()

	return net.FileConn(f)
}

const (
	TCP_FASTOPEN     = 23
	TCP_FASTOPEN_VAL = 5
)

// TfoListen announces on the local network address laddr using tcp protocol and fast open option.
// laddr must be in the form of "host:port".
// It returns a tfo-enabled listener and an error if any.
func tfoListen(laddr string) (lst net.Listener, err error) {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(s)

	sa, err := tcpAddrToSockaddr(laddr)
	if err != nil {
		return
	}

	err = unix.Bind(s, sa)
	if err != nil {
		return
	}

	// set the socket to fast open mode
	err = unix.SetsockoptInt(s, unix.SOL_TCP, 23, TCP_FASTOPEN_VAL)
	if err != nil {
		return
	}

	err = unix.Listen(s, 10)
	if err != nil {
		return
	}

	f := os.NewFile(uintptr(s), "TFOListen")
	defer f.Close()

	return net.FileListener(f)
}
