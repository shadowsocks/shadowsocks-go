// +build !linux

package main

import (
	"net"
)

func getOriginDst(c net.Conn) (net.Addr, error) {
	return c.LocalAddr(), nil
}
