package shadowsocks

import (
	"sync/atomic"
)

type TrafficListener interface {
	WhenIn(len int)
	WhenOut(len int)
}
