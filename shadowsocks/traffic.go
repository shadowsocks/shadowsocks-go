package shadowsocks

import (
	"sync/atomic"
)

type TrafficListener struct {
	In  int64 `json:"in"`
	Out int64 `json:"out"`
}

func (t *TrafficListener) WhenIn(len int) {
	atomic.AddInt64(&t.In, len)
}

func (t *TrafficListener) WhenOut(len int) {
	atomic.AddInt64(&t.Out, len)
}

func (t *TrafficListener) GetIn() int64 {
	return atomic.LoadInt64(&t.In)
}

func (t *TrafficListener) GetOut() int64 {
	return atomic.LoadInt64(&t.Out)
}
