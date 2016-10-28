package shadowsocks

type TrafficListener struct {
	In  int64 `json:"in"`
	Out int64 `json:"out"`
}

func (t *TrafficListener) WhenIn(len int) {
	t.In += int64(len)
}

func (t *TrafficListener) WhenOut(len int) {
	t.Out += int64(len)
}

func (t *TrafficListener) Clear() {
	t.In = 0
	t.Out = 0
}
