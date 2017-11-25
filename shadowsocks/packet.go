package shadowsocks

import "io"

type Packet struct {
	writer io.Writer
	data []byte

	payload []byte
	payload_len int

	packet []byte // [IV][encrypted payload]
}