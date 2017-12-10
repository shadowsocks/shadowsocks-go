package shadowsocks

import (
	"net"
)
// chanFromConn creates a channel from a Conn object, and sends everything it
//  Read()s from the socket to the channel.
func chanFromConn(conn net.Conn, b []byte) chan []byte {
	c := make(chan []byte)

	go func() {
		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				if DebugLog {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Read data error")
				}
				break
			}
		}
	}()

	return c
}

// Pipe creates a full-duplex pipe between the two sockets and transfers data from one to the other.
func PipeStream(conn1 net.Conn, conn2 net.Conn, buffer []byte) {
	chan1 := chanFromConn(conn1, buffer)
	chan2 := chanFromConn(conn2, buffer)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				_, err := conn2.Write(b1)
				if DebugLog && err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				_, err := conn1.Write(b2)
				if DebugLog && err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		}
	}
}