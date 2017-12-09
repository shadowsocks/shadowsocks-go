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
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("Read data error")
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
				if _, err := conn2.Write(b1); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				if _, err := conn1.Write(b2); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		}
	}
}

// chanFromConn creates a channel from a Conn object, and sends everything it
//  Read()s from the socket to the channel.
func chanFromPacket(conn net.PacketConn, b []byte) (c chan []byte, addr net.Addr) {
	//c = make(chan []byte)
	//c = make(chan []byte)
	var n int
	var err error

	go func() {
		for {
			n, addr, err = conn.ReadFrom(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				Logger.Fields(LogFields{
					"err": err,
				}).Warn("Read data error")
				break
			}
		}
	}()

	return
}

// Pipe creates a full-duplex pipe between the two sockets and transfers data from one to the other.
func PipePacket(conn1 net.PacketConn, conn2 net.PacketConn, buffer []byte) {
	chan1, addr1 := chanFromPacket(conn1, buffer)
	chan2, addr2 := chanFromPacket(conn2, buffer)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				if _, err := conn2.WriteTo(b1, addr1); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				if _, err := conn1.WriteTo(b2, addr2); err != nil {
					Logger.Fields(LogFields{
						"err": err,
					}).Warn("Write data error")
				}
			}
		}
	}
}