package shadowsocks
//
//import "io"
//
//type Packet struct {
//	Info *cipherInfo
//
//	reader io.Reader
//	writer io.Writer
//
//	data []byte
//
//	iv_offset int
//
//	payload []byte
//	payload_len int
//
//	packet []byte // [IV][encrypted payload]
//}
//
//func (p *Packet) getData(r io.Reader) (data []byte, err error) {
//	var n int
//	buf := leakyBuf.Get()
//	buf_len := len(buf)
//	data_len := 0
//	counter := 1
//	for {
//		n, err = r.Read(buf)
//		if err != nil && err != io.EOF {
//			Logger.Fields(LogFields{
//				"err": err,
//			}).Warn("read data error")
//			return
//		} else if n == buf_len {
//			tmp_buf := make([]byte, buf_len*counter)
//			if data != nil {
//				copy(tmp_buf, data)
//			}
//			copy(tmp_buf[data_len:], buf[:n])
//			data = tmp_buf
//			data_len += n
//		} else { // read all data while got eof error
//			if counter == 1 {
//				data = buf[:n]
//			} else {
//				tmp_buf := make([]byte, buf_len*(counter-1)+n)
//				copy(tmp_buf, data)
//				copy(tmp_buf[data_len:], buf[:n])
//				data = tmp_buf
//			}
//			data_len += n
//
//			break
//		}
//		counter++
//	}
//
//	return
//}