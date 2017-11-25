package shadowsocks

import (
	"net"
	"time"
	"reflect"
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

func removeEOF(data []byte) (int, []byte) {
	n := len(data) - 1
	for n > 0 && int64(data[n]) == 0 {
		n--
	}

	return n+1, data[:n+1]
}

func PipeEncrypt(src, dst net.Conn, cipher interface{}) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)

		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			var data []byte
			Logger.Fields(LogFields{
				"buf_len": n,
				"buf_str": string(buf[0:n]),
				"buf": buf[0:n],
			}).Info("prepare sending request to ss server")

			if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherStream" {
				data, err = cipher.(*CipherStream).Pack(buf[0:n])
			} else if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherAead" {
				data, err = cipher.(*CipherAead).Pack(buf[0:n])
			}

			if err != nil {
				Logger.Fields(LogFields{
					"data_len": len(data),
					"data_str": string(data),
					"data": data,
					"err": err,
				}).Warn("packing data error")
				break
			}

			Logger.Fields(LogFields{
				"data_len": len(data),
				"data_str": string(data),
				"data": data,
			}).Info("checking data after packing")

			_, data = removeEOF(data)
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(data); err != nil {
				Logger.Fields(LogFields{
					"n": len(data),
					"buf": string(data),
					"err": err,
				}).Warn("write buff error")
				break
			}
		}

		if err != nil {
			Logger.Fields(LogFields{
				"n": n,
				"buf_len": len(buf),
				"buf": string(buf),
				"err": err,
			}).Warn("read buff error")
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}

func PipeDecrypt(src, dst net.Conn, cipher interface{}) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)

		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			var data []byte
			Logger.Fields(LogFields{
				"buf_len": n,
				"buf_str": string(buf[0:n]),
				"buf": buf[0:n],
			}).Info("prepare sending request result to local")

			if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherStream" {
				data, err = cipher.(*CipherStream).UnPack(buf[0:n])
			} else if reflect.TypeOf(cipher).String() == "*shadowsocks.CipherAead" {
				data, err = cipher.(*CipherAead).UnPack(buf[0:n])
			}
			if err != nil {
				Logger.Fields(LogFields{
					"data_len": len(data),
					"data_str": string(data),
					"data": data,
					"err": err,
				}).Warn("unpacking data error")
				break
			}

			Logger.Fields(LogFields{
				"data_len": len(data),
				"data_str": string(data),
				"data": data,
			}).Info("checking data after unpacking")

			_, data = removeEOF(data)
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(data); err != nil {
				Logger.Fields(LogFields{
					"n": len(data),
					"buf": string(data),
					"err": err,
				}).Warn("write buff error")
				break
			}
		}

		if err != nil {
			Logger.Fields(LogFields{
				"n": n,
				"buf_len": len(buf),
				"buf": string(buf),
				"err": err,
			}).Warn("read buff error")
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}