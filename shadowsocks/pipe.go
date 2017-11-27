package shadowsocks

import (
	"net"
)

type Pipe interface {
	Pack(src, dst net.Conn)
	UnPack(src, dst net.Conn)
}

func Piping(local, remote net.Conn, cipher *Cipher) {
	if cipher.CType == C_STREAM {
		p := &PipeStream{Cipher: cipher.Inst.(*CipherStream)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	} else if cipher.CType == C_AEAD {
		p := &PipeAead{Cipher: cipher.Inst.(*CipherAead)}
		go p.Pack(local, remote)
		p.UnPack(remote, local)
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			//Logger.Fields(LogFields{
			//	"buf": buf[0:n],
			//	"buf_str": string(buf[0:n]),
			//}).Warn("Check write buffer")
			if _, err := dst.Write(buf[0:n]); err != nil {
				//Debug.Println("write:", err)
				break
			}
		}
		if err != nil {
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