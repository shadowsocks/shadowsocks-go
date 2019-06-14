package shadowsocks

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func mustNewCipher(method string) *Cipher {
	const testPassword = "password"
	cipher, err := NewCipher(method, testPassword)
	if err != nil {
		panic(err)
	}
	return cipher
}

type transcriptConn struct {
	net.Conn
	ReadTranscript []byte
}

func (conn *transcriptConn) Read(p []byte) (int, error) {
	n, err := conn.Conn.Read(p)
	conn.ReadTranscript = append(conn.ReadTranscript, p[:n]...)
	return n, err
}

func connIVs(method string) (clientIV, serverIV []byte, err error) {
	// underlying network connection
	clientConn, serverConn := net.Pipe()
	// make a transcript of bytes at the network level
	clientTranscriptConn := &transcriptConn{Conn: clientConn}
	serverTranscriptConn := &transcriptConn{Conn: serverConn}
	// connection at the ShadowSocks level
	clientSSConn := NewConn(clientTranscriptConn, mustNewCipher(method))
	serverSSConn := NewConn(serverTranscriptConn, mustNewCipher(method))

	clientToServerData := []byte("clientToServerData")
	serverToClientData := []byte("serverToClientData")

	go func() {
		defer serverSSConn.Close()
		buf := make([]byte, len(clientToServerData))
		// read the client IV
		_, err := io.ReadFull(serverSSConn, buf)
		if err != nil {
			return
		}
		// send the server IV
		_, err = serverSSConn.Write(serverToClientData)
		if err != nil {
			return
		}
	}()

	// send the client IV
	_, err = clientSSConn.Write(clientToServerData)
	if err != nil {
		return
	}
	// read the server IV
	buf := make([]byte, len(serverToClientData))
	_, err = io.ReadFull(clientSSConn, buf)
	if err != nil {
		return
	}

	// pull the IVs out of the network transcripts
	clientIV = serverTranscriptConn.ReadTranscript[:clientSSConn.Cipher.info.ivLen]
	serverIV = clientTranscriptConn.ReadTranscript[:serverSSConn.Cipher.info.ivLen]

	return
}

func TestIndependentIVs(t *testing.T) {
	for method := range cipherMethod {
		clientIV, serverIV, err := connIVs(method)
		if err != nil {
			t.Errorf("%s connection error: %s", method, err)
			continue
		}
		if bytes.Equal(clientIV, serverIV) {
			t.Errorf("%s equal client and server IVs", method)
			continue
		}
	}
}
