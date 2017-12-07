package main

import (
	ss "github.com/qunxyz/shadowsocks-go/shadowsocks"
	"fmt"
	"bytes"
)

func main() {
	method := "chacha20-ietf"
	password := "123456"
	c, err := ss.NewCryptor(method, password)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < 1000; i++ {
		//b := []byte("hello")
		b := []byte("GET /go.php HTTP/1.1\r\nHost: test.com\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36\r\nUpgrade-Insecure-Requests: 1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nDNT: 1\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6\r\nCookie: PHPSESSID=eleine4o6cvrumsukftglgdkf5; LUM_SESSION=p37m370h9v5plu7419vibavs31; language=en-gb; currency=USD; __atuvc=2%7C48; default=g798i1qf76943q6u9g64db4i93\r\n\r\n")


		w := bytes.NewBuffer(nil)

		if err = c.InitEncrypt(w); err != nil {
			fmt.Println(err)
		}

		n, err := c.Pack(b, w)
		if err != nil {
			fmt.Println(err)
		}

		ct := b[:n]
		r := bytes.NewBuffer(nil)
		w.WriteTo(r)

		if err = c.InitDecrypt(r); err != nil {
			fmt.Println(err)
		}
		n, err = c.UnPack(ct, r)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("plaintext: %s", ct[:n])
	}
}
