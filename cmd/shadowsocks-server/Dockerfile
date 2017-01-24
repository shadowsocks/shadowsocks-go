FROM golang:1.5

ENV SS_PASSWORD=shadowsocks
ENV SS_METHOD=aes-256-cfb

COPY ./ $GOPATH/src/shadowsocks
WORKDIR $GOPATH/src/shadowsocks

RUN go get github.com/tools/godep && \
	godep go build -o /usr/local/bin/shadowsocks .

EXPOSE 8388

CMD ["/usr/local/bin/shadowsocks"]
