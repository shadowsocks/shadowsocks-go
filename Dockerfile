FROM golang
MAINTAINER arthurkiller "arthur-lee@qq.com"
VOLUME ["/etc/shadowsocks-go/config.json"]
RUN go get -u github.com/arthurkiller/shadowsocks-go/cmd/shadowsocks-server
CMD ["shadowsocks-server", "-c /etc/shadowsocks-go/config.json"]
