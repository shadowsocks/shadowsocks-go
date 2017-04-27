FROM golang
MAINTAINER arthurkiller "arthur-lee@qq.com"
RUN go get -u github.com/arthurkiller/shadowsocks-go/cmd/shadowsocks-server
CMD ["shadowsocks-server", "-c", "/shadowsocks-go/config.json"]
