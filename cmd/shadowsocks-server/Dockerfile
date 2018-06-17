# very simple docker file 
# you may need run "CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo" on linux first

FROM scratch
ADD shadowsocks-server /shadowsocks-server
ENV SSR_SERVER_PORT 80
ENV SSR_PASSWORD password
ENV SSR_METHOD aes-256-cfb
EXPOSE $SSR_SERVER_PORT
CMD ["/shadowsocks-server", "-u", "true"]
