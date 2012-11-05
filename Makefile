GOPATH := $(PWD)

all: bin/local bin/server bin/test

.PHONY: clean

clean:
	rm -rf bin/* pkg/*

bin/local: src/shadowsocks/*.go src/local/*.go
	go install local

bin/server: src/shadowsocks/*.go src/server/*.go
	go install server

bin/test: src/shadowsocks/*.go src/test/*.go
	go install test
