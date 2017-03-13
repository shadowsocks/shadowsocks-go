# Use shadowsocks as command prefix to avoid name conflict
# Maybe ss-local/server is better because easier to type
PREFIX := shadowsocks
LOCAL := $(GOPATH)/bin/$(PREFIX)-local
SERVER := $(GOPATH)/bin/$(PREFIX)-server
CGO := CGO_ENABLED=0
# PLATFORMS="darwin/386 darwin/amd64 freebsd/386 freebsd/amd64 freebsd/arm linux/386 linux/amd64 linux/arm windows/386 windows/amd64"
ARCH := GOOS=linux GOARCH=amd64

all: $(LOCAL) $(SERVER) $(TEST)

.PHONY: clean

clean:
	rm -f $(LOCAL) $(SERVER) $(TEST)

# -a option is needed to ensure we disabled CGO
$(LOCAL): shadowsocks/*.go cmd/$(PREFIX)-local/*.go
	cd cmd/$(PREFIX)-local; $(CGO) $(ARCH) go install

$(SERVER): shadowsocks/*.go cmd/$(PREFIX)-server/*.go
	cd cmd/$(PREFIX)-server; $(CGO) $(ARCH) go install

local: $(LOCAL)

server: $(SERVER)

test:
	cd shadowsocks; go test
