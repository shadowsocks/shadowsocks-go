# Use shadowsocks as command prefix to avoid name conflict
# Maybe ss-local/server is better because easier to type
PREFIX := shadowsocks
LOCAL := $(GOPATH)/bin/$(PREFIX)-local
SERVER := $(GOPATH)/bin/$(PREFIX)-server
CGO := CGO_ENABLED=0

all: $(LOCAL) $(SERVER) $(TEST)

.PHONY: clean

clean:
	rm -f $(LOCAL) $(SERVER) $(TEST)

# -a option is needed to ensure we disabled CGO
$(LOCAL): shadowsocks/*.go cmd/$(PREFIX)-local/*.go
	cd cmd/$(PREFIX)-local; $(CGO) go install -a

$(SERVER): shadowsocks/*.go cmd/$(PREFIX)-server/*.go
	cd cmd/$(PREFIX)-server; $(CGO) go install -a

local: $(LOCAL)

server: $(SERVER)

test:
	cd shadowsocks; go test
