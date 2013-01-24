# Use shadowsocks as command prefix to avoid name conflict
# Maybe ss-local/server is better because easier to type
PREFIX := shadowsocks
LOCAL := $(GOBIN)/$(PREFIX)-local
SERVER := $(GOBIN)/$(PREFIX)-server
CGO := CGO_ENABLED=0

# TODO define the install package path for use in clean and detect whether
# package need re-build

all: $(LOCAL) $(SERVER) $(TEST)

.PHONY: clean

clean:
	rm -rf $(LOCAL) $(SERVER) $(TEST)

$(LOCAL): shadowsocks/*.go cmd/$(PREFIX)-local/*.go
	cd shadowsocks; go install
	cd cmd/$(PREFIX)-local; $(CGO) go install -a

$(SERVER): shadowsocks/*.go cmd/$(PREFIX)-server/*.go
	cd shadowsocks; go install
	cd cmd/$(PREFIX)-server; $(CGO) go install -a

test:
	cd shadowsocks; go test
