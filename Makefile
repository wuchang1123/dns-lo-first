BINARY := dns-lo-first
MAIN := ./cmd/lo-first
BUILD_DIR := build

.PHONY: build openwrt run test clean install-openwrt

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) $(MAIN)

openwrt:
	mkdir -p $(BUILD_DIR)/openwrt-x86_64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $(BUILD_DIR)/openwrt-x86_64/$(BINARY) $(MAIN)

run:
	go run $(MAIN) -config config.yaml

test:
	go test ./...

clean:
	rm -rf $(BUILD_DIR)

install-openwrt: openwrt
	install -Dm755 $(BUILD_DIR)/openwrt-x86_64/$(BINARY) /usr/bin/$(BINARY)
	install -Dm644 config.yaml /etc/dns-lo-first/config.yaml
	install -Dm755 openwrt/dns-lo-first.init /etc/init.d/dns-lo-first
