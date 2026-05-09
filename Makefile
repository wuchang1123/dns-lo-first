BINARY := dns-lo-first
BUILD_DIR := build

.PHONY: build run test tidy clean openwrt

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/dns-lo-first

openwrt:
	mkdir -p $(BUILD_DIR)/openwrt-x86_64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/openwrt-x86_64/$(BINARY) ./cmd/dns-lo-first

run:
	go run ./cmd/dns-lo-first -config config.yaml

test:
	go test ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BUILD_DIR)
