APP := lo-first
PKG := ./cmd/lo-first
BIN_DIR := bin
GO ?= go

GO_BUILD_ENV := CGO_ENABLED=0 GOTOOLCHAIN=local
GO_BUILD_FLAGS := -trimpath -ldflags "-s -w"

.PHONY: all build build-all test clean \
	darwin-amd64 darwin-arm64 \
	linux-amd64 linux-arm64 linux-armv7 \
	windows-amd64 windows-arm64

all: test build

build:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP) $(PKG)

build-all: darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 linux-armv7 windows-amd64 windows-arm64

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_DIR)

darwin-amd64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=darwin GOARCH=amd64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-darwin-amd64 $(PKG)

darwin-arm64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=darwin GOARCH=arm64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-darwin-arm64 $(PKG)

linux-amd64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=linux GOARCH=amd64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-linux-amd64 $(PKG)

linux-arm64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=linux GOARCH=arm64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-linux-arm64 $(PKG)

linux-armv7:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=linux GOARCH=arm GOARM=7 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-linux-armv7 $(PKG)

windows-amd64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=windows GOARCH=amd64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-windows-amd64.exe $(PKG)

windows-arm64:
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_ENV) GOOS=windows GOARCH=arm64 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(APP)-windows-arm64.exe $(PKG)
