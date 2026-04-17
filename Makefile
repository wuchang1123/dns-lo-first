.PHONY: all linux linux-arm64 linux-arm macos clean install uninstall

# 编译所有平台
all: linux linux-arm64 linux-arm macos

# Linux AMD64
linux:
	GOOS=linux GOARCH=amd64 go build -o bin/dns-server-linux-amd64 ./cmd/dns-server/
	@echo "已编译 Linux AMD64: bin/dns-server-linux-amd64"

# Linux ARM64
linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o bin/dns-server-linux-arm64 ./cmd/dns-server/
	@echo "已编译 Linux ARM64: bin/dns-server-linux-arm64"

# Linux ARMv7
linux-arm:
	GOOS=linux GOARCH=arm GOARM=7 go build -o bin/dns-server-linux-armv7 ./cmd/dns-server/
	@echo "已编译 Linux ARMv7: bin/dns-server-linux-armv7"

# macOS ARM64 (Apple Silicon)
macos:
	GOOS=darwin GOARCH=arm64 go build -o bin/dns-server-darwin-arm64 ./cmd/dns-server/
	@echo "已编译 macOS ARM64: bin/dns-server-darwin-arm64"

# macOS AMD64 (Intel)
macos-amd64:
	GOOS=darwin GOARCH=amd64 go build -o bin/dns-server-darwin-amd64 ./cmd/dns-server/
	@echo "已编译 macOS AMD64: bin/dns-server-darwin-amd64"

# 清理编译产物
clean:
	rm -f bin/dns-server*
	@echo "已清理编译产物"

# 默认编译当前平台
default:
	go build -o bin/dns-server ./cmd/dns-server/
	@echo "已编译当前平台: bin/dns-server"

# 安装 systemd 服务（需要 root 权限）
install:
	@chmod +x scripts/install.sh scripts/uninstall.sh
	@sudo scripts/install.sh

# 卸载 systemd 服务（需要 root 权限）
uninstall:
	@chmod +x scripts/install.sh scripts/uninstall.sh
	@sudo scripts/uninstall.sh
