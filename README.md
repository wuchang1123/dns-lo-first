# LO FIRST - 本地智能DNS服务器

![](lo.png)

基于Go开发的高性能本地DNS服务器，支持智能分流、判毒检测和定时更新。

## 特性

- **智能分流**: 自动区分中国域名和海外域名
- **判毒系统**: TLS证书验证 + IP段匹配，防止DNS污染
- **多上游支持**: 同时支持本地（国内）和海外DNS上游
- **定时更新**: 自动更新中国域名列表和海外服务IP段
- **高性能**: 并发查询、智能缓存

## 架构

```
DNS请求 -> 缓存检查 -> 域名分类 -> 查询策略
                              |
              +---------------+---------------+
              |                               |
        中国域名                        海外域名
              |                               |
        本地DNS查询                  本地+海外并发查询
                                              |
                                       判毒系统检查
                                              |
                                    通过 -> 返回本地结果
                                    不通过 -> 返回海外结果
```

## 判毒系统

判毒系统用于检测DNS响应是否被污染：

1. **TLS证书验证**: 对返回的IP进行TLS握手，验证证书是否匹配域名（SNI=域名）
2. **IP段匹配**: 检查IP是否在已知的海外服务IP段内
3. **并发检查**: 支持并发检查多个IP

如果判毒通过，直接使用本地DNS结果（速度快）；
如果判毒不通过，等待海外DNS结果（干净）。

## 安装

```bash
# 克隆仓库
git clone <repository>
cd dns-lo-first

# 下载依赖
go mod download

# 构建
go build -o dns-lo-first ./cmd/lo-first
```

### 开机启动

**Linux (systemd)**

```bash
# 编译 Linux 版本
make linux

# 安装 systemd 服务
sudo make install

# 启用开机启动
sudo systemctl enable lo-first

# 启动服务
sudo systemctl start lo-first

# 查看状态
sudo systemctl status lo-first
```

**macOS (launchd)**

```bash
# 编译 macOS 版本
make macos

# 安装 launchd 服务
sudo make install

# 重启电脑后服务会自动启动，或手动启动：
sudo launchctl start com.lo-first

# 查看状态
sudo launchctl list | grep lo-first
```

### 卸载

```bash
sudo make uninstall
```

## 配置

编辑 `config.yaml`：

```yaml
server:
  listen: ":53"          # DNS监听地址
  cache_size: 10000      # 缓存大小

upstream:
  local:                 # 本地DNS服务器
    - "223.5.5.5:53"
    - "223.6.6.6:53"
  overseas:              # 海外DNS服务器
    - "8.8.8.8:53"
    - "1.1.1.1:53"

china_domains:
  source_url: "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
  file_path: "./data/china_domains.txt"
  update_interval: 24    # 更新间隔（小时）

overseas_ip_ranges:
  sources:
    google:
      url: "https://www.gstatic.com/ipranges/goog.json"
      file_path: "./data/google_ips.txt"
      update_interval: 24

poison_check:
  enabled: true
  tls_timeout: 5
  concurrent_checks: 10
```

## 使用

### 启动服务器

```bash
# 使用默认配置
sudo ./bin/lo-first-darwin-arm64

# 指定配置文件
sudo ./bin/lo-first-darwin-arm64 -config /path/to/config.yaml
```

> 注意：需要root权限或特权端口权限来监听53端口

### 仅更新数据

```bash
./bin/lo-first-darwin-arm64 -update-only
```

### 测试

```bash
# 使用dig测试
dig @127.0.0.1 www.baidu.com
dig @127.0.0.1 www.google.com

# 使用nslookup测试
nslookup www.baidu.com 127.0.0.1
```

## 项目结构

```
dns-lo-first/
├── cmd/
│   └── lo-first/
│       └── main.go           # 入口程序
├── internal/
│   ├── config/               # 配置管理
│   ├── domain/               # 中国域名管理
│   ├── iprange/              # IP段管理
│   ├── poison/               # 判毒系统
│   ├── server/               # DNS服务器
│   ├── upstream/             # 上游DNS管理
│   └── updater/              # 定时更新
├── scripts/
│   ├── install.sh            # 安装脚本
│   ├── uninstall.sh          # 卸载脚本
│   ├── lo-first.service    # systemd 服务文件
│   └── com.lo-first.plist  # macOS launchd 服务文件
├── config.yaml               # 配置文件
├── go.mod
└── README.md
```

## 工作原理

### 查询流程

1. **接收请求**: 监听UDP 53端口接收DNS查询
2. **缓存检查**: 检查是否有缓存的响应
3. **域名分类**: 
   - 中国域名：直接查询本地DNS
   - 海外域名：并发查询本地+海外DNS
4. **判毒检查**（仅海外域名）:
   - 对本地DNS返回的IP进行TLS验证和IP段检查
   - 通过：直接返回本地结果
   - 不通过：等待并返回海外DNS结果
5. **返回响应**: 将结果返回给客户端并缓存

### 数据更新

- **中国域名**: 从dnsmasq-china-list项目定时更新
- **IP段**: 从各服务商官方源定时更新
- **更新间隔**: 可配置，默认24小时

## 许可证

MIT License
