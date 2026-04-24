# Local First - 本地优先DNS服务器

![](lo.png)

基于Go开发的高性能本地DNS服务器，支持智能分流、判毒检测和定时更新。

**❗ 重要提示：**
- IPv4 Only
- 本项目不关注海外上游服务器是否可用

## 特性

- **本地优先**: 无污染本地优先原则
- **智能分流**: 自动区分所在国域名和海外域名
- **判毒系统**: TLS证书验证，防止DNS污染
- **多上游支持**: 同时支持本地（国内）和海外DNS上游
- **定时更新**: 自动更新所在国域名列表
- **高性能**: 并发查询、智能缓存

## 架构

```
DNS请求 -> 缓存检查 -> 域名分类 -> 查询策略
                              |
              +---------------+---------------+
              |                               |
        所在国域名                        海外域名
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
2. **并发检查**: 支持并发检查多个IP

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
# 基础目录，默认当前目录
base_dir: "."

server:
  listen: ":53"          # DNS监听地址
  cache_size: 10000      # 缓存大小
  log_timezone: "Asia/Shanghai"  # 日志时区
  log_level: "info"       # 日志等级: debug, info, warn, error, fatal

upstream:
  local:                 # 本地DNS服务器
    - "223.5.5.5:53"
    - "223.6.6.6:53"
  overseas:              # 海外DNS服务器
    - "8.8.8.8:53"
    - "1.1.1.1:53"

local_domains:
  source_url: "https://raw.githubusercontent.com/wuchang1123/cn-dns-conf/refs/heads/main/out/dnsmasq-china.conf"
  file_path: "./data/china_domains.txt"
  update_interval: 24    # 更新间隔（小时）
  custom:                # 自定义域名列表
    - "baidu.com"
    - "taobao.com"
  overpass:              # 跳过本地DNS查询的域名（直接使用海外DNS）
    - "googlevideo.com"
    - "ytimg.com"
    - "github.com"

poison_check:
  enabled: true
  tls_timeout: 5         # TLS连接超时（秒）
  concurrent_checks: 10  # 并发校验数量
  tls_port: 443          # 校验端口
  cache_refresh_interval: 60  # 缓存刷新间隔（分钟），0表示禁用
  cache_ttl: 30          # 缓存过期时间（分钟）
```

### 配置说明

| 配置项 | 说明 |
|--------|------|
| `base_dir` | 基础目录，cache、data、log目录将在其下创建 |
| `server.log_timezone` | 日志时区，如 `Asia/Shanghai`、`America/New_York` |
| `server.log_level` | 日志等级，可选值：debug, info, warn, error, fatal |
| `local_domains.overpass` | 域名列表，这些域名直接使用海外DNS，跳过本地DNS查询和判毒检查 |

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
│   ├── domain/               # 所在国域名管理
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
   - 所在国域名：直接查询本地DNS
   - 海外域名：并发查询本地+海外DNS
4. **判毒检查**（仅海外域名）:
   - 对本地DNS返回的IP进行TLS验证
   - 通过：直接返回本地结果
   - 不通过：等待并返回海外DNS结果
5. **返回响应**: 将结果返回给客户端并缓存

### DNS 查询流程详解

```
ServeDNS(入口)
    │
    ├── 1. 前置检查
    │       ├── 非 TypeA 查询 → 直接失败返回
    │       └── 清理域名（移除 http://、https://、路径）
    │
    ├── 2. Overpass 域名检查
    │       ├── isOverpassDomain = true → 直接用海外 DNS
    │       └── isOverpassDomain = false → 继续
    │
    ├── 3. 本地缓存检查（仅非 Overpass 域名）
    │       └── 如果是本地域名且有本地缓存 → 直接返回缓存
    │               ipSource = "local_cache"
    │
    ├── 4. TLS 缓存检查（passed IPs）
    │       └── 如果有有效 TLS 缓存 → 直接返回缓存响应
    │               ipSource = "tls_cache"
    │
    ├── 5. 并发查询控制（pending queries）
    │       └── 如果已有相同查询 → 加入等待队列
    │
    └── 6. 执行查询（根据域名类型）
            │
            ├── 【Overpass 域名】→ queryOverseasOnly()
            │       └── ipSource = "overseas_upstream"
            │
            ├── 【本地域名】→ queryLocalOnly()
            │       └── ipSource = "local_upstream"
            │
            └── 【普通域名】→ queryWithPoisonCheck()
                    │
                    └── 返回 (response, source, error)
                            source 可能是：
                            • "tls_cache" - 从 TLS 缓存返回
                            • "asn_pass" - ASN 检查通过
                            • "local_upstream" - 本地 DNS 响应通过判毒
                            • "overseas_upstream" - 海外 DNS 响应
                            • "unknown" - 查询失败
```

#### 详细分支路线图

##### 路线 1：Overpass 域名（直接海外）

```
isOverpassDomain = true
    → queryOverseasOnly()
        ├── 先检查 TLS 缓存 → 有则直接返回
        ├── 执行海外 DNS 查询
        ├── ASN 检查 → 通过则立即返回
        ├── TLS 验证（后台执行）
        └── 返回海外响应
    → ipSource = "overseas_upstream"
```

##### 路线 2：本地域名（直接本地）

```
isLocalDomain = true（且不是 Overpass）
    → 先检查本地 DNS 缓存 → 有则直接返回
    │       ipSource = "local_cache"
    → queryLocalOnly()
    → ipSource = "local_upstream"
```

##### 路线 3：普通域名（判毒流程）

```
isLocalDomain = false 且 isOverpassDomain = false
    → queryWithPoisonCheck()

    ┌─────────────────────────────────────────────────────────────┐
    │ 阶段一：检查 TLS 缓存（乐观缓存策略）                        │
    │   ├── 有有效缓存 → 直接返回缓存响应                           │
    │   │           （后台继续查询本地和海外 DNS）                 │
    │   └── 无缓存 → 继续正常流程                                  │
    └─────────────────────────────────────────────────────────────┘
    │
    ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ 阶段二：并发查询本地和海外 DNS                               │
    │   • 本地 DNS：3 秒超时                                      │
    │   • 海外 DNS：5 秒超时                                       │
    └─────────────────────────────────────────────────────────────┘
    │
    ├── 【本地 DNS 先返回】
    │       │
    │       ├── ASN 检查
    │       │       ├── 通过 → 立即返回，TTL=3
    │       │       │       ipSource = "asn_pass"
    │       │       └── 不通过 → 继续判毒
    │       │
    │       ├── TLS 判毒（source = "local"）
    │       │       │
    │       │       ├── 【关键】source = "local" 时，强制执行 TLS 验证
    │       │       │   无论域名是否在 common_blocked_domains 列表
    │       │       │
    │       │       ├── TLS 验证结果：
    │       │       │   ├── passed = true
    │       │       │   │       → 返回本地响应
    │       │       │   │           ipSource = "local_upstream"
    │       │       │   │           （后台验证剩余 IP）
    │       │       │   │
    │       │       │   └── passed = false
    │       │       │           → 继续等待海外 DNS
    │       │       │
    │       └── 本地超时 → 继续等待海外 DNS
    │
    └── 【海外 DNS 先返回】
            │
            ├── ASN 检查
            │       ├── 通过 → 立即返回，TTL=3
            │       │       ipSource = "asn_pass"
            │       └── 不通过 → 继续判毒
            │
            ├── TLS 判毒（source = "overseas"）
            │       │
            │       ├── 【TLS 验证跳过条件检查】
            │       │   同时满足以下条件才跳过 TLS 验证：
            │       │   1. source ≠ "local"（即来自海外）
            │       │   2. tlsVerifyRestrict = true
            │       │   3. 域名不在 common_blocked_domains 列表
            │       │
            │       ├── 跳过 TLS 验证时：
            │       │       → 直接 passed = true
            │       │       → 返回海外响应
            │       │           ipSource = "overseas_upstream"
            │       │
            │       └── 执行 TLS 验证时：
            │               ├── passed = true
            │               │       → 返回海外响应
            │               │           ipSource = "overseas_upstream"
            │               │           （后台验证剩余 IP）
            │               │
            │               └── passed = false
            │                       → 返回响应但 TTL=1
            │                       ipSource = "overseas_upstream"
            │
            └── 海外超时 → 返回查询失败
```

#### ipSource 含义说明

| ipSource | 说明 |
|----------|------|
| `local_cache` | 直接用本地 DNS 缓存 |
| `local_upstream` | 本地 DNS 响应，通过判毒检查 |
| `overseas_upstream` | 海外 DNS 响应 |
| `asn_pass` | IP 在 org IP 段内，ASN 检查通过 |
| `tls_cache` | 从 TLS 验证缓存返回 |
| `unknown` | 查询失败 |

#### common_blocked_domains 配置说明

`common_blocked_domains.txt` 文件用于配置需要 TLS 判毒的域名列表：

- **为空时**：对所有域名都进行 TLS 判毒
- **非空时**：仅对列表内的域名做 TLS 判毒，其余域名直接视为通过

TLS 验证跳过条件（必须同时满足）：

| 条件 | 说明 |
|------|------|
| `source != "local"` | 来源是海外 DNS（不是本地 DNS） |
| `tlsVerifyRestrict = true` | 配置了 common_blocked_domains 列表 |
| 域名不在列表中 | 不在 common_blocked_domains 列表 |

**重要**：当 `source = "local"` 时（本地 DNS 返回的 IP），无论域名是否在列表中，都会**强制执行 TLS 验证**。

#### 日志示例

```
# 本地域名查询
[LOCAL DOMAIN] baidu.com -> 使用本地DNS

# Overpass 域名查询
[OVERPASS DOMAIN] googlevideo.com -> 直接使用海外DNS

# 普通域名查询（本地通过判毒）
[POISON CHECK] google.com: 检查 1/1 个IP [142.250.x.x], passed=true, reason=all TLS checks passed
[LOCAL OK] google.com -> 判毒通过，使用本地DNS

# 普通域名查询（本地判毒失败，等待海外）
[POISON CHECK] chatgpt.com: 检查 1/1 个IP [184.173.x.x], passed=false, reason=TLS handshake failed
[WAIT OVERSEAS] chatgpt.com -> 等待海外DNS
[OVERSEAS CHECK] chatgpt.com: 检查 1/1 个IP [104.16.x.x], passed=true
[OVERSEAS OK] chatgpt.com -> 使用海外DNS
```

### 数据更新

- **所在国域名**: 从 `wuchang1123/cn-dns-conf` 项目定时更新
- **支持格式**: 支持 `server=/domain1/domain2/domain3/.../ip` 格式
- **更新间隔**: 可配置，默认24小时
- **自定义域名**: 支持在配置文件中添加自定义域名

## 许可证

MIT License
