# LO FIRST

![LO FIRST](lo.png)

Local First 是一个基于 Go 的本地优先 DNS 服务器，面向需要“国内域名优先本地解析、其他域名智能校对”的场景。它支持本地/海外上游分流、Do53/DoH 上游、ASN 辅助识别、TLS 证书校验、乐观缓存、定时更新和跨平台编译。

## 功能

- **IPv4 Only**：核心处理 `A` 查询；`AAAA` 和其他类型查询直接转发，不参与本服务的 IPv4 校对逻辑。
- **本地/海外上游**：上游分为 `local` 和 `overseas` 两组；同组内先随机选择一个上游查询，失败后并发尝试剩余上游。
- **智能分流**：规则优先级为 `overseas_only > local_only > local_domains > 默认并发`。
- **域名匹配**：普通域名匹配 apex + 子域；支持 `*.example.com` 严格子域语义。
- **国内域名列表**：通过 `local_domains.source_url` 定时更新，更新成功后热加载，无需重启。
- **DNS 污染识别**：对命中 `domain_asn.yaml` 的域名做 ASN 前缀判断；重点嫌疑域名可对本地响应做 TLS/SNI/SAN 校验。
- **乐观缓存**：缓存过期后先以 `ttl=2` 返回旧结果，并在后台刷新。
- **可读缓存文件**：内存保存快速响应格式，落盘保存人可读 JSON。
- **独立查询日志**：每条查询单独记录耗时、域名、类型、响应 IP 和 RCODE。
- **优雅退出**：终端中按 `Ctrl+C` 会停止 UDP/TCP DNS 服务并退出。

## 构建

本地平台编译：

```bash
make build
```

跨平台编译：

```bash
make build-all
```

输出位于 `bin/`，支持：

- `darwin-amd64`
- `darwin-arm64`
- `linux-amd64`
- `linux-arm64`
- `linux-armv7`
- `windows-amd64`
- `windows-arm64`

运行测试：

```bash
make test
```

清理构建产物：

```bash
make clean
```

## 运行

```bash
./bin/lo-first -config config.yaml
```

默认监听：

```text
:5355
```

可以用 `dig` 测试：

```bash
dig @127.0.0.1 -p 5355 example.com A
```

## 配置

主要配置文件是 `config.yaml`。

```yaml
server:
  listen: ":5355"
  domain_ttl: 60
  concurrent_timeout: 6
  log_timezone: "Asia/Shanghai"
  log_level: "info"
  log_path: "./log"
  cache_path: "./cache"
  cache_size: 10000
```

`concurrent_timeout` 控制默认本地+海外并发查询时等待双方结果的窗口，单位是秒。

上游配置：

```yaml
upstream:
  servers:
    local:
      - "223.5.5.5:53"
    overseas:
      - "8.8.8.8:53"
      - "1.1.1.1:53"
  local_only:
    - "ntp.org"
  overseas_only:
    - "googlevideo.com"
```

`local_only`、`overseas_only` 支持 apex + 子域匹配。`overseas_only` 优先级最高。

国内域名列表：

```yaml
local_domains:
  source_url: "https://raw.githubusercontent.com/wuchang1123/cn-dns-conf/refs/heads/main/out/dnsmasq-china.conf"
  file_path: "./data/china_domains.txt"
  update_interval: 24
```

服务启动后会尝试下载更新，之后按 `update_interval` 小时间隔刷新。下载成功后会热加载到内存匹配器。

污染识别：

```yaml
poison_check:
  enabled: true
  tls_timeout: 5
  concurrent_checks: 10
  tls_port: 443
  asn_enabled: true
  asn_file_path: "./data/domain_asn.yaml"
```

`domain_asn.yaml` 维护域名后缀、组织和 IPv4 前缀映射。命中后如果响应 IP 落在对应组织前缀中，会优先认为该响应可信。

## 分流逻辑

1. `overseas_only` 命中：只查询海外上游。
2. `local_only` 命中：只查询本地上游。
3. `local_domains` 命中：只查询本地上游。
4. 未命中上述规则：本地和海外上游并发查询。

默认并发查询中：

- 海外响应通过 ASN 识别后可先返回，并后台继续补全校对结果。
- 重点嫌疑域名的本地响应会做 TLS 证书校验，使用查询域名作为 SNI。
- 本地和海外结果一致时，优先使用本地响应。
- 超时后优先返回海外结果；只有本地结果时返回本地结果并使用短 TTL。

## 缓存

缓存目录由 `server.cache_path` 控制，默认是 `./cache`。

- `response_cache.json`：基础响应缓存，文件为人可读 JSON；内存中使用快速响应格式。
- `verdict_cache.json`：校对结论缓存，记录本地/海外响应 IP、结论和过期时间。

基础响应缓存 key 为：

```text
qname + qtype + qclass
```

缓存过期后，服务会先返回旧响应并将 TTL 降到 `2`，同时后台刷新。

## 日志

普通运行日志：

```text
log/lo-first.log
```

查询日志：

```text
log/query.log
```

查询日志格式固定为无键值字段：

```text
2026-04-25 10:54:52 161.811ms default.exp-tas.com.  A  IN  [13.107.5.93]  NOERROR <nil>
```

字段依次为：

```text
时间 耗时 qname qtype qclass 响应IPs RCODE 写响应错误
```

耗时统一使用毫秒，保留 3 位小数并四舍五入。

## 数据文件

- `data/china_domains.txt`：国内域名列表，支持 dnsmasq `server=/a/b/c/ip` 格式，一行多个域名都会被加载。
- `data/common_blocked_domains.txt`：常见被干扰域名参考列表。
- `data/domain_asn.yaml`：域名后缀、组织和 IPv4 前缀映射。

## 开发

格式化和测试：

```bash
gofmt -w cmd internal
go test ./...
```

构建当前平台：

```bash
make build
```
