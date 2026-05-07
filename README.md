# dns-lo-first

Local-first DNS server for OpenWrt x86_64.

## Build

```sh
make build
make openwrt
```

## Run Locally

```sh
go run ./cmd/lo-first -config config.yaml
```

The default listener is `:5355` to avoid conflicting with `dnsmasq` on port 53.

## OpenWrt Layout

- Binary: `/usr/bin/dns-lo-first`
- Config: `/etc/dns-lo-first/config.yaml`
- Data: `/etc/dns-lo-first/data`
- Cache: `/var/cache/dns-lo-first`
- Logs: `/var/log/dns-lo-first`

Install `openwrt/dns-lo-first.init` as `/etc/init.d/dns-lo-first` when deploying as a `procd` service.
