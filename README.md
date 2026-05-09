# dns-lo-first

Local-first DNS server implemented from `plan.md`.

## Build

```sh
make build
```

## Run

```sh
sudo ./build/dns-lo-first -config config.yaml
```

Use a high port in `config.yaml` for local testing without root, for example `":1053"`.

## OpenWrt x86_64

```sh
make openwrt
```

The OpenWrt binary is written to `build/openwrt-x86_64/dns-lo-first`.
