# fpm-wg

Sync WireGuard `AllowedIPs` from FRR's route events — using FRR's **stock**
`dplane_fpm_nl` module, no Lua scripting required.

`fpm-wg` is the replacement for the `zebra on-rib-process script update_wireguard`
Lua hook. FRR's official packages are built `--disable-scripting`, so the Lua
hook is unavailable after upgrading; `dplane_fpm_nl` ships in the stock package
and streams the same dataplane route events as netlink messages over TCP.

```
FRR zebra (-M dplane_fpm_nl)  ──netlink/TCP──▶  fpm-wg  ──▶  WireGuard AllowedIPs
```

## How it works

1. `fpm-wg` listens on `127.0.0.1:2620`; FRR's `dplane_fpm_nl` module dials in.
2. On connect, FRR replays the whole RIB (walks), so state converges without
   extra logic after a reboot or a `fpm-wg` restart.
3. Each `RTM_NEWROUTE`/`RTM_DELROUTE` is decoded together with nexthop objects
   (`RTM_NEWNEXTHOP`, default `use-next-hop-groups` = yes).
4. A route's gateway is matched to a peer by its tunnel address (the peer's
   `/32` allowed-ip inside `tunnel_net`). Route install ⇒ add prefix to that
   peer; withdraw ⇒ strip the prefix from whichever peer holds it. Prefixes the
   process did not add (e.g. the base tunnel `/32`) are never removed.
5. Changes are coalesced over `flush_interval` and applied as a full-list
   replace per peer, so the applier is called at most once per peer per window.

## Configuration

JSON (see `deploy/fpm-wg.json`); every field is overridable by flag.

```json
{
  "listen": "127.0.0.1:2620",
  "interface": "wg0",
  "tunnel_net": "192.168.200.0/24",
  "applier": "ctrl",
  "flush_interval": "100ms",
  "log_level": "info"
}
```

| field | meaning |
|---|---|
| `listen` | TCP address FRR's FPM dials |
| `interface` | WireGuard interface to manage |
| `tunnel_net` | CIDR containing peer tunnel `/32`s (used to map gateway→peer) |
| `applier` | `ctrl` (direct WireGuard netlink via wgctrl) or `exec` (shell out to `wg`) |
| `flush_interval` | coalescing window |
| `log_level` | `debug`/`info`/`warn`/`error` |

## FRR side

`/etc/frr/daemons`:

```
zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl"
```

`/etc/frr/frr.conf`:

```
fpm address 127.0.0.1 port 2620
```

Runtime CLI is module-namespaced: `show fpm status`, `show fpm counters`.

> **Gotcha:** `zebra -C` (config dry-run/sanity check) **segfaults** if the config
> contains `fpm address`. Normal startup is unaffected. Do not use `zebra -C` to
> validate an FPM config.

## Install (release)

`scripts/install.sh` downloads the latest GitHub **release** asset for the host
architecture, installs `/usr/local/bin/fpm-wg`, writes a default
`/etc/fpm-wg/config.json` (only if absent) and a systemd unit, then enables and
starts the service.

```bash
curl -fsSL https://raw.githubusercontent.com/ehealth-co-id/fpm-wg/master/scripts/install.sh | sudo bash
# or, from a checkout:
sudo bash scripts/install.sh
```

The installer never overwrites an existing config — set `tunnel_net` (and
`interface`) there before relying on the service.

For private forks, export a token (`Contents: read`); the script then downloads
through the API asset endpoint instead:

```bash
sudo -E GITHUB_TOKEN=ghp_xxx bash scripts/install.sh
```

## Build & test

```
make build      # -> bin/fpm-wg (static, CGO disabled)
make cross      # GOOS=linux GOARCH=<amd64|arm64> -> ./fpm-wg (release CI)
make test
make install
```

Releases are produced by `.github/workflows/release.yml` on `v*` tags: it runs
`go vet` + `go test`, then uploads `fpm-wg-linux-amd64` and
`fpm-wg-linux-arm64` as release assets.

## Deploy

```
install -Dm0755 bin/fpm-wg /usr/local/bin/fpm-wg
install -Dm0644 deploy/fpm-wg.json /etc/fpm-wg/config.json
install -Dm0644 deploy/fpm-wg.service /etc/systemd/system/fpm-wg.service
systemctl enable --now fpm-wg
```

`fpm-wg.service` orders after `wg-quick@wg0.service` and `frr.service`.

## Appliers

* `ctrl` (default) — writes WireGuard directly through the kernel's generic
  netlink family via `wgctrl`. No process fork, no `wg` dependency.
* `exec` — shells out to `wg(8)`. Portable; used by the lab harness, which
  emulates WireGuard with a `wg` shim because the test host (WSL2) has no
  WireGuard kernel support.

## Layout

```
cmd/fpm-wg        entrypoint, flags, wiring
internal/fpm      FPM framing + netlink decoding (unit-tested on live captures)
internal/syncer   gateway->peer mapping, allowed-ips model, coalescing
internal/wg       Applier interface: Ctrl (wgctrl) + Exec (wg CLI)
internal/server   TCP listener + connection handling
internal/config   JSON config
deploy/           systemd unit + example config
scripts/          install.sh (release installer)
.github/          release workflow
```
