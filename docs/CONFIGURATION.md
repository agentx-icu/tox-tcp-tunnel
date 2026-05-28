# Configuration

ToxTunnel uses YAML configuration files. CLI flags can override most settings.
Default data directories are `/var/lib/toxtunnel` in server mode and
`$HOME/.config/toxtunnel` in client mode.

## Server Configuration

```yaml
mode: server
data_dir: /var/lib/toxtunnel

service:                            # service-manager policy (--service flag)
  auto_start: true                  # server default: be online when daemonized

logging:
  level: info
  file: /var/log/toxtunnel.log     # optional

tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: auto             # auto or lan
  bootstrap_nodes:
    - address: tox.node.example.com
      port: 33445
      public_key: "AABBCCDD..."

server:
  rules_file: /etc/toxtunnel/rules.yaml   # access-control rules; unset = default deny
  disclose:                              # optional system-info opt-in (all default false)
    hostname: false
    os: false
    os_version: false
    arch: false
    uptime: false
    toxtunnel_version: false
```

## Client Configuration

```yaml
mode: client
data_dir: ~/.config/toxtunnel

service:                                 # service-manager policy (--service flag)
  auto_start: false                       # ignored in client mode
  allow_client_daemon: false              # set true to actually bind local forward
                                          # ports under --service; defaults false so
                                          # packaged installs don't silently listen

logging:
  level: info

tox:
  udp_enabled: true
  bootstrap_mode: auto
  bootstrap_nodes: []

client:
  # Either a 76-char Tox ID, or an alias registered with `toxtunnel servers add`.
  # Aliases resolve from <data_dir>/known_servers.yaml at startup.
  server_id: "AABBCCDD..."               # or e.g. server_id: homelab

  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22                     # local:2222 -> remote:22

    - local_port: 8080
      remote_host: 192.168.1.100
      remote_port: 80                     # local:8080 -> remote:80
```

### Multi-Server Failover

`client.server_id` accepts either a single string (the form above) or a list:
the first entry is the primary server; every subsequent entry is a fallback
tried in order if the primary becomes unreachable. Each entry may be a 76-char
Tox ID or a known-servers alias. The same `--server-id <primary>` plus
repeated `--server-id-fallback <id-or-alias>` CLI flags are equivalent.

```yaml
client:
  server_id:
    - "AABBCCDD..."         # primary
    - homelab-backup        # alias from known_servers.yaml
    - "112233...76hex"      # explicit fallback Tox ID

  failover:
    timeout_seconds: 60                 # active-server-offline threshold
    prefer_primary_grace_seconds: 30    # primary-back-online dwell time
```

The client adds every listed server as a Tox friend at startup and tracks
one active endpoint at a time. When the active server stays offline for
`failover.timeout_seconds` (default `60`), the client promotes the
lowest-index online fallback. When the configured primary (index 0) comes
back online and stays online for `failover.prefer_primary_grace_seconds`
(default `30`), the client switches back. Switchovers are logged at INFO
level, and any tunnels routed through the previous endpoint are torn down
via local `TUNNEL_CLOSE`; TCP listeners rebuild tunnels through the new
active server on the next accepted connection. The single-string `server_id`
form remains fully supported and behaves exactly as before.

### Dynamic Destinations (SOCKS5 / HTTP CONNECT)

Instead of enumerating every `forwards:` mapping ahead of time, the client can
expose a SOCKS5 v5 (RFC 1928) and HTTP CONNECT (RFC 7231 §4.3.6) listener.
Browsers, `curl --socks5`, `nc -X 5`, and any other proxy-aware tool can then
ask for arbitrary destinations at runtime — the server still enforces what is
allowed via `rules.yaml`, so enabling this on the client does not change the
trust boundary.

```yaml
client:
  server_id: "AABBCCDD..."
  socks5:
    enabled: false                  # default: off (backwards-compatible)
    listen: "127.0.0.1:1080"        # local bind for both SOCKS5 and HTTP CONNECT
```

The listener auto-detects protocol by sniffing the first byte of each accepted
connection: `0x05` is SOCKS5, anything else is parsed as HTTP CONNECT.
Authentication is intentionally not implemented in v1 — bind to loopback only
(`127.0.0.1` / `::1`) and rely on the server-side rules engine for access
control. Only the CONNECT command is supported; SOCKS5 BIND and UDP ASSOCIATE
are rejected with reply code `0x07` (command not supported). The CLI form
`--socks5 host:port` is equivalent to setting `socks5.enabled: true` plus
`socks5.listen`.

## Service Policy (`service:`)

Controls whether `toxtunnel --service` (run under systemd / launchd / Windows SCM)
keeps the process resident or exits 0 cleanly.

| Key | Mode | Default | Effect |
|---|---|---|---|
| `auto_start` | server | `true` | When false, the daemon under `--service` logs "Service idle…" and exits 0. Linux unit stays `active (exited)`; macOS `KeepAlive { SuccessfulExit: false }` does not respawn. |
| `allow_client_daemon` | client | `false` | When false, the client daemon under `--service` exits 0 immediately — local forward ports are NOT bound. Flip to true once `client.server_id` and `forwards` are set. |
| `auto_start` | client | n/a | Ignored. Client gating reads `allow_client_daemon` only. |
| `allow_client_daemon` | server | n/a | Ignored. Server gating reads `auto_start` only. |

The soft-fail exit-0 also fires when the config file is missing or fails
validation under `--service`, so a packaged install never loops on a broken
config.

## Tox Network Configuration

Shared toxcore network settings now live under the top-level `tox:` block for both client and
server.

### `bootstrap_mode: auto` (Default)

If `tox.bootstrap_nodes` is empty and `bootstrap_mode` is `auto`, ToxTunnel automatically:
1. Fetches a current node list from `https://nodes.tox.chat/json` on startup
2. Caches the list under `data_dir/bootstrap_nodes.json`
3. Uses cached nodes when the remote fetch fails

This is the recommended approach for most users.

### `bootstrap_mode: lan`

Use this when both peers are on the same local network and you do not want to depend on
`https://nodes.tox.chat/json`.

```yaml
tox:
  udp_enabled: true
  bootstrap_mode: lan
  bootstrap_nodes: []
```

In LAN mode ToxTunnel:
- enables toxcore local discovery,
- does not fetch the public node list,
- does not read or write `bootstrap_nodes.json`,
- and still uses any explicitly configured `tox.bootstrap_nodes` as supplements.

LAN mode requires `tox.udp_enabled: true` and works best when both peers are on the same broadcast
domain.

### Manual Bootstrap Nodes

For air-gapped environments, private networks, or pinned bootstrap daemons:

```yaml
tox:
  bootstrap_nodes:
    - address: 144.217.167.73
      port: 33445
      # public_key must be exactly 64 hex characters (the bootstrap node's DHT key)
      public_key: "7E5B5593A644DADA5272775FE2674241FFC0A2AB922990A91219C5092750F69D"
    - address: tox.kurnevsky.net
      port: 33445
      public_key: "82EF82BA33445A1F53A3BF27B7C4BBFCC9C78BC8BE2F5D17A0DA2B6F3E32D1B25"
```

> Note: the `public_key` values above are illustrative — fetch real, current
> values from `https://nodes.tox.chat/json` before relying on them.

Get current bootstrap nodes from:
- https://nodes.tox.chat/json (official Tox node list)

### Compatibility

Legacy server bootstrap fields such as `server.tcp_port`, `server.udp_enabled`, and
`server.bootstrap_nodes` are still accepted when reading older configs. Newly serialized configs
always use the canonical top-level `tox:` block.

## Access Control Rules

Restrict which friends can access which destinations.

Create `rules.yaml`:

```yaml
rules:
  - friend: "AABBCCDD..."               # 64 hex characters (public key only)
                                        # `friend_pk` is also accepted as an alias
    allow:
      - host: "127.0.0.1"
        ports: [22, 80, 443]
      - host: "*.internal.example.com"
        ports: []                       # empty = all ports
    deny:
      - host: "10.*"
        ports: []
```

Reference it in server config:

```yaml
server:
  rules_file: /etc/toxtunnel/rules.yaml
```

### Pattern Matching

Target host patterns (`allow[].host` / `deny[].host`):

- A single `*` wildcard is supported per pattern, with one prefix and one
  suffix (e.g. `*.example.com`, `localhost*`, `192.168.*`).
- A bare `*` matches any host.
- Host matching is case-insensitive.
- Multi-segment patterns like `192.168.*.*` will NOT match — the rules engine
  honors only the first `*` for host targets. Use `192.168.*` instead.

Source IP patterns (rule sources, when present) use a separate per-octet
matcher that does support multi-octet wildcards such as `192.168.*.*`.

Other rules:

- Empty `ports: []` means "all ports".
- **Deny rules take precedence over allow rules.**
- The friend identity field accepts `friend` (canonical) or `friend_pk` (alias);
  it must be exactly 64 hex characters (the friend's public key, not the full
  76-char Tox ID).

### Default Behavior

If no `rules_file` is configured, the server is **default-deny**:

- incoming friend requests whose public key is absent from the rules are refused,
- no tunnels can be opened,
- and operators will see a startup warning telling them to configure `server.rules_file`.

In practice, create at least one rule entry per allowed client public key before
attempting the first connection.

## Data Directory

The `data_dir` stores:

| File                      | Description                        |
| ------------------------- | ---------------------------------- |
| `tox_save.dat`            | Tox identity (private key)         |
| `bootstrap_nodes.json`    | Cached bootstrap node list         |
| `known_servers.yaml`      | Client-only: registry of previously-connected servers (alias, last connection, disclosed system info) |

**Important**: Back up `tox_save.dat` to preserve your Tox identity.

## Known-Servers Registry (client side)

Each successful client→server connection writes an entry to
`<data_dir>/known_servers.yaml`: 76-char Tox ID, optional alias, first/last
connection timestamps, transport (`udp` direct or `tcp` relay), and any system
info the server explicitly opted into disclosing.

Manage the registry from the CLI:

```bash
toxtunnel servers list                       # compact list
toxtunnel servers list --full                # full 76-char IDs
toxtunnel servers show <alias_or_tox_id>     # full record
toxtunnel servers add <alias> <tox_id>       # register an alias
toxtunnel servers remove <alias_or_tox_id>   # forget
```

Each `servers` subcommand accepts `-d/--data-dir DIR` (defaults to
`~/.config/toxtunnel`) or `-c/--config FILE` (reads `data_dir` from the config).
The separate `print-id` subcommand does **not** read `-c/--config`; for a
non-default identity use `toxtunnel print-id --data-dir <data_dir>`.

Once an alias is registered it can be used anywhere a Tox ID is expected
(`--server-id <alias>`, `client.server_id: <alias>` in YAML). The CLI prints a
`Resolved alias '<alias>' to <prefix>...` line on stderr when this happens.

**Concurrency caveat:** the on-disk file is treated as single-writer. Stop the
toxtunnel daemon before running `servers add`/`remove`, otherwise your edit
will race with the daemon's on-connect updates and one side will be lost.

## Server Self-Disclosure (`server.disclose:`)

When a client comes online it sends an `INFO_REQUEST` (frame `0x06`). The server
replies with `INFO_REPLY` (`0x07`) containing a small YAML map of only the
fields its operator has explicitly opted into.

All disclosure fields default to `false`. A default server discloses **nothing**.

| Field | Source |
|---|---|
| `hostname` | `gethostname()` / `GetComputerName` |
| `os` | `uname.sysname` / `"Windows"` |
| `os_version` | `uname.release` / Windows build number |
| `arch` | `uname.machine` / native arch |
| `uptime` | Linux `/proc/uptime`; macOS `kern.boottime`; Windows `GetTickCount64` |
| `toxtunnel_version` | Build version string |

Per-field map:

```yaml
server:
  disclose:
    hostname: true
    os: true
    arch: true
    # remaining fields default false
```

Or scalar shorthand (useful in dev / private deployments):

```yaml
server:
  disclose: true     # flips every field on
  # disclose: false  # equivalent to the default (everything off)
```

Old servers (pre-v0.2.0) that don't know `INFO_REQUEST` ignore the frame; the
client times out silently and persists only locally-observable metadata
(`tox_id`, `last_connection_type`, timestamps).

> **ToxTunnel does NOT implement remote command execution.** Disclosure is the
> only way the server publishes runtime metadata, and the operator opts in
> per field.

## Tunnel-level Tuning (`tunnel:`)

Per-tunnel buffering and lifecycle knobs. All defaults are safe — only touch
these if a profile or operational requirement justifies it. The wire format is
unchanged regardless of values.

```yaml
tunnel:
  idle_timeout_seconds: 0          # 0 = disabled (default). >0 closes tunnels
                                    # that have been idle (no TUNNEL_DATA in
                                    # either direction) for this long.
  reaper_tick_seconds: 30          # how often the reaper scans; only matters
                                    # if idle_timeout_seconds > 0.

  keepalive_interval_seconds: 0    # 0 = disabled (default). >0 sends a PING to
                                    # each peer every interval and declares it
                                    # dead after 3× of no PONG.

  coalesce_max_delay_us: 200       # 0 disables coalescing. Otherwise the
                                    # per-tunnel WriteQueue holds small writes
                                    # for up to this many microseconds before
                                    # emitting one TUNNEL_DATA frame.
  coalesce_max_bytes: 1362         # flush early if the buffered payload hits
                                    # this many bytes. Default matches the
                                    # TUNNEL_DATA payload MTU.
```

| Field | Default | Reloadable? | Effect |
|---|---|---|---|
| `idle_timeout_seconds` | `0` (off) | restart | Idle reaper threshold. When >0 the reaper closes tunnels with no TUNNEL_DATA in either direction for the given duration. |
| `reaper_tick_seconds` | `30` | restart | Reaper scan period. Lower = faster reclaim, higher = less wake-up overhead. |
| `keepalive_interval_seconds` | `0` (off) | restart | Application-level PING/PONG liveness. When >0, each peer is PINGed every interval and declared dead after `3×interval` of no PONG — the server drops that friend's tunnels, the client marks the active server offline so failover promotes a fallback. Catches an app wedged while its toxcore link still looks alive. |
| `coalesce_max_delay_us` | `200` | restart | Max time a small write is buffered before being emitted. `0` disables coalescing — every write becomes its own TUNNEL_DATA frame, matching pre-v0.3.0 behaviour. |
| `coalesce_max_bytes` | `1362` | restart | Buffer-size flush threshold. Should be ≤ TUNNEL_DATA payload MTU; higher values are clamped. |
| `coalesce_mode` | `fixed` | restart | Coalescer policy. `fixed` (v0.3.0 behaviour), `adaptive` (state machine selects between bypass / drain / batch per push), `bypass` (no hold timer ever), `drain` (emit on overflow only). |

### Adaptive coalescing (`coalesce_mode: adaptive`)

The adaptive coalescer maintains a per-tunnel EWMA of write size and
inter-arrival gap. On every push it picks one of three behaviours:

- **`bypass`** — `avg_write_size >= MTU`. Every push emits a single
  frame; no hold timer. Best for bulk transfers.
- **`drain`** — `avg_write_gap_us > 4 * coalesce_max_delay_us`.
  Sub-MTU writes that arrive faster than the hold window: emit on
  overflow only, never armed by a timer.
- **`batch`** — otherwise. The v0.3.0 default: hold for up to
  `coalesce_max_delay_us` (200 µs) or `coalesce_max_bytes` (1362 B),
  whichever comes first.

A 4-tick hysteresis prevents the state machine from flapping on a
brief burst. Transitions log at DEBUG and increment
`toxtunnel_coalesce_policy_transitions_total`.

### BDP-aware flow control (`flow_control:`)

```yaml
flow_control:
  mode: fixed                  # fixed (default; v0.3.0) | bdp
  send_window_min_bytes: 65536           # 64 KiB clamp floor (bdp mode)
  send_window_max_bytes: 4194304         # 4 MiB clamp ceiling (bdp mode)
  safety_factor_x100: 150                # 1.5× BDP headroom
  fixed_window_bytes: 262144             # 256 KiB — used in fixed mode
```

When `mode: bdp`, the per-tunnel `BdpFlowControl` updates an EWMA of
RTT (from PING/PONG round-trip) and bandwidth (cumulative-ACK delta)
and recomputes the target window as `bdp × safety_factor_x100 / 100`
clamped to `[min, max]`. ACK threshold scales proportionally to keep
~16 ACKs in flight regardless of window size.

`mode: fixed` preserves the v0.3.0 256 KiB / 16 KiB cadence
byte-for-byte. Non-reloadable.

### Tunnel-resume protocol (`tunnel.resume:`) — opt-in

```yaml
tunnel:
  resume:
    enabled: false                  # OPT-IN. Default false.
    state_path: ""                  # default: <data_dir>/tunnel_resume_state.yaml
    max_age_seconds: 300            # how long the server holds a disconnected
                                    # friend's tunnels for reattach
    on_gap: passthrough             # passthrough (default) | close
```

When `enabled: true`, the live hold-across-reconnect handshake runs:

- **Server** — on a friend disconnect it holds that friend's whole manager
  (its tunnels and their target TCP connections, keepalive paused) for
  `max_age_seconds` instead of tearing it down, then resurrects it when the
  friend reconnects. A prune timer closes the held tunnels if the friend never
  returns.
- **Client** — on reconnect it sends `TUNNEL_RESUME_REQUEST` for each surviving
  tunnel, carrying its sent/received byte offsets, and acts on the
  `TUNNEL_RESUME_ACK`: continue on `Ok`, close on any decline.
- **Gaps** — there is no application-level retransmit buffer, so bytes lost in
  the disconnect cannot be replayed. `on_gap` decides: `close` drops the tunnel
  (safe — no silent corruption), `passthrough` continues with a logged hole
  (lossy; only for streams that tolerate it).

Resume covers the **live-reconnect** case (a brief Tox-network blip with both
processes still running). It cannot survive a process restart, because the local
TCP sockets do not — the persistent `state_path` store is reserved for that
future use and is not consulted by the live path.

With `enabled: false` the new opcodes (`0x08` / `0x09`) are wire-inactive and
v0.3.0 peers see no change.

The reaper, coalescer, BDP flow control, and resume store all live in
the existing I/O pool — none start new threads. See
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
("Operational Endpoints" and the rows in "Components") for the dataflow.

## Tox-Thread Watchdog (`watchdog:`)

```yaml
watchdog:
  enabled: true              # default on; set false to disable entirely
  deadline_seconds: 30       # default; minimum enforced 5
  systemd_notify: true       # default true on Linux; ignored elsewhere
```

The Tox iteration thread bumps a heartbeat on every return from
`tox_iterate`. A 1 Hz observer on the main `IoContext` calls
`std::abort()` if the heartbeat is older than `deadline_seconds`. The
service manager (systemd, launchd, Windows SCM) handles the restart;
the in-process detector preserves a core dump for postmortem.

Non-reloadable. `systemd_notify: true` periodically sends
`sd_notify(WATCHDOG=1)` on the main thread so a stalled main thread is
caught by `WatchdogSec` if the systemd unit declares one.

## Per-Friend Rate Limiting (`rules.yaml`)

Anti-DoS layer. Default behaviour is "no limiting" (v0.3.0
semantics). When configured, `RateLimiter` runs before `RulesEngine`
on the TUNNEL_OPEN path.

```yaml
# Top-level defaults — apply to every friend that does NOT name its own block.
rate_limit_defaults:
  mode: enforce              # off (default) | report | enforce
  open_per_sec: 10
  open_burst: 50
  bytes_per_sec: 10485760    # 10 MiB/s
  bytes_burst: 33554432      # 32 MiB
  max_concurrent_tunnels: 100

rules:
  - friend: "AABB...64hex..."
    rate_limit:              # per-friend override; additive over defaults
      bytes_per_sec: 104857600
      max_concurrent_tunnels: 200
    allow:
      - host: "127.0.0.1"
        ports: [22]
```

Modes:

- `off` — no limiting, no counters.
- `report` — counters tick on rejection but the request is allowed
  through. Shadow mode for tuning the limits against real traffic.
- `enforce` — over-budget OPENs receive `TUNNEL_ERROR` with reason
  code 3 (`Rate limit exceeded`).

Hot-reloadable via the rules file (`SIGHUP` / `toxtunnel reload`).
Loosening takes effect immediately; tightening is observed lazily on
the next consume + refill cycle.

## Prometheus Metrics (`metrics:`)

`MetricsServer` exposes a `GET /metrics` endpoint in Prometheus text format.
**Default-off**; flip on per-server / per-client as desired.

```yaml
metrics:
  enabled: false                       # default: off
  listen: "127.0.0.1:9105"             # bind address — loopback recommended
  # path: /metrics                     # optional; default /metrics
```

| Field | Default | Reloadable? | Effect |
|---|---|---|---|
| `metrics.enabled` | `false` | restart | Master switch. Setting to `true` starts `MetricsServer` at boot. |
| `metrics.listen` | `127.0.0.1:9105` | restart | HTTP bind. Use a non-loopback bind only if you front-proxy with TLS + auth. |
| `metrics.path` | `/metrics` | restart | URL path. Other paths return `404`. |

The full list of exported series is in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
under "Operational Endpoints → /metrics HTTP". For Grafana / Alertmanager
wiring examples, see [`docs/ADVANCED_SCENARIOS.md`](ADVANCED_SCENARIOS.md)
("Scraping Prometheus metrics").

## Local Inspection IPC (`inspect:`)

`InspectServer` powers the `toxtunnel inspect` CLI. It is **default-on**
because the listener is a local Unix-domain socket (POSIX) or named pipe
(Windows), so the OS permission bits gate access — there is no TCP attack
surface.

```yaml
inspect:
  enabled: true                        # default: on
  socket_path: ""                      # empty = <data_dir>/toxtunnel.sock
                                        # (POSIX) or
                                        # \\.\pipe\toxtunnel-inspect-<pid> (Windows)
  socket_mode: 0600                    # POSIX-only; chmod on the socket file
```

| Field | Default | Reloadable? | Effect |
|---|---|---|---|
| `inspect.enabled` | `true` | restart | Master switch. Set to `false` to disable the IPC listener entirely. |
| `inspect.socket_path` | `<data_dir>/toxtunnel.sock` | restart | Where to bind. Override only if `data_dir` lives on a filesystem that does not support sockets. |
| `inspect.socket_mode` | `0600` | restart | POSIX file mode on the socket inode. `0660` is appropriate if you run the daemon as a system user and want a group to peek. |

The IPC wire format (single-line JSON request → single-line JSON reply) and
the catalogue of `cmd` values live in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
("Operational Endpoints → toxtunnel inspect IPC").

## Hot Reload (`SIGHUP` / reload pipe)

A running daemon will reload a tightly scoped subset of its configuration in
place, without dropping existing tunnels, when it receives:

- POSIX: `SIGHUP` (e.g. `kill -HUP <pid>` or `systemctl reload toxtunnel`).
- Windows: a single byte written to the reload named pipe (default
  `\\.\pipe\toxtunnel-reload-<pid>`). The CLI helper is `toxtunnel reload`.

### Reloadable fields

| Field | Effect on reload |
|---|---|
| `logging.level` | Swapped atomically — next log line uses the new level. |
| `client.forwards` | New listeners are bound, removed listeners are closed, unchanged listeners keep their open tunnels. |
| `server.rules_file` | File is re-read and the parsed `RulesEngine` is swapped in. Tunnels disallowed by the new rules are closed; everything else continues. |

### Non-reloadable fields (reload is rejected, running config untouched)

`mode`, `data_dir`, the entire `tox.*` block, `server.disclose.*`,
`client.server_id`, `client.failover.*`, `client.socks5.*`, the entire
`metrics.*` block, the entire `inspect.*` block, and the `tunnel.*` block.

Changing any of those requires a full restart. A reload that touches one of
them is rejected as a whole — no partial application — and logged at WARN:

```
Reload rejected: field client.server_id is not reloadable
```

A successful reload is logged at INFO and increments
`toxtunnel_reloads_total{result="success"}`.

For a worked example, see [`docs/ADVANCED_SCENARIOS.md`](ADVANCED_SCENARIOS.md)
("Hot-reloading rules.yaml without dropping connections").

## Logging

```yaml
logging:
  level: info              # trace, debug, info, warn, error
  file: /var/log/toxtunnel.log   # optional, defaults to stderr
```

`logging.level` is one of the few fields that is hot-reloadable — see "Hot
Reload" above. `logging.file` is **not** reloadable (it is opened at startup);
rotate it via `logrotate` + `copytruncate` or your platform equivalent.

## Multiple Port Forwards

Client can forward multiple services:

```yaml
client:
  forwards:
    # SSH
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22

    # PostgreSQL
    - local_port: 5432
      remote_host: 127.0.0.1
      remote_port: 5432

    # Web server on server's LAN
    - local_port: 8080
      remote_host: 192.168.1.100
      remote_port: 80
```

Connect with:
```bash
ssh -p 2222 user@localhost
psql -h localhost -p 5432
curl http://localhost:8080
```

## Pipe Mode (SSH ProxyCommand)

Skip the config file for one-off SSH connections:

```bash
ssh -o ProxyCommand="toxtunnel -m client --server-id SERVER_ADDRESS --pipe %h:%p" user@dummy
```

Or add to `~/.ssh/config`:

```
Host my-tox-server
    User myuser
    ProxyCommand toxtunnel -m client --server-id SERVER_ADDRESS --pipe %h:%p
```

Then: `ssh my-tox-server`

> `SERVER_ADDRESS` may be a 76-char Tox ID or a known-servers alias (see the
> Known-Servers Registry section above). After `toxtunnel servers add homelab
> <FULL_ID>` you can write `--server-id homelab` directly.
