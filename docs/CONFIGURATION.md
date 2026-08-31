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
      local_address: 127.0.0.1
      remote_host: 127.0.0.1
      remote_port: 22                     # local:2222 -> remote:22

    - local_port: 8080
      local_address: 127.0.0.1
      remote_host: 192.168.1.100
      remote_port: 80                     # local:8080 -> remote:80
```

#### Which interface a forward listens on — `local_address`

`local_address` is the local interface the forward binds. **It takes numeric
IP literals only** — `127.0.0.1`, `::1`, `192.168.1.10`, `0.0.0.0`, `::`. It is
not `local_host`, and it does not accept `localhost` or any other hostname;
that would be rejected at startup. (`remote_host` is different: it is resolved
on the *server* side, so a hostname is fine there.)

| Value | Who can reach the forward |
|---|---|
| `127.0.0.1` (recommended) | Only this machine |
| `::1` | Only this machine, over IPv6 |
| A specific interface address | Anything that can reach that interface |
| `0.0.0.0` / `::` | Anything that can route to this host |

**If you omit the key the forward binds `0.0.0.0`** — every interface — which
is what every ToxTunnel before v0.4.13 did unconditionally. That default is
kept only so existing deployments do not change behaviour on upgrade; it is a
compatibility fallback, not a recommendation. A forward is a hole into the
remote network, and on a laptop on a café network the wildcard means anyone on
that network can use it.

So from v0.4.13 a client that omits the key logs a warning at startup naming
the forward, and `toxtunnel config check` reports the same thing:

```
forward 0.0.0.0:2222 -> 127.0.0.1:22 is listening on all interfaces because no
'local_address' was set; anything that can reach this host can use it. Set
'local_address: 127.0.0.1' on this forward to accept only local connections, or
set it explicitly to silence this warning.
```

Writing `local_address: 0.0.0.0` explicitly is a supported choice and silences
the warning — the warning is for operators who did not know, not for those who
decided. Set it explicitly either way; a future release may change the default
to loopback.

Changing `local_address` on a running daemon takes effect on reload: the
listener is stopped and rebound. Adding `local_address: 0.0.0.0` to a forward
that was already binding the wildcard is a no-op and does *not* disturb the
live listener. See [Hot Reload](#hot-reload) for the failure mode when the new
address is not available on the host.

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

Failures carry the server's reason, so a policy rejection is distinguishable
from a network fault:

| Server outcome | `TUNNEL_ERROR` code | SOCKS5 reply | HTTP CONNECT status |
|---|---|---|---|
| Connected | — | `0x00` success | `200 Connection Established` |
| Denied by policy: `rules.yaml`, rate limit, or tunnel cap | 1 | `0x02` connection not allowed by ruleset | `403 Forbidden` |
| Any other open failure: DNS, connect timeout, target lost mid-open | 2 | `0x04` host unreachable | `502 Bad Gateway` |
| Target actively refused the connection | 3 | `0x05` connection refused | `502 Bad Gateway` |
| Anything else (server offline, no tunnel ids) | — | `0x01` general failure | `502 Bad Gateway` |

Servers up to v0.4.11 sent code 3 for policy denials as well, so a rate limit
reached the client as `0x04` "host unreachable". A v0.4.12+ client recognises
those older replies and still reports them as `0x02`.

## Data Directory Locking

A running daemon holds an exclusive lock on its `data_dir`
(`<data_dir>/toxtunnel.lock`, `fcntl` on POSIX / exclusive `CreateFile` on
Windows) for its whole lifetime, and publishes its pid in
`<data_dir>/toxtunnel.pid`. A second daemon pointed at the same directory
refuses to start:

```
data directory /var/lib/toxtunnel is already in use by toxtunnel pid 1234.
```

This is not tidiness: two daemons sharing a `data_dir` share one Tox identity
(`tox_save.dat`), one inspect socket, one `known_servers.yaml` and one resume
store. The lock is a kernel lock, so it is released automatically however the
holder dies — a `kill -9` leaves a stale pid file, which the next daemon simply
overwrites.

Startup also fails (exit 1) if the lock cannot be taken for any other reason,
such as an unwritable directory. Set `TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR=1` to
start anyway; only do that when the `data_dir` provably cannot host a lock, and
be aware nothing then stops a second daemon from corrupting shared state.

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

LAN mode is also the right choice for **same-host / loopback testing** (server and client on one
machine): in the default `auto` mode two same-host daemons often never friend (DHT returns each
peer's NAT-translated public IP and the loopback connect fails without NAT hairpin), whereas LAN
mode brings the friend online in ~10 s with no internet. See the `tox-tunnel-ops` skill's
`examples/local-loopback-test.md` for a full single-machine walk-through.

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
  - friend: "AABBCCDD..."               # 64 hex characters = the first 64 chars of the
                                        # client's 76-char Tox ID (the public key; the trailing
                                        # 12 chars are nospam+checksum). `friend_pk` is also
                                        # accepted. A wrong length is rejected when the rules file
                                        # loads. Tip: `toxtunnel print-id --data-dir <client_data_dir>`
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
The `print-id` subcommand accepts the same two flags: `toxtunnel print-id
-c <daemon.yaml>` prints the identity from the config's `data_dir` (so it always
matches the daemon), and `toxtunnel print-id --data-dir <data_dir>` targets a
directory directly. When no identity exists yet at the resolved directory,
`print-id` creates one and says so on stderr.

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
  reaper_tick_seconds: 10          # how often the reaper scans; only matters
                                    # if idle_timeout_seconds > 0.

  keepalive_interval_seconds: 0    # 0 = disabled (default). >0 sends a PING to
                                    # each peer every interval and declares it
                                    # dead after 3× of no PONG.

  # Note: a tunnel stuck in "Disconnecting" is already covered by
  # `half_close_timeout_seconds`, which is ON by default (120s). Set
  # `idle_timeout_seconds` only to reclaim tunnels that are idle in a
  # non-terminal state — it is a broader policy, not the fix for a half-close.
  # Historically a tunnel could linger in "Disconnecting" state
  # indefinitely while waiting for the reciprocal close that never arrives —
  # observable in `toxtunnel inspect tunnels` with a growing `idle_seconds`.

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
| `reaper_tick_seconds` | `10` | restart | Reaper scan period. Lower = faster reclaim, higher = less wake-up overhead. |
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
  mode: bdp                    # bdp (default since v0.4.1) | fixed (v0.3.0 cadence)
  send_window_min_bytes: 65536           # 64 KiB clamp floor (bdp mode)
  send_window_max_bytes: 4194304         # 4 MiB clamp ceiling (bdp mode)
  safety_factor_x100: 150                # 1.5× BDP headroom
  fixed_window_bytes: 262144             # 256 KiB — used in fixed mode
```

`mode: bdp` is the default since v0.4.1. The per-tunnel
`BdpFlowControl` updates an EWMA of RTT (from PING/PONG round-trip)
and bandwidth (cumulative-ACK delta) and recomputes the target window
as `bdp × safety_factor_x100 / 100` clamped to `[min, max]`. ACK
threshold scales proportionally to keep ~16 ACKs in flight regardless
of window size.

`mode: fixed` opts out and locks the v0.3.0 256 KiB / 16 KiB cadence
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
on the TUNNEL_OPEN path, and on the inbound TUNNEL_DATA path.

```yaml
# Top-level defaults — the baseline for every friend.
rate_limit_defaults:
  mode: enforce              # off (default) | report | enforce
  open_per_sec: 10
  open_burst: 50
  bytes_per_sec: 1048576     # inbound TUNNEL_DATA payload, bytes/sec
  bytes_burst: 4194304
  max_concurrent_tunnels: 100

rules:
  - friend: "AABB...64hex..."
    rate_limit:              # per-friend override, merged field by field
      max_concurrent_tunnels: 200
    allow:
      - host: "127.0.0.1"
        ports: [22]
```

Modes:

- `off` — no limiting, no counters, no accounting.
- `report` — counters tick when a request or a frame is over budget,
  but nothing is refused or delayed. Shadow mode for tuning the limits
  against real traffic before switching them on. Switching a friend from
  `enforce` to `report` by reload releases anything already deferred for
  it immediately, in order.
- `enforce` — over-budget OPENs receive `TUNNEL_ERROR` with reason
  code 1 (`Rate limit exceeded`); over-budget TUNNEL_DATA is deferred
  and replayed (see below).

  Code 1 is the *policy-denied* category, so a SOCKS5 client answers
  `0x02` ("connection not allowed by ruleset") and an HTTP CONNECT
  client `403 Forbidden` — the caller can tell your rate limit apart
  from a dead target. Servers up to v0.4.11 sent code 3 here, which
  clients could only report as `0x04` "host unreachable"; a v0.4.12+
  client still recognises that older reply as a denial.

### Override merging

A per-friend `rate_limit:` block overrides **only the fields it names**;
every other field — `mode` included — keeps its `rate_limit_defaults`
value. In the example above the friend raises `max_concurrent_tunnels`
to 200 and still inherits `mode: enforce`, `open_per_sec: 10` and
`open_burst: 50`.

Writing a field explicitly is therefore different from omitting it:

| In the friend's block | Effect |
|---|---|
| field omitted | inherits the `rate_limit_defaults` value |
| `open_per_sec: 0` | that friend is exempt from the OPEN rate limit; other fields still inherit |
| `mode: off` | limiting disabled for that friend only |

If the rules file has no `rate_limit_defaults:` block at all, a
friend-only `rate_limit:` block with no `mode` defaults to `enforce` —
there is nothing to inherit, and a configured limit is meant to apply.

> Earlier releases made a per-friend block **replace** the defaults
> wholesale, so naming one field zeroed the rest. Tightening
> `max_concurrent_tunnels` for a friend switched that friend's OPEN rate
> limiting off entirely. Rules files that worked around this by
> repeating every field in each friend block remain correct.

### `bytes_per_sec` / `bytes_burst`

A token bucket over the **payload of inbound TUNNEL_DATA frames** — the
bytes a friend pushes *at* this server, per friend, summed across all of
that friend's tunnels. This is the same direction `open_per_sec` guards:
a server's rules describe what a peer may do to it. Traffic the server
sends back is not metered by this key.

> Earlier releases parsed these keys and did nothing with them. If you
> are upgrading from one of those, a rules file that already sets a byte
> budget will start shaping traffic on restart — check the value is one
> you actually want before rolling it out.

**What `enforce` does when a friend is over budget.** It does not drop
the frame. A tunnel carries TCP semantics, and dropping a TUNNEL_DATA
frame punches a hole in a lossless byte stream that neither end can
detect or repair. Instead the server **defers** the frame: it goes into a
per-friend FIFO and is replayed, in arrival order, as the bucket refills.
Every byte the peer sent is delivered; it just arrives later.

Deferral is what makes the throttle propagate rather than accumulate. A
deferred frame is never handed to its tunnel, so no `TUNNEL_ACK` is
generated for it, so the peer's send window fills and the peer stops
sending — the backpressure reaches the origin TCP socket the same way the
existing slow-target path works. The deferral queue is therefore bounded
by flow control, not by hope.

Ordering is preserved for every tunnel-lifecycle frame: `TUNNEL_OPEN`,
`TUNNEL_DATA`, `TUNNEL_CLOSE`, `TUNNEL_ERROR` and the resume opcodes all
queue behind deferred data, because a `TUNNEL_CLOSE` that overtook it
would tear the tunnel down and strand the bytes still waiting. `PING` /
`PONG` (the keepalive channel — delaying it would let a healthy peer be
declared dead), `TUNNEL_ACK` (send-window credit for the *opposite*
direction) and `INFO_REQUEST` / `INFO_REPLY` bypass the queue.

**Two rails bound deferral, and both fail open.** Deferral cannot be
unbounded, and when a bound is reached the server releases the backlog
early — in order, losing nothing — rather than dropping bytes or
disconnecting the peer. The configured rate is briefly exceeded, which is
logged at `warn`. The rails are:

- **32 MiB of deferred bytes per friend.** A memory bound, not an
  accusation: a friend with a large `max_concurrent_tunnels` can reach it
  with entirely well-behaved traffic, so the server does not treat it as
  misbehaviour. If you see this in the log regularly, either
  `bytes_per_sec` is far below what the peer is offering, or the peer is
  not honouring flow control.
- **A release deadline**, computed per frame from its own tunnel's
  remaining reaper slack: `tunnel.idle_timeout_seconds` or
  `tunnel.half_close_timeout_seconds` (whichever is tighter, when
  enabled), minus how long that tunnel has already been idle, minus
  reaper-tick margin. Capped at 60 s, and 60 s flat when neither reaper
  is enabled. This one is a correctness bound: the reapers judge a tunnel
  by when it last saw TUNNEL_DATA, and a parked frame has not reached its
  tunnel yet — so without it, deferral could let the reaper close the
  very tunnel the queued bytes belong to. It is per frame rather than per
  queue because a tunnel that was *already* nearly idle when its frame
  arrived can afford almost no wait; the queue releases at the earliest
  deadline any frame in it asked for.

The consequence worth stating plainly: **a receiver-side deferral cannot
hold an average rate against a peer that ignores flow control.** Against
such a peer the throttle degrades to bursts capped by the memory rail.
It is a budget for cooperative peers, not a defence against a hostile
one; `max_concurrent_tunnels` and `open_per_sec` are the anti-DoS knobs.

**What to expect in the metric.**
`toxtunnel_rate_limit_bytes_throttled_total` counts *frames that found
the bucket short* — one increment per frame, on first judgement, not per
retry and not per byte:

- `mode: report` — the counter rises while traffic is completely
  unaffected. This is the number to watch when sizing a limit: a budget
  that never moves it is not binding, one that moves it constantly is
  tighter than the link.
- `mode: enforce` — the counter rises and those frames were deferred.
  A steadily climbing counter is the throttle working, not an error.
  Expect throughput for that friend to settle at `bytes_per_sec` after
  the initial `bytes_burst`, unless a rail above is being hit.
- `mode: off` — the counter never moves for that friend; nothing is even
  accounted.

**Both fields must be non-zero for the bucket to engage**, exactly as
with `open_per_sec` / `open_burst`: a refill rate with no capacity holds
no tokens. `bytes_burst: 0` is the way to exempt a friend. A non-zero
`bytes_burst` is raised to 65535 if it is smaller — a bucket cannot admit
an item bigger than its capacity, and a maximum-size TUNNEL_DATA frame
would otherwise be deferred forever. Both fields are also clamped to 1
GB/s, which is three orders of magnitude past what a Tox tunnel carries;
the clamp exists so the refill arithmetic cannot overflow. `effective_spec`
reports the clamped values, i.e. what is actually enforced. `toxtunnel
inspect` does **not** — it carries no rate-limit state at all, so if you
configured a value above the clamp you have to apply the clamp yourself to
know what is in force.

### Reloading rate limits resets every token bucket

Rate limits are hot-reloadable via the rules file (`SIGHUP` /
`toxtunnel reload`). The reload is applied as a single atomic swap: the
daemon discards the whole per-friend limiter table and rebuilds it from
the new rules, so a concurrent `TUNNEL_OPEN` is judged against either
the complete old generation or the complete new one — never a mixture.

**A reload therefore refills every friend's bucket and zeroes its
rejection counters.** The table is destroyed wholesale because it has
to be: a friend that was dropped from the new rules must not keep its
old bucket alive. There is no carry-over of accumulated token state and
no "lazy tightening" — an earlier revision of this document claimed the
new limits were observed gradually on the next refill cycle, which was
never what the code did.

Operational consequences, in order of how much they matter:

- **Anyone who can trigger a reload can refresh their own burst
  allowance.** A friend that is mid-flood and pinned at zero tokens
  gets a full `open_burst` again on every `SIGHUP`. If reloads are
  automated (a config-management agent, a file watcher, a cron
  `toxtunnel reload`), keep the cadence well above the window you
  expect the limiter to enforce over — a limiter reset every 30 s
  cannot hold an average rate measured over minutes. The rate limiter
  is not a defence against an adversary who also controls reloads.
- **Per-friend rejection counts in `toxtunnel inspect` restart at 0.**
  Treat them as "since the last reload", not "since start".
- **Byte buckets refill too**, so a friend that was being throttled gets
  a fresh `bytes_burst` on every reload. Anything already deferred is
  still replayed in order — the reload changes the budget, never the
  queue — and adding or removing a byte budget takes effect on live
  connections without waiting for a reconnect.
- **Prometheus counters are unaffected.**
  `toxtunnel_rate_limit_open_rejected_total` and its siblings live in
  `MetricsRegistry`, not in the buckets, so they stay monotonic across
  reloads. Alert on those, not on the inspect snapshot.

Everything else about a limit change applies at once: the new spec is
in force for the very next `TUNNEL_OPEN`, whether it loosens or
tightens.

## Prometheus Metrics (`metrics:`)

`MetricsServer` exposes a `GET /metrics` endpoint in Prometheus text format.
**Default-off**; flip on per-server / per-client as desired.

```yaml
metrics:
  enabled: false                       # default: off
  listen: "127.0.0.1:9100"             # bind address — loopback recommended
  # path: /metrics                     # optional; default /metrics
```

| Field | Default | Reloadable? | Effect |
|---|---|---|---|
| `metrics.enabled` | `false` | restart | Master switch. Setting to `true` starts `MetricsServer` at boot. |
| `metrics.listen` | `127.0.0.1:9100` | restart | HTTP bind. Use a non-loopback bind only if you front-proxy with TLS + auth. |
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
```

| Field | Default | Reloadable? | Effect |
|---|---|---|---|
| `inspect.enabled` | `true` | restart | Master switch. Set to `false` to disable the IPC listener entirely. |

The socket path is hard-coded by platform — there is no
`inspect.socket_path` or `inspect.socket_mode` setting. On POSIX the
listener binds at `<data_dir>/toxtunnel.sock` (mode `0600` per OS umask
at create time); on Windows it serves `\\.\pipe\toxtunnel-<pid>` (DACL: the
daemon's user, SYSTEM, and Administrators). The daemon also writes
`<data_dir>/toxtunnel.pid` so the CLI can find the pipe / process.
If you need a different path, change `data_dir`.

The IPC wire format (single-line JSON request → single-line JSON reply) and
the catalogue of `cmd` values live in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
("Operational Endpoints → toxtunnel inspect IPC").

## Hot Reload (`SIGHUP` / reload pipe)

A running daemon will reload a tightly scoped subset of its configuration in
place, without dropping existing tunnels, when it receives:

- POSIX: `SIGHUP` (e.g. `kill -HUP "$(cat <data_dir>/toxtunnel.pid)"` or
  `systemctl reload toxtunnel`).
- Windows: `RELOAD\n` written to the reload named pipe
  (`\\.\pipe\toxtunnel-reload-<pid>`).

The CLI helper `toxtunnel reload [-d DIR | -c CONFIG]` does the right thing on
both platforms: it reads `<data_dir>/toxtunnel.pid` and sends SIGHUP (POSIX) or
writes to the pipe (Windows). `TOXTUNNEL_RELOAD_PID` overrides the pid file.

### Reloadable fields

| Field | Effect on reload |
|---|---|
| `logging.level` | Swapped atomically — next log line uses the new level. |
| `client.forwards` | New listeners are bound, removed listeners are closed, unchanged listeners keep their open tunnels. A rule is "unchanged" by its *effective* `local_address` plus `local_port`/`remote_host`/`remote_port`, so adding `local_address: 0.0.0.0` to a forward that already bound the wildcard disturbs nothing; changing it to a different address stops and rebinds that listener. |
| `server.rules_file` | File is re-read, the parsed `RulesEngine` is swapped in, rate-limit buckets are synced and per-friend tunnel caps re-applied. **Already-open tunnels are not touched** — even ones the new rules would now deny; only the next `TUNNEL_OPEN` is evaluated against them. Drop the friend (or restart) to cut live traffic. |

### Non-reloadable fields (reload is rejected, running config untouched)

`mode`, `data_dir`, the entire `tox.*` block, `server.disclose.*`,
`client.server_id`, `client.failover.*`, `client.socks5.*`, the entire
`metrics.*` block, the entire `inspect.*` block, the entire `tunnel.*`
block (including `coalesce_*`, `idle_timeout_seconds`, `reaper_tick_seconds`,
`keepalive_*`, and `resume.*`), the entire `flow_control.*` block, and
the entire `watchdog.*` block.

Changing any of those requires a full restart. A reload that touches one of
them is rejected as a whole — no partial application — and logged at ERROR:

```
reload rejected: config reload rejected: field 'client.server_id' requires a restart (not in the reloadable subset)
```

A successful reload is logged at INFO (`config reloaded (rules: N rules)` on the
server, `config reloaded (forwards: +A -B)` on the client). There is no reload
counter in the metrics endpoint — the log is the record.

### A forward whose new bind address is unavailable stays down

Reload rebinds a changed forward by **stopping the old listener first**, then
binding the new one. If the new `local_address` parses but is not usable on
this host — not assigned to any interface, or that port is already taken on it
— the new bind fails and **that forward is left down**: the old listener is
already gone.

This is contained rather than fatal, and deliberately so. Reload is
best-effort *per forward*: the daemon keeps running, every other forward keeps
serving, and tunnels already established through the old listener are
unaffected (they are accepted connections, not listeners). The failure is
logged at ERROR and reported in the reload result, and because the rule is not
recorded as active, a later reload retries it — so fixing the address and
reloading again is enough, with no restart.

```
Reload: not forwarding 10.1.2.3:2222 -> 127.0.0.1:22 (Can't assign requested address)
```

Verify with `toxtunnel config check` before reloading a live daemon.

One client-side caveat: a reload that *adds* a forward whose local port is
already taken applies everything else and logs
`reload applied with warnings: 127.0.0.1:N: Address already in use`. That one
forward is not served; the next reload retries it. At **startup** a busy forward
port is fatal instead: the daemon logs `cannot listen on configured forward
port(s): 127.0.0.1:N: …` and exits 1, rather than coming up healthy-looking
while forwarding nothing. (On Windows the OS wording is "Only one usage of each
socket address … is normally permitted"; listeners there take
`SO_EXCLUSIVEADDRUSE`, so a second instance cannot quietly share the port the
way plain `SO_REUSEADDR` would allow.)

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

The file sink flushes immediately on every `info`/`warn`/`error` line, and
buffered `debug`/`trace` lines are flushed at least every 2 seconds (via
spdlog's periodic flush thread). Operators tailing the log will see steady-state
events with no perceptible lag; you do not need to send `SIGUSR1` or any other
"flush" signal. The trade-off is one extra syscall per `info` line — negligible
under any realistic toxtunnel workload.

## Multiple Port Forwards

Client can forward multiple services:

```yaml
client:
  forwards:
    # SSH
    - local_port: 2222
      local_address: 127.0.0.1
      remote_host: 127.0.0.1
      remote_port: 22

    # PostgreSQL
    - local_port: 5432
      local_address: 127.0.0.1
      remote_host: 127.0.0.1
      remote_port: 5432

    # Web server on server's LAN
    - local_port: 8080
      local_address: 127.0.0.1
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
