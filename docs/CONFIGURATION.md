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
  rules_file: /etc/toxtunnel/rules.yaml   # optional access control
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

If no `rules_file` is configured, the server allows all connections from any friend.

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

Each subcommand accepts `-d/--data-dir DIR` (defaults to the same
`~/.config/toxtunnel` used by `print-id`) or `-c/--config FILE` (reads
`data_dir` from the config).

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

## Logging

```yaml
logging:
  level: info              # trace, debug, info, warn, error
  file: /var/log/toxtunnel.log   # optional, defaults to stderr
```

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
