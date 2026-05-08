# Configuration

ToxTunnel uses YAML configuration files. CLI flags can override most settings.
Default data directories are `/var/lib/toxtunnel` in server mode and
`$HOME/.config/toxtunnel` in client mode.

## Server Configuration

```yaml
mode: server
data_dir: /var/lib/toxtunnel

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
```

## Client Configuration

```yaml
mode: client
data_dir: ~/.config/toxtunnel

logging:
  level: info

tox:
  udp_enabled: true
  bootstrap_mode: auto
  bootstrap_nodes: []

client:
  server_id: "AABBCCDD..."               # 76 hex characters (full Tox address)

  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22                     # local:2222 -> remote:22

    - local_port: 8080
      remote_host: 192.168.1.100
      remote_port: 80                     # local:8080 -> remote:80
```

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

**Important**: Back up `tox_save.dat` to preserve your Tox identity.

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
