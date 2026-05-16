# ToxTunnel

TCP tunneling over the [Tox](https://tox.chat) P2P network.

Forward any TCP port through Tox with end-to-end encryption, no central server, and automatic NAT traversal.

---

## Why ToxTunnel?

### vs. Specific Solutions

| | ToxTunnel | frp / ngrok | Tailscale / ZeroTier | WireGuard / OpenVPN |
|---|---|---|---|---|
| **Need Registration?** | **No** | ngrok requires account; frp needs relay server | Account required | No |
| **Need Central Server?** | **No** | Yes (relay/broker) | Coordination server | Manual or self-hosted |
| **Cost** | **Free, forever** | Free tiers limited; paid plans | Free tier limited | Free (self-hosted) |
| **Setup Steps** | Build → run | Deploy relay + configure client | Sign up → install → authorize | Generate keys → configure routes |
| **NAT Traversal** | **Automatic** (Tox DHT) | Relay handles it | DERP relay fallback | Manual port forward or STUN |
| **LAN Optimization** | **Direct P2P, zero hop** | Still routes through relay | Can do direct, but needs coordinator | Direct if configured |
| **E2E Encryption** | **Always on** (NaCl) | TLS to relay; relay can inspect | WireGuard-based | Yes |
| **Privacy** | **No accounts, no logs, no metadata** | Provider sees traffic metadata | Provider sees connection graph | Self-hosted = private |
| **Bandwidth** | **Your ISP only** | Relay server bottleneck | DERP relay bottleneck | Your ISP / server |
| **Works Offline / Air-gapped** | **Yes** (LAN mode) | No | No | Yes (manual config) |

### Key Advantages

- **No Registration Required** - Just install and run. No account, no email, no phone number, no verification. Generate a Tox ID locally and start tunneling immediately. Compare this to ngrok (account + authtoken), Tailscale (Google/Microsoft/GitHub login), or ZeroTier (account + network ID).

- **True P2P, No Relay** - Data flows directly between peers. No relay server to become a bottleneck, a single point of failure, or a surveillance point. frp and ngrok route everything through a central server; even Tailscale falls back to DERP relays when direct connection fails.

- **LAN-First Design** - When both devices are on the same local network, ToxTunnel connects directly via LAN with zero hops and near-zero latency — no internet required, no external coordination. Most VPN and tunnel solutions still route through external servers even for same-network peers.

- **Zero Config NAT Traversal** - The Tox DHT network handles NAT hole-punching automatically. No router port forwarding, no STUN/TURN setup, no firewall rules. It just works.

- **End-to-End Encrypted** - All traffic is encrypted with NaCl (libsodium) — the same cryptography used by Signal. Encryption is mandatory and cannot be disabled. Unlike TLS-to-relay solutions, no intermediary can inspect your data.

- **No Metadata Leakage** - No accounts means no identity graph. No central server means no connection logs. Your traffic patterns are visible only to your ISP, not to any service provider.

- **Cross-Platform** - Works on Linux, macOS, Windows with consistent experience.

- **Open Source** - Full transparency, auditable code, GPLv3 licensed.

### v0.3.0 Capabilities at a Glance

- **Dynamic destinations** — Run the client as a SOCKS5 / HTTP CONNECT proxy
  (`--socks5 127.0.0.1:1080`) and point a browser, `curl`, or any
  proxy-aware tool at it. No need to enumerate every port in `forwards:`.
  Loopback-only by design.
- **Prometheus metrics** — Opt-in `/metrics` HTTP endpoint exporting
  tunnel/byte/error counters. Scrape it from Prometheus / VictoriaMetrics
  with zero extra infra.
- **Runtime inspect** — `toxtunnel inspect tunnels` / `inspect status`
  talks to the live daemon over a local Unix socket (Windows named pipe)
  and prints tunnel state without touching `/proc` or restarting.
- **Hot reload** — `kill -HUP <pid>` (POSIX) or `toxtunnel reload`
  (Windows) re-reads the YAML and applies rules, forwards, and log level
  without dropping existing tunnels.
- **Multi-server failover** — Give the client a list of server Tox IDs.
  It connects to all of them, runs the active session against one, and
  fails over automatically if the active server goes offline. Returns to
  the primary once it stays online for the configured grace window.
- **Idle tunnel reaper** + **write coalescing** — Server-side knobs that
  keep long-lived deployments lean (closes idle tunnels) and small-write
  workloads efficient (batches up to one Tox-MTU per packet).

---

## How It Works

### Principle Overview

```
                          No registration, no server, no config
                          ──────────────────────────────────────

    Your Laptop                                            Remote Machine
  ┌──────────────┐          Tox P2P Network            ┌──────────────────┐
  │              │     ┌───────────────────────┐       │                  │
  │  App ──► :2222 ════╡  Encrypted P2P Link  ╞══════► :22 ──► SSH       │
  │              │     │  (NaCl / libsodium)   │       │                  │
  │  ToxTunnel   │     └───────────────────────┘       │  ToxTunnel       │
  │   Client     │       NAT traversal: auto           │   Server         │
  └──────────────┘       LAN: direct, 0 hop            └──────────────────┘
```

**Three steps, no accounts:**

```
Server:   ./toxtunnel -m server           → prints Tox ID
Client:   ./toxtunnel -c client.yaml      → opens local port(s)
Connect:  ssh -p 2222 localhost           → done
```

### How Connection Is Established

```
  Client                     Tox DHT                    Server
    │                           │                          │
    │   1. Generate Tox ID      │    1. Generate Tox ID    │
    │       (local, instant)    │       (local, instant)   │
    │                           │                          │
    │   2. Lookup Server ID ──► │                          │
    │                           │ ◄── 2. Announce to DHT   │
    │   3. NAT hole-punch ──────┼──────────────────────►   │
    │                           │                          │
    │   4. ◄══════ Encrypted P2P channel established ═══►  │
    │                           │                          │
    │   5. TCP traffic flows directly, no relay             │
    │      ◄══════════════════════════════════════════►     │
```

### LAN vs Internet

```
  Same LAN (direct, fastest):

    Client ◄══════════════════════► Server
              Direct P2P, 0 hops
              No internet needed


  Different Networks (NAT traversal):

    Client ◄───► NAT ◄───► Tox DHT ◄───► NAT ◄───► Server
                       hole-punch
                 then: Client ◄════════════► Server
                         Direct P2P, no relay
```

---

## Installation

### One-line install (recommended)

Each installer auto-detects your architecture, downloads the latest
release, installs the native package, seeds a config, and starts the
service.

**macOS / Linux** (DEB / RPM / .pkg auto-detected):

```bash
# Server (default — listens for clients, gets a Tox ID)
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh

# Client (writes a client config scaffold; service stays idle until you fill in server_id + flip allow_client_daemon)
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh -s -- --mode client
```

**Windows** (run PowerShell as Administrator):

```powershell
# Server
irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex

# Client (env var works around `iex` not passing args)
$env:TOXTUNNEL_MODE = 'client'; irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex
```

The installers respect three env vars / flags: `TOXTUNNEL_MODE` (`server`|`client`),
`TOXTUNNEL_VERSION` (`latest`|`vX.Y.Z`), `TOXTUNNEL_REPO` (`owner/repo`). After
install you'll see the binary path, config path, and next-step instructions
(get the Tox ID for server, fill in `server_id` for client).

### From GitHub Releases (manual)

Every release publishes both **versioned** assets
(`toxtunnel-<version>-<System>-<arch>.<ext>`) and a stable **`-latest`** alias
(`toxtunnel-<System>-<arch>-latest.<ext>`). The commands below use the alias
via `releases/latest/download/...`, which always serves the newest release.
For a specific version, browse [GitHub Releases](https://github.com/anonymoussoft/tox-tcp-tunnel/releases)
and use the versioned filename instead.

#### Linux (DEB - Ubuntu/Debian)

```bash
ARCH=x86_64   # or aarch64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Linux-${ARCH}-latest.deb"
sudo dpkg -i "toxtunnel-Linux-${ARCH}-latest.deb"
```

The DEB package automatically:
- Installs `toxtunnel` to `/usr/bin/`
- Creates a `toxtunnel` system user and group
- Creates data directory `/var/lib/toxtunnel`
- Installs config template to `/etc/toxtunnel/config.yaml`
- Registers and **starts** the systemd service (`systemctl enable --now`)

Background services honor `service.auto_start` / `service.allow_client_daemon` in the YAML config (server installs seed `service.auto_start: true`; client defaults keep the daemon idle unless explicitly enabled).

Manage the service:

```bash
sudo systemctl start toxtunnel     # Start
sudo systemctl enable toxtunnel    # Enable on boot
sudo systemctl status toxtunnel    # Check status
sudo systemctl stop toxtunnel      # Stop
```

#### Linux (RPM - Fedora/RHEL/CentOS)

```bash
ARCH=x86_64   # or aarch64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Linux-${ARCH}-latest.rpm"
sudo rpm -i "toxtunnel-Linux-${ARCH}-latest.rpm"
```

Service management is the same as the DEB package (systemd).

#### macOS

```bash
ARCH=arm64    # or x86_64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Darwin-${ARCH}-latest.pkg"
sudo installer -pkg "toxtunnel-Darwin-${ARCH}-latest.pkg" -target /
```

The package installs:
- `toxtunnel` to `/usr/local/bin/`
- Example config to `/usr/local/share/toxtunnel/config.yaml.example`
- Sample launchd plist to `/usr/local/share/toxtunnel/com.toxtunnel.daemon.plist`

The installer **postinstall** copies the plist into `/Library/LaunchDaemons/` and runs `launchctl bootstrap`. You still need to create `/usr/local/etc/toxtunnel/config.yaml` before the daemon can run.

Set up the config (one-time):

```bash
sudo mkdir -p /usr/local/etc/toxtunnel
sudo cp /usr/local/share/toxtunnel/config.yaml.example /usr/local/etc/toxtunnel/config.yaml
# Edit the config for your role (server vs client) and service policy.
```

Manage the job:

```bash
sudo launchctl print system/com.toxtunnel.daemon
sudo launchctl kickstart -k system/com.toxtunnel.daemon   # reload after config edits
```

#### Windows

1. Download the latest MSI from
   `https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Windows-AMD64-latest.msi`
   (use `toxtunnel-Windows-ARM64-latest.msi` for ARM)
2. Run the installer as Administrator
3. The installer places files in `C:\Program Files\ToxTunnel\`. **In v0.2.0 the MSI does
   not auto-register the Windows service** — you register it yourself after creating the config
   (one command, shown below). Subsequent releases will register it automatically.

Create the config and register the service:

```powershell
mkdir 'C:\ProgramData\ToxTunnel' -Force
notepad 'C:\ProgramData\ToxTunnel\config.yaml'

# One-time service registration (run as Administrator):
& 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' install-windows-service `
    -c 'C:\ProgramData\ToxTunnel\config.yaml'
```

Service policy (`service.auto_start` / `service.allow_client_daemon`) decides whether the service
process stays resident or exits successfully without opening ports.

Manage the service:

```powershell
sc start ToxTunnel
sc stop ToxTunnel
sc query ToxTunnel
```

Remove the service registration:

```powershell
& 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' uninstall-windows-service
```

> **Tip:** The bundled `scripts/install.ps1` one-line installer handles all of the above
> in a single command — see the "One-line install" section above.

### From Source

```bash
# macOS
brew install cmake pkg-config libsodium

# Ubuntu/Debian
sudo apt install -y build-essential cmake git pkg-config libsodium-dev

# Clone and build
git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

For Windows build instructions, see [docs/BUILDING.md](docs/BUILDING.md).

---

## Quick Start

### Print Your Tox ID

```bash
# Text output
toxtunnel print-id

# QR code (for scanning with a phone to transfer the ID)
toxtunnel print-id --qr

# QR code with color
toxtunnel print-id --qr --color
```

## SSH Over ToxTunnel

### Scenario

You have two machines:
- **Server Machine** (remote): The machine you want to SSH into
- **Client Machine** (local): Your laptop/desktop

Both machines need ToxTunnel built and `ssh` installed.

---

### Step 1: Start Server (on remote machine)

```bash
./build/toxtunnel -m server
```

Output:
```
Server Tox address: DE47F247CE6D7BE29A5903A234A045A227C6CB969943A8317EA74F7D38810D10D43C53082F2B
TunnelServer started
```

**Copy this 76-character Tox address.** You'll need it on the client.

> Note: The server must stay running. Run it in a terminal or use `nohup`, `tmux`, or systemd.

---

### Step 2: Start Client (on local machine)

Create a config file `client.yaml`:

```yaml
mode: client
data_dir: ~/.config/toxtunnel

tox:
  udp_enabled: true
  bootstrap_mode: auto

client:
  # Paste the server's Tox address here
  server_id: "DE47F247CE6D7BE29A5903A234A045A227C6CB969943A8317EA74F7D38810D10D43C53082F2B"

  forwards:
    - local_port: 2222      # Local port to listen on
      remote_host: 127.0.0.1  # SSH server on remote machine
      remote_port: 22        # SSH port
```

Start the client:

```bash
./build/toxtunnel -c client.yaml
```

Output:
```
Listening on local port 2222 -> 127.0.0.1:22
Client started
```

> Wait for "Server friend 0 is now online" before connecting (may take 10-30 seconds).

If both peers are on the same LAN and you do not want to depend on `https://nodes.tox.chat/json`,
switch the shared tox block to:

```yaml
tox:
  udp_enabled: true
  bootstrap_mode: lan
  bootstrap_nodes: []
```

You can still add private bootstrap daemons under `tox.bootstrap_nodes` as supplements.

---

### Step 3: Connect via SSH

In a new terminal on your local machine:

```bash
ssh -p 2222 your_username@localhost
```

That's it! Your SSH connection is now routed through the Tox network.

---

## Alternative: SSH ProxyCommand (No Config File)

If you prefer not to create a config file, you can use SSH's ProxyCommand feature.

### How It Works

The `--pipe` mode connects stdin/stdout directly to the tunnel, allowing SSH to use it as a transport.

### Example Command

```bash
# Replace with your server's Tox address
SERVER_ID="DE47F247CE6D7BE29A5903A234A045A227C6CB969943A8317EA74F7D38810D10D43C53082F2B"

ssh -o ProxyCommand="./build/toxtunnel -m client --server-id ${SERVER_ID} --pipe 127.0.0.1:22" user@dummy
```

**Explanation:**
- `--pipe 127.0.0.1:22` - Connect to port 22 on the server machine
- `user@dummy` - The hostname is ignored; only the username matters
- Each SSH session starts a new ToxTunnel instance

### SSH Config Setup

Add to `~/.ssh/config`:

```
Host tox-remote
    User your_username
    ProxyCommand /path/to/toxtunnel -m client --server-id YOUR_SERVER_TOX_ADDRESS --pipe 127.0.0.1:22
```

Then simply:

```bash
ssh tox-remote
```

---

## Testing on a Single Machine

To test locally before deploying:

```bash
# Terminal 1: Start server
./build/toxtunnel -m server

# Terminal 2: Start client with the config from Step 2
./build/toxtunnel -c client.yaml -d /tmp/tox-client

# Wait for connection, then:
# Terminal 3: Test SSH
ssh -p 2222 localhost
```

---

## Known-Servers Registry (client side)

Once the client successfully connects to a server, it persists a record under
`<data_dir>/known_servers.yaml`:

- 76-char Tox ID, optional alias, first/last connected timestamps
- Last transport reported by toxcore (`udp` direct or `tcp` relay)
- Server-disclosed system info (only what the server explicitly opted into via
  its `server.disclose.*` config — see below)

Manage the registry from the CLI:

```bash
toxtunnel servers list                       # list known servers (compact)
toxtunnel servers list --full                # show full Tox IDs
toxtunnel servers show homelab               # full record by alias or Tox ID
toxtunnel servers add homelab DE47F2...      # name a Tox ID for later
toxtunnel servers remove homelab             # forget by alias or Tox ID
```

After registering an alias you can use it anywhere a Tox ID is expected:

```bash
toxtunnel -m client --server-id homelab --pipe 127.0.0.1:22
```

```yaml
# client.yaml
client:
  server_id: homelab     # resolved from known_servers.yaml at startup
  forwards:
    - { local_port: 2222, remote_host: 127.0.0.1, remote_port: 22 }
```

`servers list/show/add/remove` accept `-d/--data-dir DIR` (defaults to the same
`~/.config/toxtunnel` used by `print-id`) or `-c/--config FILE` (reads
`data_dir` from the config).

The packaged installs ship `known_servers.yaml.example` next to
`config.yaml.example` (`/usr/share/toxtunnel/` on Linux,
`/usr/local/share/toxtunnel/` on macOS, `share/toxtunnel/` under the Windows
install root) — useful as a schema reference if you'd rather pre-seed the
registry by editing YAML directly.

### Server self-disclosure (opt-in)

When a client comes online it sends an `INFO_REQUEST` control frame. The
server replies with `INFO_REPLY` carrying only the fields it has explicitly
opted into. Defaults are all `false` — a default server discloses **nothing**.

```yaml
# server.yaml — opt in to specific fields
server:
  rules_file: rules.yaml
  disclose:
    hostname: true
    os: true
    arch: true
    # os_version: false        (default)
    # uptime: false            (default)
    # toxtunnel_version: false (default)

  # Or as a global toggle (useful in dev):
  # disclose: true             # flips every field on
  # disclose: false            # flips every field off (default)
```

ToxTunnel does **not** support remote command execution — disclosure is the
only way the server publishes runtime metadata, and the server operator
chooses each field. Old servers that don't know `INFO_REQUEST` simply ignore
the frame; the client falls back to local-only metadata for that entry.

## CLI Reference

```
toxtunnel [OPTIONS]
toxtunnel print-id [OPTIONS]
toxtunnel servers {list|show|add|remove} [OPTIONS]
toxtunnel inspect [tunnels|status] [OPTIONS]
toxtunnel reload [OPTIONS]
toxtunnel install-windows-service [OPTIONS]      # Windows only
toxtunnel uninstall-windows-service              # Windows only
```

### Main Command

| Flag                          | Description                                  |
| ----------------------------- | -------------------------------------------- |
| `-c, --config FILE`           | YAML config file                             |
| `-m, --mode MODE`             | `server` or `client`                         |
| `-d, --data-dir DIR`          | Override data directory (`/var/lib/toxtunnel` for server, `$HOME/.config/toxtunnel` for client) |
| `-l, --log-level LEVEL`       | `trace`, `debug`, `info`, `warn`, `error`    |
| `-p, --port PORT`             | TCP relay port override (server mode)        |
| `--server-id ID`              | Primary server's 76-char Tox address OR an alias from `known_servers.yaml` (client mode) |
| `--server-id-fallback ID`     | Fallback server Tox ID or alias (client mode). Repeatable; tried in order if the primary stays offline. |
| `--pipe HOST:PORT`            | Pipe mode: connect stdin/stdout to tunnel    |
| `--socks5 HOST:PORT`          | Enable SOCKS5 / HTTP CONNECT listener (client mode; loopback only) |
| `--service`                   | Run as system service (systemd/SCM/launchd)  |
| `-v, --version`               | Show version                                 |

### servers Subcommand

| Command                                            | Description                                  |
| -------------------------------------------------- | -------------------------------------------- |
| `toxtunnel servers list [--full] [-d DIR \| -c F]` | List known servers (alias, short Tox ID, last connection) |
| `toxtunnel servers show <alias_or_id>`             | Full record including disclosed system info |
| `toxtunnel servers add <alias> <tox_id> [--notes]` | Register an alias for a Tox ID              |
| `toxtunnel servers remove <alias_or_id>`           | Forget a server                             |

Once an alias is added, `--server-id` and `client.server_id` will accept it.

### print-id Subcommand

| Flag                 | Description                                     |
| -------------------- | ----------------------------------------------- |
| `-d, --data-dir DIR` | Data directory for loading/creating local Tox identity (default: `$HOME/.config/toxtunnel`) |
| `--qr`               | Render Tox ID as terminal QR code               |
| `--color`             | Use ANSI colors in QR output (requires `--qr`)  |

### inspect Subcommand

Talks to a running daemon over local IPC (Unix socket
`<data_dir>/toxtunnel.sock` or Windows named pipe
`\\.\pipe\toxtunnel-inspect-<pid>`) and prints a snapshot of active tunnels or
the daemon's connection status. Read-only; nothing on the wire leaves the host.

| Form                                      | Description                                  |
| ----------------------------------------- | -------------------------------------------- |
| `toxtunnel inspect tunnels [--json]`      | List open tunnels (id, peer, idle, bytes)    |
| `toxtunnel inspect status [--json]`       | Daemon status (mode, friends online, uptime) |
| `-d, --data-dir DIR` / `-c, --config F`   | Where to find the IPC socket / pid file      |

The IPC endpoint is enabled by default (`inspect.enabled: true`). Set it to
`false` in the YAML to disable per-host.

### reload Subcommand

Triggers a hot reload of the running daemon. Reloads only `server.rules_file`
contents, `client.forwards`, and `logging.level` — anything else (Tox
identity, bootstrap nodes, metrics binding) requires a restart.

| Form                                      | Description                                  |
| ----------------------------------------- | -------------------------------------------- |
| `kill -HUP <pid>`                         | POSIX: same effect, no CLI involvement       |
| `toxtunnel reload`                        | Windows: writes to `\\.\pipe\toxtunnel-reload-<pid>` |
| `-d, --data-dir DIR` / `-c, --config F`   | Locate the daemon's pid file                 |

---

## SOCKS5 / HTTP CONNECT (dynamic destinations)

Instead of declaring every `local_port -> remote_host:remote_port` in
`forwards:`, run the client as a local SOCKS5 (and HTTP CONNECT) proxy and let
applications choose the destination. The server still enforces `rules.yaml`,
so this changes nothing about the server's trust boundary.

```yaml
client:
  server_id: "SERVER_TOX_ADDRESS"
  socks5:
    enabled: true
    listen: 127.0.0.1:1080     # loopback-only (non-loopback rejected at startup)
```

Or one-shot from the command line:

```bash
toxtunnel -m client --server-id SERVER_TOX_ADDRESS --socks5 127.0.0.1:1080
```

Then point a browser, `curl`, or any proxy-aware tool at it:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://10.0.0.5:8080/health
curl --proxy 127.0.0.1:1080 https://internal.example.org    # HTTP CONNECT
```

---

## Prometheus /metrics endpoint

Opt-in HTTP endpoint exporting counters for tunnels opened/closed, bytes in/out,
errors, and friend connection state.

```yaml
metrics:
  enabled: true
  listen: 127.0.0.1:9100
  path: /metrics
```

Prometheus scrape config:

```yaml
- job_name: toxtunnel
  static_configs:
    - targets: ['127.0.0.1:9100']
```

The endpoint serves `GET <path>` only; every other request returns 404. Runs on
the existing I/O thread pool — no extra threads.

---

## Multi-server failover

Give the client more than one server Tox ID. It adds every server as a Tox
friend at startup, runs the active session against the first online candidate,
and fails over if the active server stays offline past
`failover.timeout_seconds`. Once the primary (index 0) is back online and stays
online for `prefer_primary_grace_seconds`, the client switches back.

```yaml
client:
  # First entry is the primary; the rest are fallbacks, tried in order.
  server_id:
    - "PRIMARY_TOX_ADDRESS"
    - "FALLBACK_A_TOX_ADDRESS"
    - homelab-backup                # known-servers alias also works
  failover:
    timeout_seconds: 60
    prefer_primary_grace_seconds: 30
  forwards:
    - { local_port: 2222, remote_host: 127.0.0.1, remote_port: 22 }
```

CLI equivalent (repeatable `--server-id-fallback`):

```bash
toxtunnel -m client \
    --server-id PRIMARY_TOX_ADDRESS \
    --server-id-fallback FALLBACK_A_TOX_ADDRESS \
    --server-id-fallback homelab-backup \
    --pipe 127.0.0.1:22
```

---

## Hot reload (SIGHUP / `toxtunnel reload`)

Edit the YAML and reapply rules, forwards, and log level on the live daemon
without dropping existing connections.

```bash
# POSIX (Linux / macOS):
kill -HUP "$(cat /var/run/toxtunnel.pid)"

# Windows (uses a per-pid named pipe under the hood):
toxtunnel reload -c C:\ProgramData\ToxTunnel\config.yaml
```

Anything outside that subset (Tox identity, bootstrap nodes, `metrics.listen`,
`socks5.listen`, `inspect.enabled`) requires a full restart.

---

## Runtime inspect

Peek at a running daemon over local IPC — no remote ports exposed.

```bash
toxtunnel inspect tunnels
toxtunnel inspect status --json
```

Disable the endpoint with `inspect: { enabled: false }` if you don't want even
local processes to see tunnel state.

---

## Multiple Port Forwards

Forward multiple services through one client:

```yaml
client:
  server_id: "SERVER_TOX_ADDRESS"
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22        # SSH

    - local_port: 5432
      remote_host: 127.0.0.1
      remote_port: 5432      # PostgreSQL

    - local_port: 8080
      remote_host: 192.168.1.100
      remote_port: 80        # Web server on remote LAN

    - local_port: 3389
      remote_host: 127.0.0.1
      remote_port: 3389      # Windows RDP

    - local_port: 873
      remote_host: 127.0.0.1
      remote_port: 873        # Rsync
```

### More Scenarios

For detailed guides on various use cases, see:
- [HTTP Tunneling](docs/HTTP_TUNNELING.md) - Web server and proxy access
- [Database Tunneling](docs/DATABASE_TUNNELING.md) - Secure database access
- [Advanced Scenarios](docs/ADVANCED_SCENARIOS.md) - RDP/VNC, Rsync, NAS, custom services

---

## Documentation

- [Building Guide](docs/BUILDING.md) - Windows, Docker, detailed instructions
- [Configuration](docs/CONFIGURATION.md) - Full YAML schema (access control,
  bootstrap nodes, `metrics`, `inspect`, `tunnel`, `socks5`, `failover` blocks)
- [Architecture](docs/ARCHITECTURE.md) - Protocol, threading model, internals
- [HTTP Tunneling](docs/HTTP_TUNNELING.md) - Web server access, HTTP proxy scenarios
- [Database Tunneling](docs/DATABASE_TUNNELING.md) - Database access (PostgreSQL, MySQL, Redis, etc.)
- [Advanced Scenarios](docs/ADVANCED_SCENARIOS.md) - RDP/VNC, Rsync, NAS, custom services

## Packaging

Pre-built installers are published to GitHub Releases on every version tag (`v*`).

Runtime compatibility targets for release artifacts:

- Linux x86_64/aarch64 packages are built against a CentOS 7-era ABI floor (glibc 2.17) and are intended to run on Ubuntu 20.04+, CentOS 7+, and newer derivatives.
- Windows x86_64 release builds target the Windows 7 API baseline while remaining compatible with modern Windows.
- Windows ARM64 artifacts target modern Windows only (Windows 7 has no ARM64 edition).

| Platform | Formats            | Service Type |
|----------|--------------------|--------------|
| Linux    | DEB, RPM, tar.gz   | systemd      |
| macOS    | .pkg, tar.gz       | launchd      |
| Windows  | MSI                | Windows SCM  |

Build installers locally:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build && cpack    # produces platform-native packages
```

---

## License

GPLv3 - see [LICENSE](LICENSE)
