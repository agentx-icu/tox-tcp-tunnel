# Advanced Scenarios

This guide covers advanced use cases for ToxTunnel including remote desktop, file transfer, NAS access, and custom services.

## Table of Contents

1. [Rsync File Transfer](#rsync-file-transfer)
2. [Remote Desktop (RDP/VNC)](#remote-desktop-rdpvnc)
3. [NAS Access](#nas-access)
4. [Custom Services](#custom-services)
5. [SOCKS5 / HTTP CONNECT Proxy](#socks5--http-connect-proxy)
6. [Scraping Prometheus Metrics](#scraping-prometheus-metrics)
7. [Live Tunnel Inspection During Incidents](#live-tunnel-inspection-during-incidents)
8. [Hot-Reloading rules.yaml Without Dropping Connections](#hot-reloading-rulesyaml-without-dropping-connections)
9. [Multi-Server Failover](#multi-server-failover)
10. [Multi-hop Tunneling](#multi-hop-tunneling)
11. [High Availability](#high-availability)
12. [Service Integration](#service-integration)

---

## Rsync File Transfer

Synchronize files between machines using ToxTunnel for secure tunneling.

### Single-Machine Testing

```bash
# Terminal 1: Start an rsync daemon for testing
mkdir -p /tmp/rsync-root /tmp/dest
echo "Hello World" > /tmp/rsync-root/test.txt
echo "Data file" > /tmp/rsync-root/data.txt

cat > /tmp/rsyncd.conf <<'EOF'
[files]
path = /tmp/rsync-root
read only = false
use chroot = false
EOF

rsync --daemon --no-detach --config=/tmp/rsyncd.conf
```

```bash
# Terminal 2: Start ToxTunnel server
./build/toxtunnel -m server -d /tmp/toxtunnel-server
```

Copy the server's Tox address.

> For multi-host or repeated scenarios it's worth registering each server once:
> `toxtunnel servers add <alias> <tox_id>`, then use `--server-id <alias>` or
> `client.server_id: <alias>` everywhere below. The registry lives at
> `<data_dir>/known_servers.yaml` and survives reconnects. See the
> "Known-Servers Registry" section of `docs/CONFIGURATION.md`.

```bash
# Terminal 3: Start ToxTunnel client
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"

cat > /tmp/toxtunnel-rsync-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 8873
      remote_host: 127.0.0.1
      remote_port: 873
EOF

./build/toxtunnel -c /tmp/toxtunnel-rsync-client.yaml
```

```bash
# Terminal 4: Test rsync through the forwarded port
rsync -avz rsync://localhost:8873/files/ /tmp/dest/

# Check destination
cat /tmp/dest/test.txt
```

### Two-Machine Deployment

#### Remote Machine (Source)

```bash
# Install rsync
sudo apt install rsync

# Start rsync daemon in service mode (for automation)
cat > rsyncd.conf << 'EOF'
[files]
path = /home/user/backup
comment = Remote backup directory
read only = false
use chroot = false
EOF

cat > /tmp/rsyncd.service << 'EOF'
[Unit]
Description=rsync daemon for ToxTunnel

[Service]
ExecStart=/usr/bin/rsync --daemon --config=/tmp/rsyncd.conf
ExecStop=/bin/kill -TERM $MAINPID
KillMode=process
EOF

# Start rsync daemon
rsync --daemon --config=/tmp/rsyncd.conf
```

#### Local Machine (Destination)

```yaml
# rsync_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

logging:
  level: info

client:
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 8873
      remote_host: 127.0.0.1
      remote_port: 873      # rsync port
```

```bash
# Start client
./build/toxtunnel -c rsync_client.yaml

# Sync files from remote
rsync -avz rsync://localhost:8873/files/ /local/backup/

# With SSH-style syntax instead of an rsync daemon
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"
rsync -avz -e "ssh -o ProxyCommand=\"./build/toxtunnel -m client --server-id ${SERVER_ID} --pipe 127.0.0.1:22\"" \
    user@dummy:/remote/path/ /local/destination/
```

### Automated Backups

Create a systemd service for automated backups:

```bash
# /etc/systemd/system/tox-backup.service
[Unit]
Description=ToxTunnel backup service
After=network.target

[Service]
Type=oneshot
User=backup
ExecStart=/usr/bin/rsync -avz rsync://localhost:8873/files/ /mnt/backups/
```

```bash
# Enable and run
sudo systemctl daemon-reload
sudo systemctl start tox-backup
```

---

## Remote Desktop (RDP/VNC)

Access remote desktops securely through ToxTunnel.

### Single-Machine Testing

Test VNC tunneling locally before deploying to two separate machines.

```bash
# Terminal 1: Install and start VNC server (Linux/macOS)
# Linux
sudo apt install tigervnc-standalone-server
vncpasswd
vncserver :1 -geometry 1920x1080 -depth 24

# macOS (use built-in Screen Sharing or install TigerVNC)
# brew install tigervnc
# System Preferences > Sharing > Screen Sharing > Enable

# Terminal 2: Start ToxTunnel server
./build/toxtunnel -m server -d /tmp/toxtunnel-server
```

Copy the server's Tox address.

```bash
# Terminal 3: Start ToxTunnel client
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"

cat > /tmp/toxtunnel-vnc-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 5901
      remote_host: 127.0.0.1
      remote_port: 5901
EOF

./build/toxtunnel -c /tmp/toxtunnel-vnc-client.yaml

# Terminal 4: Connect to VNC through tunnel
vncviewer localhost:1
# Or with TigerVNC
vncviewer localhost:5901
```

### RDP (Windows Remote Desktop)

#### Remote Machine (Windows Server/Desktop)

```bash
# Enable Remote Desktop
# Settings > System > Remote Desktop > Enable
```

#### Local Machine

```yaml
# rdp_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_WINDOWS_MACHINE_TOX_ADDRESS"

  forwards:
    - local_port: 3389
      remote_host: 127.0.0.1
      remote_port: 3389      # RDP port
```

```bash
# Start ToxTunnel client
./build/toxtunnel -c rdp_client.yaml

# Connect using Remote Desktop Client
# Windows: mstsc
# macOS: Microsoft Remote Desktop app
# Linux: Remmina, FreeRDP

# With FreeRDP
xfreerdp /v:localhost:3389 /u:username /p:password
```

### VNC (Linux Remote Desktop)

#### Remote Machine (Linux)

```bash
# Install VNC server
sudo apt install tigervnc-standalone-server

# Set up password
vncpasswd

# Start VNC server (choose a desktop, e.g., :1 for GNOME)
vncserver :1 -geometry 1920x1080 -depth 24
```

#### Local Machine

```yaml
# vnc_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_LINUX_MACHINE_TOX_ADDRESS"

  forwards:
    - local_port: 5901
      remote_host: 127.0.0.1
      remote_port: 5901      # VNC port for :1
```

```bash
# Start ToxTunnel
./build/toxtunnel -c vnc_client.yaml

# Connect with VNC viewer
# RealVNC, TightVNC, TigerVNC, etc.
vncviewer localhost:1
```

### NoMachine (Alternative Desktop)

```yaml
# nomachine_client.yaml
client:
  server_id: "PASTE_TOX_ADDRESS"

  forwards:
    - local_port: 4000
      remote_host: 127.0.0.1
      remote_port: 4000      # NoMachine default port
```

---

## NAS Access

Access Network Attached Storage (NAS) systems through ToxTunnel.

### Single-Machine Testing

Test NAS-like file sharing locally using a simple HTTP file server.

```bash
# Terminal 1: Create a test directory and start a file server
mkdir -p /tmp/nas-share
echo "Test file from NAS" > /tmp/nas-share/readme.txt
echo "Another file" > /tmp/nas-share/data.txt

# Start a simple HTTP file server
python3 -m http.server 8080 --directory /tmp/nas-share

# Terminal 2: Start ToxTunnel server
./build/toxtunnel -m server -d /tmp/toxtunnel-server
```

Copy the server's Tox address.

```bash
# Terminal 3: Start ToxTunnel client
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"

cat > /tmp/toxtunnel-nas-http-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 8888
      remote_host: 127.0.0.1
      remote_port: 8080
EOF

./build/toxtunnel -c /tmp/toxtunnel-nas-http-client.yaml

# Terminal 4: Access the NAS through tunnel
curl http://localhost:8888/
curl http://localhost:8888/readme.txt

# Or open in browser
open http://localhost:8888
```

For SSHFS-based testing:

```bash
# Terminal 1: Ensure SSH server is running
# Linux: sudo systemctl start ssh
# macOS: System Preferences > Sharing > Remote Login > Enable

./build/toxtunnel -m server -d /tmp/toxtunnel-server

# Terminal 2: Start client (after getting server Tox ID)
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"
cat > /tmp/toxtunnel-nas-ssh-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22
EOF

./build/toxtunnel -c /tmp/toxtunnel-nas-ssh-client.yaml

# Terminal 3: Mount via SSHFS
mkdir -p /tmp/nas-mount
sshfs -p 2222 $USER@localhost:/tmp/nas-share /tmp/nas-mount
ls /tmp/nas-mount

# Unmount when done
# Linux: fusermount -u /tmp/nas-mount
# macOS: umount /tmp/nas-mount
```

### Web Interface Access

Most NAS systems provide web interfaces:

```yaml
# nas_web_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_NAS_TOX_ADDRESS"

  forwards:
    # Synology/TrueNAS web interface
    - local_port: 5000
      remote_host: 127.0.0.1
      remote_port: 5000

    # SMB/CIFS file shares
    - local_port: 1445
      remote_host: 127.0.0.1
      remote_port: 445
```

### File System Mounts

#### Mount SMB/CIFS Share

```bash
# Create mount directory
sudo mkdir -p /mnt/nas-share

# Mount through tunnel
sudo mount -t cifs \
    //localhost/share \
    /mnt/nas-share \
    -o username=youruser,password=yourpass,domain=WORKGROUP,vers=3.0,port=1445
```

#### SSHFS Mount (SSH enabled NAS)

```yaml
# nas_ssh_client.yaml
client:
  server_id: "PASTE_NAS_TOX_ADDRESS"

  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22      # SSH port
```

```bash
# Install sshfs
sudo apt install sshfs

# Mount
mkdir ~/nas-drive
sshfs -o port=2222 \
    user@localhost:/remote/path \
    ~/nas-drive \
    -o allow_other
```

#### Synology NAS Specific

```yaml
# synology_client.yaml
client:
  server_id: "PASTE_SYNOLOGY_TOX_ADDRESS"

  forwards:
    - local_port: 5000
      remote_host: 127.0.0.1
      remote_port: 5000      # DSM web interface
    - local_port: 5001
      remote_host: 127.0.0.1
      remote_port: 5001      # DSM HTTPS
    - local_port: 1445
      remote_host: 127.0.0.1
      remote_port: 445       # SMB
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22        # SSH
```

```bash
# Open DSM in your browser
# http://localhost:5000

# Or mount the SMB share through the forwarded SMB port
sudo mount -t cifs //localhost/share /mnt/nas \
    -o username=admin,password=mypass,port=1445
```

### Cloud Storage Tunneling

Mount cloud storage with local tunnel access:

```yaml
# cloud_tunnel.yaml
client:
  server_id: "PASTE_SERVER_TOX_ADDRESS"

  forwards:
    # S3 proxy port
    - local_port: 9000
      remote_host: 127.0.0.1
      remote_port: 9000
```

```bash
# On remote server: Start rclone with local mount
rclone mount s3:my-bucket /mnt/cloud \
    --vfs-cache-mode full \
    --addr 127.0.0.1:9000

# On local: Access through tunnel
ls /mnt/cloud
```

---

## Custom Services

### Minecraft Server

```yaml
# minecraft_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_MINECRAFT_HOST_TOX_ADDRESS"

  forwards:
    - local_port: 25565
      remote_host: 127.0.0.1
      remote_port: 25565      # Minecraft default
    - local_port: 25575
      remote_host: 127.0.0.1
      remote_port: 25575      # RCON port
```

```bash
# Connect to Minecraft server
# Start client
./build/toxtunnel -c minecraft_client.yaml

# Connect game client to localhost:25565
```

### Game Servers (Various)

```yaml
# game_servers.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_GAME_HOST_TOX_ADDRESS"

  forwards:
    # Counter-Strike
    - local_port: 27015
      remote_host: 127.0.0.1
      remote_port: 27015

    # Garry's Mod
    - local_port: 27015
      remote_host: 127.0.0.1
      remote_port: 27015

    # SteamCMD Master Server Query Port
    - local_port: 27020
      remote_host: 127.0.0.1
      remote_port: 27020
```

### Docker Remote API

```yaml
# docker_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_DOCKER_HOST_TOX_ADDRESS"

  forwards:
    - local_port: 2375
      remote_host: 127.0.0.1
      remote_port: 2375      # Docker HTTP API
```

```bash
# Start client
./build/toxtunnel -c docker_client.yaml

# Use Docker through tunnel
docker -H tcp://localhost:2375 ps
```

### Kubernetes API Server

```yaml
# k8s_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_K8S_MASTER_TOX_ADDRESS"

  forwards:
    - local_port: 6443
      remote_host: 127.0.0.1
      remote_port: 6443      # Kubernetes API server
```

```bash
# Configure kubectl
kubectl config set-cluster remote-k8s \
    --server=https://localhost:6443 \
    --insecure-skip-tls-verify
```

---

## SOCKS5 / HTTP CONNECT Proxy

Run the client as a SOCKS5 v5 + HTTP CONNECT listener so a browser (or any
proxy-aware tool) can dial arbitrary destinations through the tunnel without
the operator pre-registering each target in `forwards:`. Authorisation stays
on the server via `rules.yaml`.

```yaml
# socks5_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  server_id: "PASTE_REMOTE_SERVER_TOX_ADDRESS"
  socks5:
    enabled: true
    listen: "127.0.0.1:1080"
```

```bash
./build/toxtunnel -c socks5_client.yaml
# or, equivalently:
./build/toxtunnel -m client --server-id <id-or-alias> --socks5 127.0.0.1:1080

# Browse anything the server's rules allow:
curl --socks5 127.0.0.1:1080 https://internal.example.com/
firefox --new-instance --no-remote # then set SOCKS5 host=127.0.0.1 port=1080

# Same listener accepts plain HTTP CONNECT:
curl --proxy http://127.0.0.1:1080 https://internal.example.com/
```

The server's `rules.yaml` is the single source of truth for which destinations
the SOCKS5 client may reach. The listener supports `CONNECT` only —
`BIND` and `UDP ASSOCIATE` requests are rejected with SOCKS5 reply code `0x07`,
and unauthenticated proxy auth is the only mode (bind to loopback).

---

## Scraping Prometheus Metrics

Wire ToxTunnel's `/metrics` endpoint into the rest of your observability
stack. See [`docs/CONFIGURATION.md`](CONFIGURATION.md) ("Prometheus Metrics
(`metrics:`)") for the config block and
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md) ("Operational Endpoints →
`/metrics` HTTP") for the full series catalogue.

### Server (or client) config

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9105"   # loopback-only — fronted by node_exporter / reverse proxy
```

Reload semantics: `metrics.*` is **not** SIGHUP-reloadable. A restart is
required to flip the listener on or change its bind.

### Quick sanity check

```bash
curl -s http://127.0.0.1:9105/metrics | head
# # HELP toxtunnel_tunnels_open Tunnels currently in OPEN state
# # TYPE toxtunnel_tunnels_open gauge
# toxtunnel_tunnels_open 4
# # HELP toxtunnel_bytes_in_total Bytes received per direction
# ...
```

### Prometheus scrape job

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: toxtunnel
    scrape_interval: 15s
    static_configs:
      - targets:
          - homelab.internal:9105
          - dmz.internal:9105
        labels:
          service: toxtunnel
```

Run Prometheus itself behind ToxTunnel if the daemon's `metrics.listen` is
loopback-only — add a `forwards:` mapping on the scraper host pointing at
`127.0.0.1:9105` on each target.

### Alertmanager rule examples

```yaml
# alerts.yml
groups:
  - name: toxtunnel
    rules:
      - alert: ToxTunnelNoFriendsOnline
        expr: toxtunnel_active_friends == 0
        for: 5m
        labels: { severity: page }
        annotations:
          summary: "ToxTunnel has zero peers online for 5m"

      - alert: ToxTunnelReloadsRejected
        expr: increase(toxtunnel_reloads_total{result="rejected"}[15m]) > 0
        labels: { severity: warn }
        annotations:
          summary: "A SIGHUP / reload attempt was rejected — non-reloadable field changed"

      - alert: ToxTunnelFailoverStorm
        expr: increase(toxtunnel_failover_switchovers_total[10m]) > 3
        labels: { severity: page }
        annotations:
          summary: "Active-server switchovers exceeded 3 in 10m — primary is flapping"
```

### Grafana

Import a panel keyed off the series above. A minimal dashboard usually
includes: tunnels open (gauge), bytes_in / bytes_out (rate), tunnels_closed by
reason (stacked counter), reloads (annotation), and `tox_self_connection_status`
(state-timeline).

---

## Live Tunnel Inspection During Incidents

`toxtunnel inspect` talks to the local-only `InspectServer` IPC (default-on,
no remote attack surface — see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
"Operational Endpoints → `toxtunnel inspect` IPC"). Use it when something is
wrong on a running daemon and you need ground truth without restarting.

### Interactive triage

```bash
# Who am I and how long have I been up?
toxtunnel inspect status

# What tunnels are alive right now?
toxtunnel inspect tunnels

# Which friends does the daemon see online?
toxtunnel inspect friends

# Snapshot of every metrics counter (same numbers /metrics serves,
# even when metrics.enabled = false).
toxtunnel inspect metrics
```

The CLI pretty-prints by default. Pass `--json` for raw IPC output suitable
for `jq` / scripts:

```bash
toxtunnel inspect tunnels --json \
  | jq '.tunnels[] | select(.idle_seconds > 60)'
```

### Scripted health probes

Because every reply is one JSON line on a Unix-domain socket, you can shell
out from anywhere on the same host without depending on the metrics endpoint:

```bash
# Fail the systemd unit's ExecStartPost if no peers are online after boot.
SOCK=/var/lib/toxtunnel/inspect.sock
status=$(printf '{"cmd":"status"}\n' \
  | socat - UNIX-CONNECT:$SOCK \
  | jq -r '.tunnels_open')
[ "${status:-0}" -gt 0 ] || exit 1
```

### When inspect is your only option

- The daemon is running but `/metrics` is disabled.
- You suspect a thread is stuck — `toxtunnel inspect status` will still answer
  because the IPC accept loop runs on the I/O pool, not the Tox thread.
- You need a snapshot at the exact moment a tunnel hangs, before SIGHUP /
  restart loses the state.

If `toxtunnel inspect` itself hangs, the I/O pool is wedged; capture a core
dump (`gcore` / minidump) before restarting.

---

## Hot-Reloading rules.yaml Without Dropping Connections

The reloadable subset is intentionally tiny — see
[`docs/CONFIGURATION.md`](CONFIGURATION.md) ("Hot Reload (`SIGHUP` / reload
pipe)"). For `rules.yaml` specifically: edit the file, signal the daemon, and
existing tunnels that are still allowed by the new rules **stay open**. Only
tunnels that the new rules now deny are closed.

### Workflow (POSIX)

```bash
# 1. Edit the rules file in place.
sudoedit /etc/toxtunnel/rules.yaml

# 2. Signal the running server.
sudo systemctl reload toxtunnel        # preferred — wraps SIGHUP
# or:
sudo kill -HUP $(pidof toxtunnel)

# 3. Confirm in the logs.
sudo journalctl -u toxtunnel -n 5 --no-pager | grep -i reload
# Reload applied: rules_file=/etc/toxtunnel/rules.yaml (3 allow, 1 deny)

# 4. Confirm via the metrics counter (if metrics.enabled).
curl -s http://127.0.0.1:9105/metrics | grep toxtunnel_reloads_total
# toxtunnel_reloads_total{result="success"} 7
# toxtunnel_reloads_total{result="rejected"} 0
```

If you accidentally edit a non-reloadable field — say you bump `tox.tcp_port`
in the same checkpoint — the reload is rejected as a whole:

```
Reload rejected: field tox.tcp_port is not reloadable
```

The running daemon's config is untouched; revert the offending change, signal
again, and you're back in business.

### Workflow (Windows)

```powershell
# 1. Edit the rules file.
notepad C:\ProgramData\toxtunnel\rules.yaml

# 2. Trigger the reload over the named pipe.
toxtunnel reload                       # talks to \\.\pipe\toxtunnel-reload-<pid>

# 3. Inspect the running state.
toxtunnel inspect status
```

### What the daemon does internally

`ConfigReload::apply()` parses the new file, diffs against the live `Config`,
and either swaps just the reloadable subset under each consumer's strand or
rejects the whole reload. See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
("Operational Endpoints → SIGHUP / reload pipe") for the full flow.

### Recommended workflow for sensitive rule changes

```bash
# Stage the new file alongside, validate it without applying.
sudo cp /etc/toxtunnel/rules.yaml /etc/toxtunnel/rules.yaml.next
sudoedit /etc/toxtunnel/rules.yaml.next
toxtunnel config check --rules /etc/toxtunnel/rules.yaml.next

# Atomically move it into place, then signal.
sudo mv /etc/toxtunnel/rules.yaml.next /etc/toxtunnel/rules.yaml
sudo systemctl reload toxtunnel
```

---

## Multi-Server Failover

Production redundancy without an external load balancer. The client maintains
a list of servers, prefers the primary, and falls over automatically. See
[`docs/CONFIGURATION.md`](CONFIGURATION.md) ("Multi-Server Failover") for the
full field reference.

### Pattern: primary + one hot spare

```yaml
# /etc/toxtunnel/client.yaml
mode: client
data_dir: /var/lib/toxtunnel

client:
  server_id:
    - homelab-primary        # alias from `toxtunnel servers add`
    - homelab-spare

  failover:
    timeout_seconds: 60                # how long the active server may be
                                        # offline before we promote a fallback
    prefer_primary_grace_seconds: 30   # how long the primary must be back
                                        # online before we switch back

  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22
```

Both servers must export the same set of allowed destinations in their
respective `rules.yaml` — failover doesn't synchronise rules, it only changes
which Tox peer carries the traffic.

### Pattern: primary + two geographic spares

```yaml
client:
  server_id:
    - prod-iad               # us-east-1
    - prod-fra               # eu-central-1 (spare)
    - prod-sin               # ap-southeast-1 (spare-of-spare)
  failover:
    timeout_seconds: 30                 # tighter — multi-region demands fast
                                         # detection
    prefer_primary_grace_seconds: 120   # avoid flapping while iad recovers
```

The client tries `prod-iad` first. If it stays offline for 30s, the client
promotes the lowest-index online fallback (`prod-fra` if it's up, otherwise
`prod-sin`). When `prod-iad` is back online for 120s straight, the client
switches back.

### Verifying failover behaviour

```bash
# Pre-flight: confirm all servers are registered as friends and at least one
# is online.
toxtunnel inspect friends --json | jq '.friends[] | {alias, online}'

# Simulate a primary outage by shutting it down — watch the log line:
sudo systemctl stop toxtunnel@prod-iad   # on the server host

# On the client:
sudo journalctl -u toxtunnel -f | grep -i failover
# Failover: primary 'prod-iad' offline > 30s; promoting 'prod-fra'

# Bring the primary back:
sudo systemctl start toxtunnel@prod-iad
# Failover: primary 'prod-iad' back online for 120s; switching back
```

`toxtunnel_failover_switchovers_total` (counter, exported via `/metrics`)
should increment by 2 across that demo. Wire an Alertmanager rule on
`increase(...)>N over 10m` to detect flapping primaries — see "Scraping
Prometheus Metrics" above.

### Switchover semantics (what your TCP clients see)

When the client promotes a new active server it tears down every tunnel
currently routed through the old endpoint with a local `TUNNEL_CLOSE`. The
TCP listeners stay bound — the next accepted TCP connection rebuilds a fresh
tunnel through the new active server. Existing TCP connections through old
tunnels are closed by the local listener; long-lived protocols (SSH, psql)
need a reconnect, which is the same behaviour as any L4 failover.

---

## Multi-hop Tunneling

Chain multiple ToxTunnel instances for complex network setups.

### Scenario: Public Network → Private Network → Final Host

```
(Your PC) --> (Gateway VM) --> (Internal Server)
  |              |              |
ToxTunnel      ToxTunnel      ToxTunnel
  |              |              |
public IP     private IP      private IP
```

#### Configuration

1. **Gateway VM (middle hop)**

```yaml
# gateway_server.yaml
mode: server
data_dir: /var/lib/toxtunnel-gateway

server: {}
```

```yaml
# gateway_client.yaml
mode: client
data_dir: /var/lib/toxtunnel-gateway

client:
  # Connect to public Tox peer
  server_id: "PASTE_PUBLIC_TOX_ADDRESS"

  forwards:
    # Forward to internal server
    - local_port: 8080
      remote_host: 10.0.0.100
      remote_port: 80
```

2. **Your PC (entry point)**

```yaml
# my_pc_client.yaml
mode: client
data_dir: ~/.config/toxtunnel

client:
  # Connect to gateway
  server_id: "GATEWAY_TOX_ADDRESS"

  forwards:
    - local_port: 9090
      remote_host: 127.0.0.1
      remote_port: 8080      # Port from gateway config
```

3. **Usage**

```bash
# Final access
curl http://localhost:9090
```

### Dynamic Multi-hop Script

```bash
#!/bin/bash
# multi_hop_tunnel.sh

GATEWAY_ID="$1"
SERVER_PORT="$2"
LOCAL_PORT="$3"

# Start ToxTunnel connecting through gateway
TMP_CONFIG="/tmp/toxtunnel-multihop-${LOCAL_PORT}.yaml"
cat > "$TMP_CONFIG" <<EOF
mode: client
data_dir: /tmp/toxtunnel-multihop

client:
  server_id: "${GATEWAY_ID}"
  forwards:
    - local_port: ${LOCAL_PORT}
      remote_host: 127.0.0.1
      remote_port: ${SERVER_PORT}
EOF

./build/toxtunnel -c "$TMP_CONFIG" &

# Wait for connection
sleep 5

# Connect to the final service
echo "Access at: http://localhost:$LOCAL_PORT"
```

---

## High Availability

### Load Balancing Multiple Servers

```yaml
# load_balancer_config.yaml
mode: server
data_dir: /var/lib/toxtunnel-lb

tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: auto
  bootstrap_nodes:
    - address: tox1.example.com
      port: 33445
      public_key: "KEY1"
    - address: tox2.example.com
      port: 33445
      public_key: "KEY2"

server: {}
```

### Failover Configuration

```bash
#!/bin/bash
# toxtunnel_failover.sh

PRIMARY="PRIMARY_TOX_ID"
BACKUP="BACKUP_TOX_ID"

start_tunnel() {
    local server_id="$1"
    local local_port="$2"
    local config_path="$3"

    cat > "$config_path" <<EOF
mode: client
data_dir: /tmp/toxtunnel-ha

client:
  server_id: "${server_id}"
  forwards:
    - local_port: ${local_port}
      remote_host: 127.0.0.1
      remote_port: 80
EOF

    ./build/toxtunnel -c "$config_path" &
}

# Start primary tunnel
start_primary() {
    start_tunnel "$PRIMARY" 8080 /tmp/toxtunnel-primary.yaml
}

# Start backup tunnel
start_backup() {
    start_tunnel "$BACKUP" 8081 /tmp/toxtunnel-backup.yaml
}

# Health check
check_health() {
    if curl -s http://localhost:8080/health > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Main logic
start_primary
start_backup

while true; do
    if ! check_health; then
        echo "Primary failed, switching to backup..."
        pkill -f "/tmp/toxtunnel-primary.yaml"
        start_primary
    fi
    sleep 10
done
```

---

## Service Integration

### Service Discovery

```python
# service_discovery.py
import json
import requests

class ToxServiceRegistry:
    def __init__(self, registry_url):
        self.registry_url = registry_url

    def register_service(self, service_name, tox_id, port):
        data = {
            "name": service_name,
            "tox_id": tox_id,
            "port": port,
            "timestamp": time.time()
        }
        requests.post(f"{self.registry_url}/services", json=data)

    def get_service(self, service_name):
        response = requests.get(f"{self.registry_url}/services/{service_name}")
        return response.json()

# Usage
registry = ToxServiceRegistry("http://registry:5000")
registry.register_service("web", "USER_TOX_ID", 8080)
service = registry.get_service("web")
```

### API Gateway Pattern

```python
# api_gateway.py
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

# Map service names to Tox IDs
SERVICE_MAP = {
    "auth": "AUTH_TOX_ID",
    "users": "USERS_TOX_ID",
    "orders": "ORDERS_TOX_ID"
}

@app.route('/<service_name>/')
def proxy_to_service(service_name):
    if service_name not in SERVICE_MAP:
        return jsonify({"error": "Service not found"}), 404

    tox_id = SERVICE_MAP[service_name]
    target_port = 80  # Assuming all services on port 80

    # Forward request through ToxTunnel
    cmd = [
        "./build/toxtunnel",
        "-m", "client",
        "--server-id", tox_id,
        "--pipe", f"127.0.0.1:{target_port}"
    ]

    # Execute the command and stream response
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Forward request body
    request_body = request.get_data()
    process.communicate(input=request_body)

    # Process response
    response_data = process.stdout.read()
    return response_data, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

### Monitoring and Logging

```python
# tunnel_monitor.py
import psutil
import logging
from datetime import datetime

class TunnelMonitor:
    def __init__(self):
        self.logger = logging.getLogger('tunnel_monitor')
        logging.basicConfig(level=logging.INFO)

    def check_tunnels(self):
        tunnels = []

        # Check running ToxTunnel processes
        for proc in psutil.process_iter(['name', 'cmdline']):
            if proc.info['name'] == 'toxtunnel':
                cmdline = proc.info['cmdline']
                if len(cmdline) > 1:
                    tunnels.append({
                        'pid': proc.pid,
                        'cmdline': cmdline,
                        'memory': proc.memory_info().rss,
                        'cpu': proc.cpu_percent()
                    })

        # Log tunnel status
        for tunnel in tunnels:
            self.logger.info(f"PID {tunnel['pid']}: {' '.join(tunnel['cmdline'][2:])}")
            self.logger.info(f"Memory: {tunnel['memory'] / 1024 / 1024:.1f}MB")
            self.logger.info(f"CPU: {tunnel['cpu']}%")

        return tunnels

    def check_connectivity(self, service_configs):
        for service in service_configs:
            try:
                # Check if service is accessible through tunnel
                result = subprocess.run([
                    'curl', '-s', f'http://localhost:{service["local_port"]}'
                ], timeout=5, capture_output=True)

                if result.returncode == 0:
                    self.logger.info(f"Service {service['name']} is UP")
                else:
                    self.logger.warning(f"Service {service['name']} is DOWN")
            except Exception as e:
                self.logger.error(f"Service {service['name']} error: {e}")

# Usage
monitor = TunnelMonitor()
tunnels = monitor.check_tunnels()
monitor.check_connectivity([
    {'name': 'web', 'local_port': 8080},
    {'name': 'api', 'local_port': 8081}
])
```

### Kubernetes Integration

```yaml
# k8s-tox-tunnel-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: toxtunnel-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: toxtunnel-proxy
  template:
    metadata:
      labels:
        app: toxtunnel-proxy
    spec:
      containers:
      - name: toxtunnel
        image: toxtunnel:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          cat > /tmp/toxtunnel-client.yaml <<EOF
          mode: client
          data_dir: /tmp/toxtunnel

          client:
            server_id: "$(cat /etc/tox/id)"
            forwards:
              - local_port: 8080
                remote_host: 127.0.0.1
                remote_port: 80
          EOF
          while true; do
            ./toxtunnel -c /tmp/toxtunnel-client.yaml
            sleep 10
          done
        volumeMounts:
        - name: tox-id
          mountPath: /etc/tox
      volumes:
      - name: tox-id
        secret:
          secretName: tox-identity
```

---

## Best Practices for Advanced Scenarios

1. **Always use dedicated ports**: Avoid port conflicts by planning your port mapping
2. **Monitor resource usage**: Multiple tunnels can consume significant CPU/network
3. **Implement health checks**: Verify tunnel connectivity regularly
4. **Use service discovery**: For dynamic environments with changing endpoints
5. **Secure sensitive services**: Apply additional encryption/authorization as needed
6. **Test failover scenarios**: Ensure redundancy works in practice
7. **Document configurations**: Especially for multi-hop and HA setups
8. **Regular maintenance**: Keep ToxTunnel updated for security patches
