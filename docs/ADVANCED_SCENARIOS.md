# Advanced Scenarios

This guide covers advanced use cases for ToxTunnel including remote desktop, file transfer, NAS access, and custom services.

## Table of Contents

1. [Rsync File Transfer](#rsync-file-transfer)
2. [Remote Desktop (RDP/VNC)](#remote-desktop-rdpvnc)
3. [NAS Access](#nas-access)
4. [Custom Services](#custom-services)
5. [Multi-hop Tunneling](#multi-hop-tunneling)
6. [High Availability](#high-availability)
7. [Service Integration](#service-integration)

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
