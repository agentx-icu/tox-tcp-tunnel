# HTTP Tunneling

This guide covers using ToxTunnel to access HTTP/HTTPS services through the Tox P2P network.

## Table of Contents

1. [Single-Machine Testing](#single-machine-testing)
2. [Two-Machine Deployment](#two-machine-deployment)
3. [HTTP Proxy Scenario](#http-proxy-scenario)
4. [Web Server Access](#web-server-access)
5. [HTTPS Considerations](#https-considerations)
6. [Troubleshooting](#troubleshooting)

---

## Single-Machine Testing

Test HTTP tunneling locally before deploying to two separate machines.

### Setup

First, create a simple HTTP server for testing:

```bash
# Terminal 1: Start a test HTTP server
python3 -m http.server 8888 --directory /tmp
```

Or using Node.js:

```bash
npx http-server -p 8888 /tmp
```

### Start ToxTunnel Server

```bash
# Terminal 2: Start server
./build/toxtunnel -m server -d /tmp/toxtunnel-server
```

Copy the server's Tox address from the output (76 hex characters).

### Start ToxTunnel Client

```bash
# Terminal 3: Start client (replace with server's Tox address)
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"

cat > /tmp/toxtunnel-http-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 8080
      remote_host: 127.0.0.1
      remote_port: 8888
EOF

./build/toxtunnel -c /tmp/toxtunnel-http-client.yaml
```

### Test HTTP Access

```bash
# Terminal 4: Access the HTTP server through the tunnel
curl http://localhost:8080

# Test with a specific file
echo "Hello from ToxTunnel!" > /tmp/test.html
curl http://localhost:8080/test.html

# View HTTP headers
curl -I http://localhost:8080
```

Expected output:
```
Hello from ToxTunnel!
```

---

## Two-Machine Deployment

Access a web service running on a remote machine through ToxTunnel.

### Scenario: Remote Web Server Access

You have a web server running on a remote machine (e.g., an internal admin panel, development server, or IoT device).

#### Machine A (Remote - Running Web Server)

The machine hosting the HTTP service you want to access.

1. **Ensure your web server is running**

```bash
# Example: Start a simple Python HTTP server
python3 -m http.server 8888

# Or verify your existing server
netstat -tlnp | grep 8888
```

2. **Start ToxTunnel Server**

```bash
./build/toxtunnel -m server -d /var/lib/toxtunnel
```

3. **Copy the Tox address**

Save the 76-character Tox address displayed on startup.

#### Machine B (Local - Your Computer)

The machine from which you want to access the remote service.

1. **Create client config file** `web_client.yaml`:

```yaml
mode: client
data_dir: ~/.config/toxtunnel

logging:
  level: info

client:
  # Paste the server's Tox address here
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 8080      # Local port to listen on
      remote_host: 127.0.0.1  # Where the web server runs on remote machine
      remote_port: 8888      # Port the web server listens on
```

2. **Start the client**

```bash
./build/toxtunnel -c web_client.yaml
```

Wait for the connection message:
```
Server friend 0 is now online
Listening on local port 8080 -> 127.0.0.1:8888
```

3. **Access the remote web server**

```bash
# In a browser or with curl
curl http://localhost:8080

# Or open in browser: http://localhost:8080
```

### Scenario: Multiple Web Services

Forward multiple web services from one remote machine:

```yaml
# Config on local machine
client:
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 8080
      remote_host: 127.0.0.1
      remote_port: 8080      # Main web app

    - local_port: 3000
      remote_host: 127.0.0.1
      remote_port: 3000      # Development server

    - local_port: 9000
      remote_host: 192.168.1.100
      remote_port: 80       # Web server on remote LAN
```

---

## HTTP Proxy Scenario

Use ToxTunnel as an HTTP proxy to route web traffic through a remote machine.

### Setup on Remote Machine

```bash
# Install an HTTP proxy (e.g., tinyproxy)
sudo apt install tinyproxy  # Ubuntu/Debian
# or
brew install tinyproxy      # macOS

# Configure tinyproxy to listen on localhost only
echo "Listen 127.0.0.1 8888" | sudo tee -a /etc/tinyproxy/tinyproxy.conf
sudo systemctl restart tinyproxy
```

### Forward the Proxy Port

```yaml
# Config on local machine
client:
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 8888
      remote_host: 127.0.0.1
      remote_port: 8888      # tinyproxy port
```

### Use the Tunnel as Proxy

```bash
# Set HTTP_PROXY environment variable
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888

# Use with curl
curl http://example.com

# Use with specific tools
wget -e "http_proxy=http://localhost:8888" http://example.com
```

---

## Web Server Access

### Access Internal Web Applications

Many applications expose web interfaces for management:

| Application | Typical Port | Description |
|------------|-------------|-------------|
| Webmin | 10000 | Linux system administration |
| Cockpit | 9090 | Server management interface |
| Pi-hole | 80 | Network ad blocker admin |
| Home Assistant | 8123 | Home automation |
| Grafana | 3000 | Metrics dashboard |
| Prometheus | 9090 | Metrics collection |
| Portainer | 9443 | Docker management |

**Example: Access Pi-hole Admin**

Remote machine (Raspberry Pi running Pi-hole):

```bash
# Start ToxTunnel server
./build/toxtunnel -m server
```

Local machine:

```yaml
client:
  server_id: "PI_TOX_ADDRESS_HERE"
  forwards:
    - local_port: 8080
      remote_host: 127.0.0.1
      remote_port: 80      # Pi-hole HTTP port
```

```bash
# Start client and access
./build/toxtunnel -c pihole_client.yaml

# Open in browser
open http://localhost:8080/admin
```

---

## HTTPS Considerations

### HTTPS Through ToxTunnel

ToxTunnel forwards raw TCP, which means HTTPS works transparently:

1. The browser establishes an HTTPS connection to `localhost:PORT`
2. ToxTunnel forwards the encrypted TLS traffic to the remote machine
3. The remote server receives and processes the HTTPS request

**Important**: The TLS termination happens at the remote server. ToxTunnel does not inspect or modify HTTPS traffic.

### Certificate Considerations

When accessing HTTPS services through ToxTunnel:

- **localhost**: Use `http://localhost:PORT` for the tunnel itself
- **The browser**: Sees the remote server's SSL certificate
- **Certificate errors**: May occur if accessing by IP or different hostname

### Browser Configuration

To avoid certificate errors, you can:

1. **Use the same hostname**

Edit `/etc/hosts` on the local machine:

```
127.0.0.1    remote-server.example.com
```

Then access via:
```
https://remote-server.example.com:PORT
```

2. **Accept self-signed certificates** (for testing only)

```bash
curl -k https://localhost:PORT
```

---

## Troubleshooting

### Connection Refused

**Symptom**: `curl: (7) Failed to connect to localhost port XXXX`

**Solutions**:
1. Verify the ToxTunnel client is running
2. Check the local port is correct in config
3. Ensure the Tox connection is established (look for "Server friend X is now online")

### Slow Performance

**Symptom**: HTTP requests take a long time

**Solutions**:
1. Check your internet connection on both machines
2. Try different bootstrap nodes
3. Reduce the MTU if on a slow connection
4. Consider using compression for large transfers

### Connection Drops

**Symptom**: Connections reset after some time

**Solutions**:
1. Configure keep-alive settings
2. Check for firewall restrictions
3. Verify both ToxTunnel instances stay running
4. Enable debug logging to investigate

### Port Already in Use

**Symptom**: `Failed to bind to local port XXXX`

**Solutions**:
1. Choose a different local port
2. Stop the conflicting service
3. Check what's using the port: `lsof -i :XXXX`

---

## Best Practices

1. **Use dedicated ports**: Keep local ports organized (e.g., 8080 for HTTP, 8443 for HTTPS)

2. **Config file for permanence**: Use YAML configs instead of CLI flags for regular use

3. **Auto-start**: Set up ToxTunnel as a system service (systemd/launchd) for always-on tunnels

4. **Access control**: Configure rules on the server to restrict access

5. **Monitoring**: Enable logging to track connection activity

---

## Advanced: Webhook Forwarding

Forward webhooks from the remote machine to your local machine:

Remote machine (exposes webhook endpoint):

```yaml
# Server config
mode: server
```

Local machine (receives webhooks):

```yaml
# Client config - reverse forward!
client:
  server_id: "REMOTE_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 8080
      remote_host: 127.0.0.1
      remote_port: 8080      # Local webhook receiver
```

This creates a bidirectional tunnel allowing webhooks from the remote machine to reach your local development server.
