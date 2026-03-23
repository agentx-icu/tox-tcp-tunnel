# Dev/Test Server Exposure via ToxTunnel

## Scenario

You're running a development server locally (Next.js, Django, Flask, Rails, etc.) and want a teammate or tester to access it from their machine — without deploying to a staging server.

## Topology

```
Tester's Machine (client)             Your Dev Machine (server)
─────────────────────────             ──────────────────────────
Browser → 127.0.0.1:8080             dev server on :3000
        ↓                                    ↑
  toxtunnel client                    toxtunnel server
        ↓                                    ↑
        └──── Tox P2P encrypted tunnel ──────┘
```

## Security Warning

Development servers typically:
- Have no authentication
- Expose debug endpoints, stack traces, and source maps
- May have hot-reload websocket endpoints
- Run with elevated permissions

**Recommendations:**
- Use a specific friend key in rules (not wide open)
- Only keep the tunnel running during the testing session
- Don't expose `.env` or admin routes
- Consider adding basic auth (e.g., nginx proxy) in front of the dev server

## Server Config (your dev machine)

```yaml
mode: server
data_dir: ~/.config/toxtunnel/dev-expose
logging:
  level: info
tox:
  udp_enabled: true
  bootstrap_mode: auto    # or lan if both are in the same office
server:
  rules_file: rules.yaml
```

## Client Config (tester's machine)

```yaml
mode: client
data_dir: ~/.config/toxtunnel/client
logging:
  level: info
tox:
  udp_enabled: true
  bootstrap_mode: auto
client:
  server_id: <PASTE_SERVER_TOX_ID_HERE>
  forwards:
    - local_port: 8080
      remote_host: 127.0.0.1
      remote_port: 3000
```

## Rules (tester's friend key only)

```yaml
rules:
  - friend: "AABBCCDD...tester-64-char-hex-public-key...EEFF"
    allow:
      - host: "127.0.0.1"
        ports: [3000]
```

## Steps

1. Start your dev server as usual: `npm run dev` (or equivalent)
2. Start toxtunnel server: `toxtunnel -m server -c server.yaml`
3. Share your Tox ID with the tester
4. Tester starts client and accesses `http://127.0.0.1:8080`

## LAN Shortcut

If both developers are in the same office:

```yaml
tox:
  bootstrap_mode: lan    # no internet needed, faster connection
```

## Cleanup

When testing is done:
1. Stop the toxtunnel server: `Ctrl+C` or `kill $(pgrep -f "toxtunnel.*server")`
2. Optionally delete the config files and data directory
3. No persistent service to clean up (unless you set one up)

## Multiple Testers

Add each tester as a separate friend rule:

```yaml
rules:
  - friend: "AAAA...64hex..."    # Tester 1
    allow:
      - host: "127.0.0.1"
        ports: [3000]
  - friend: "BBBB...64hex..."    # Tester 2
    allow:
      - host: "127.0.0.1"
        ports: [3000]
```

## Verification

```bash
bash verify.sh 8080 http
```
