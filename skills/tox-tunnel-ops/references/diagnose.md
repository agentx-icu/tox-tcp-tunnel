# Diagnose Reference

Use this reference when an existing tunnel does not work and you need a layered,
evidence-driven troubleshooting flow.

## Diagnostic Layers

Run through these layers in order. Stop at the first failure and propose a fix.

### Layer 1: Process & Binary

- Is `toxtunnel` installed? (`which toxtunnel`)
- Is it running? (`ps aux | grep toxtunnel` / `Get-Process toxtunnel`)
- Which config file is it using? What mode?
- What version? (≥ v0.3.0 unlocks the inspect/reload/metrics short-circuits below)

**Prefer `inspect` over log tailing for live state.** If the daemon is up
and v0.3.0+, this single command answers Layers 1, 4, and 5 in one shot:

```bash
toxtunnel inspect status --json | jq .
toxtunnel inspect tunnels
```

Look for: `pid`, `version`, `mode`, `friends_online`, `active_server` (client),
`tunnels_active`. Empty / missing fields point at the failing layer.

### Layer 2: Configuration Static Check

- Is the YAML syntactically valid?
- Is `mode` set correctly?
- Does `data_dir` exist and is it writable?
- Does `tox_save.dat` exist? (first run creates it)
- Client-specific:
  - Is `server_id` set?
  - Is `server_id` not the placeholder `<PASTE_SERVER_TOX_ID_HERE>`?
  - If `server_id` is exactly 76 hex characters → treat as literal Tox ID.
  - If `server_id` is shorter → treat as an alias and check that
    `<data_dir>/known_servers.yaml` exists and contains an entry whose `alias:`
    matches. (`toxtunnel servers list -d <data_dir>` resolves this quickly.)
    A non-76-char `server_id` with no matching alias is a misconfiguration —
    the daemon will fail validation at startup.
  - Are `forwards` entries present with valid port numbers?
- Server-specific:
  - If `rules_file` is set, does the file exist?
  - Is the rules YAML valid?

### Layer 3: Rules Risk Analysis

Parse `rules.yaml` and check for:

- Overly broad allow rules: host `*` with empty ports
- Missing deny coverage: friend rules with only allow, no deny
- Stale friend keys: `friend_pk` entries that do not match known friends
- Port `0` in rules
- Friend key format: must be exactly 64 hex characters

Report risk level: LOW / MEDIUM / HIGH.

### Layer 4: Network & Tox Connection

- Does the machine have internet access? (`ping -c 1 -W 2 1.1.1.1`)
  - If `bootstrap_mode: lan`, internet is not required, but both machines must be on the same subnet
  - If `bootstrap_mode: auto`, internet is required for DHT bootstrap
- Is UDP blocked?
- Is `tox.tcp_port` (default `33445`) available?
- Check logs for:
  - `Connected to DHT`
  - `Self connection status: Online`
  - `Friend connection status: Connected`

### Layer 5: Port & Tunnel Connectivity

- Is the local listening port open? (`lsof -i :PORT -sTCP:LISTEN`)
- Can TCP connect to it? (`nc -z -w 5 127.0.0.1 PORT`)
- Is the target service reachable from the server? (`nc -zv target_host target_port`)
- Check logs for `TUNNEL_OPEN`, `TUNNEL_ERROR`, `TUNNEL_CLOSE`
- `toxtunnel inspect tunnels` shows live tunnels with their target host:port, bytes in/out, and age — if your tunnel never shows up here, the open was denied or never reached the server
- If metrics are enabled, watch `toxtunnel_tunnels_opened_total{result="denied"}` (rules blocked it) vs `result="failed"` (target unreachable from server) vs `result="ok"` (succeeded)

### Layer 6: v0.3.0 Subsystem Diagnostics

These layers only apply when the corresponding feature is enabled.

**Hot-reload didn't apply:**
- Grep the daemon log for `config reloaded` (success) or `reload failed:` / `reload rejected:` (parse / validation error)
- If neither appears, the SIGHUP / pipe message never reached the daemon — check pid resolution (`<data_dir>/toxtunnel.pid` exists?), permissions (can the caller signal the process?), and on Windows that the named pipe `\\.\pipe\toxtunnel-reload-<pid>` exists
- Remember the reloadable set is small: `server.rules_file` contents, `client.forwards`, `logging.level`. Changes to Tox identity / listen ports / mode / `data_dir` will silently NOT take effect on reload — they need a restart

**SOCKS5 listener didn't bind:**
- Check startup log for `Invalid client.socks5.listen value` or `must bind to a loopback address` — the validator rejects non-loopback binds (`0.0.0.0`, LAN IPs)
- Verify the listener is actually enabled: `socks5.enabled: true` in YAML, OR `--socks5 host:port` on the CLI
- SOCKS5 and `client.pipe` are mutually exclusive; the validator emits `socks5.enabled and client.pipe cannot be used together`
- If listener bound but CONNECTs are refused with SOCKS5 reply 0x02 ("connection not allowed"), the server-side `rules.yaml` is denying the target — that's expected; widen the allow list on the server, not the client

**Multi-server failover not switching:**
- Tail the log for `Failover: switching active server X... -> Y... (friend N)` — absence means no switch decision has fired
- Check `client.failover.timeout_seconds` (default 60) — if set too high, the client waits longer than expected before promoting a fallback
- Make sure the fallback servers are in the list (`server_id` must be a YAML sequence, or use `--server-id-fallback` repeated); a single-string `server_id` ignores the failover block
- After fallback promotion, the client waits `prefer_primary_grace_seconds` (default 30) of *continuous* primary uptime before switching back — brief primary flaps reset the grace timer
- `toxtunnel inspect status --json | jq .active_server` shows the currently active server without log diving

**Metrics endpoint missing / wrong values:**
- `curl -s localhost:9100/metrics | head` — if connection refused, `metrics.enabled: false` (the default) or the daemon didn't pick up the config (restart, since metrics listen isn't hot-reloadable)
- Wrong listen address? Check `metrics.listen` matches what Prometheus is scraping
- Path is `/metrics` by default; if a custom path was set, the default URL 404s
- `toxtunnel_friends_online` stuck at 0 → friend connectivity broken (back to Layer 4)
- `toxtunnel_tunnels_opened_total{result="denied"}` climbing → rules.yaml is rejecting opens; cross-reference with `inspect tunnels` to see what's actually getting through

**Idle reaper closed a tunnel unexpectedly:**
- Look for `toxtunnel_tunnels_closed_total{reason="timeout"}` increment or a log line about idle close
- `tunnel.idle_timeout_seconds: 0` disables the reaper entirely; non-zero values reap tunnels idle that long
- If a long-lived but quiet protocol (e.g. SSH session with no traffic) is being reaped, increase `idle_timeout_seconds` or set `0`

### Layer 6: Application Layer Smoke Test

- SSH: check SSH banner via `nc`
- HTTP: `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:PORT/`
- DB: use service-native ping or query commands

## Common Errors Explained

| Error / Symptom | Meaning | Fix |
|-----------------|---------|-----|
| `Connection refused` on local port | Client not running, wrong `local_port`, or port conflict | Check process, config, and `lsof -i :PORT` |
| Friend stays `Offline` | Wrong `server_id`, DHT not connected, or UDP blocked | Verify 76-char Tox ID, wait 30-60s, check internet, try `bootstrap_mode: lan` on same LAN |
| Friend online but tunnel fails | Rules block the target or target service is down | Check `rules.yaml` and test target with `nc -zv host port` |
| `Invalid public key length` | Wrong friend key format in `rules.yaml` | Friend public key must be exactly 64 hex chars, not the full 76-char Tox ID |
| `Rules file not found` | Bad `server.rules_file` path | Use an absolute path and verify permissions |
| Slow transfer speed | Tox TCP relay instead of direct UDP | Check for direct UDP connection in logs and unblock UDP if possible |
| Periodic disconnects | Unstable Tox friend connectivity | Raise log level and check network stability |
| `Failed to bind port` | Port already in use | Find the conflicting process and pick a different local port |
| `Permission denied` on `data_dir` | Wrong ownership or permissions | `chmod 700 data_dir` and fix owner |
| Config parse error | YAML syntax problem | Fix indentation and validate with `python3 -c "import yaml, sys; yaml.safe_load(open(sys.argv[1]))" config.yaml` |
| `client.socks5.listen must bind to a loopback address` | SOCKS5 listener set to non-loopback bind | Change to `127.0.0.1:<port>`, `::1`, or `localhost`; for remote consumers use SSH local-forward over loopback |
| `socks5.enabled and client.pipe cannot be used together` | Both dynamic-destination modes enabled | Pick one — SOCKS5 for dynamic, `pipe` for SSH ProxyCommand |
| `Invalid metrics.listen value` / `metrics.path must start with '/'` | Bad metrics config | Use `host:port` for listen and a path starting with `/` |
| `reload rejected: <reason>` in logs | New config failed parse/validation | Daemon kept old config; fix the YAML and re-trigger reload |
| `reload: no pid file at ...` (Windows) | Daemon not running, or different data_dir | Verify daemon is up; pass `-d` or `-c` so reload looks in the right place |
| SOCKS5 CONNECT returns reply 0x02 | Server-side rules.yaml denied the destination | Add the host/port to the friend's allow list on the **server** (not client) |
| Tunnel reaped while still in use | `tunnel.idle_timeout_seconds` too aggressive for the protocol | Raise the timeout or set `0` (disabled) |

## Output Format

```text
## Diagnosis Result

### Layer [N]: [Layer Name]

### Problem Identified
[Clear description of what's wrong]

### Evidence
[Log lines, command output, or config snippets that confirm the issue]

### Risk Assessment (for rules issues)
[LOW / MEDIUM / HIGH with explanation]

### Fix
[Exact steps to resolve, including commands]

### Verification
[Command to confirm the fix worked]
```

## Helper Scripts

```bash
# Full diagnostic
bash scripts/diagnose.sh /path/to/config.yaml

# Verify a specific port
bash scripts/verify.sh <local_port> [ssh|http|postgres|mysql|redis|mongo|tcp]
```

## v0.4 Stability + Performance Diagnostics

### Symptom: daemon went silent without exiting

Tox-thread watchdog fires when `tox_iterate` stalls past
`watchdog.deadline_seconds`. Check:

1. `journalctl -u toxtunnel | grep tox_thread_wedge` — the FATAL line
   carries `delta_ms` and `last_heartbeat_counter`.
2. `cat <data_dir>/abort_count` — persistent count across restarts.
3. `curl 127.0.0.1:9100/metrics | grep watchdog_aborts` — same value
   as the abort file once metrics scrape resumes.
4. `toxtunnel_tox_iterate_lag_ms` gauge rising over time indicates a
   slow toxcore but not yet a wedge — a useful early warning.

The watchdog calls `std::abort()` precisely because in-process recovery
of a wedged toxcore is unsafe. systemd / launchd / Windows SCM
brings the daemon back.

### Symptom: a friend is denied with "Rate limit exceeded"

Rate limiter rejected the TUNNEL_OPEN. Check:

1. `curl 127.0.0.1:9100/metrics | grep rate_limit_open_rejected_total`
   — global counter.
2. The structured WARN log line carries the friend public key prefix.
3. `toxtunnel inspect status --json` shows per-friend bucket levels
   (when configured).

Loosen `rate_limit_defaults` or add a per-friend override block in
`rules.yaml` and `kill -HUP` to reload.

### Symptom: adaptive coalescing is making bad decisions

The `toxtunnel_coalesce_policy_transitions_total` counter ticks on
every state-machine move. If it climbs fast under steady traffic, the
EWMA is flapping. Workarounds:

1. Pin the mode: `tunnel.coalesce_mode: fixed` to lock to the v0.3.0 cadence.
2. For bulk-only workloads pin `bypass`; for trickle-only pin `batch`.

### Symptom: high BDP link still capped at 256 KiB

`flow_control.mode` defaults to `fixed`. Set `mode: bdp` and the
per-tunnel `BdpFlowControl` will scale the window between
`send_window_min_bytes` and `send_window_max_bytes` based on RTT ×
bandwidth EWMA. Inspect via the
`toxtunnel_tunnel_send_window_bytes` summary.

### Symptom: tunnels die across server restart

v0.4 ships the wire format + state store for tunnel-resume but the
live handshake driver is partial. With `tunnel.resume.enabled: false`
(the default) restarts behave exactly as in v0.3.0. Track the v0.4.1
follow-up at
`docs/plans/2026-05-15-tunnel-resume-protocol-partial.md`.

