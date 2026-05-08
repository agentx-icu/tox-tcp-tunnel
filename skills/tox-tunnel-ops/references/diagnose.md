# Diagnose Reference

Use this reference when an existing tunnel does not work and you need a layered,
evidence-driven troubleshooting flow.

## Diagnostic Layers

Run through these layers in order. Stop at the first failure and propose a fix.

### Layer 1: Process & Binary

- Is `toxtunnel` installed? (`which toxtunnel`)
- Is it running? (`ps aux | grep toxtunnel` / `Get-Process toxtunnel`)
- Which config file is it using? What mode?
- What version?

### Layer 2: Configuration Static Check

- Is the YAML syntactically valid?
- Is `mode` set correctly?
- Does `data_dir` exist and is it writable?
- Does `tox_save.dat` exist? (first run creates it)
- Client-specific:
  - Is `server_id` set and exactly 76 characters?
  - Is `server_id` not the placeholder `<PASTE_SERVER_TOX_ID_HERE>`?
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
