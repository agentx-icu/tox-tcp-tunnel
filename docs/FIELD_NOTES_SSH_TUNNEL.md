# Field notes — using ToxTunnel to reach a NAT'd macOS box over SSH

Recorded 2026-08-14 from a real deployment: a Linux VM driving a macOS build
machine that had moved behind NAT. The tunnel itself worked on the first try
(client → server friend link in ~50 s, SSH throughput fine for interactive work
and for streaming multi-megabyte test logs). Everything below is friction that
cost time. Items 1–5 are ordered by how much; 6–8 were appended by later
sessions on the same lane, so the numbering after #5 is chronological rather
than ranked (#8 would sit at the top on cost).

> **Verified against v0.4.9 and updated on 2026-08-18.** Each item carries a
> **Status** line. Everything actionable is now fixed in code: the 2026-08-18
> change implemented #1, #3, #5, #6 and #8 on top of the #4/#7 fixes that already
> shipped in v0.4.9. Only #2 remains as written — it is operational advice with
> nothing to fix in code.

## 1. `print-id` ignores `data_dir` from `--config`

```
$ toxtunnel -c client.yaml print-id
2DF6995D…9E2E            # written to ~/.config/toxtunnel/tox_save.dat

$ toxtunnel -c client.yaml          # same config file
[info] Client Tox ID: 380349DB…E53C   # read from the data_dir in client.yaml
```

`print-id` created and persisted a **second, unrelated identity** in the default
`~/.config/toxtunnel/` while the daemon used the `data_dir` set in the config.

This is a sharp edge because `print-id` exists precisely to obtain the key you
paste into the server's `rules.yaml` allowlist. Following the obvious workflow
(`print-id` → paste → start daemon) produces an allowlist for an identity that
never connects, and the failure mode is silent: the friend link comes up
normally and only tunnel *opens* are refused.

**Suggested fix:** `print-id` should honour `-c/--config` (and `--data-dir`) for
resolution, and — since it is a read-only query — should not create an identity
as a side effect when none exists; print a clear "no identity yet at `<path>`"
instead.

**Status: fixed (2026-08-18).** `print-id` now resolves its data directory the
same way `servers`/`inspect`/`reload` do: `-d/--data-dir` wins, else `-c/--config`
(its own or the global `-c` before the subcommand) reads the config's `data_dir`,
else the platform default (`cli/main.cpp`, via `resolve_servers_data_dir`). So
`toxtunnel -c client.yaml print-id` now prints the *same* identity the daemon
uses. The silent part is gone too: when no identity exists at the resolved dir,
`print-id` writes `No existing Tox identity at <path>; creating a new one.` to
**stderr** (the Tox ID still goes to stdout alone, so piping is unaffected).
Creation is retained deliberately — README documents generating an identity by
pointing `print-id` at a fresh dir — but it now lands in the *correct* dir and is
announced, so the "silent second identity in the wrong dir" trap cannot recur.

## 2. `pkill -f` matches your own shell

Documented here because it bit us twice:

```bash
pkill -f "toxtunnel -c client.yaml"   # also kills the shell running this line
pkill -x toxtunnel                    # correct
```

Any wrapper whose command line contains the pattern (an SSH `bash -c …`, a CI
step, `nohup … &`) is matched too. Worth a line in the docs next to the
"stop the daemon before editing known_servers.yaml" warning that already exists.

## 3. Client started before the server never recovers on its own — and says so unhelpfully

With the client already running and the server started afterwards, incoming TCP
connections were refused for as long as we watched:

```
[warning] TCP connection accepted on port 2222 but server is offline, closing
```

The client had logged `Connecting to server: …` at startup and never retried
loudly enough to notice; restarting the client made the friend link come up in
~50 s. Whether this is a missing retry or just a very long backoff, the log line
is the problem: it reports the *symptom* ("server is offline") without the
*state* — how long since the last connection attempt, whether a retry is
scheduled, what the friend connection status is. A periodic
`still trying to reach server <id>, last attempt Ns ago` at warn level would
have removed the guesswork.

**Status: fixed (2026-08-18).** The client now runs a dedicated connectivity
heartbeat (`schedule_connectivity_log_tick`, every 30 s, `src/app/tunnel_client.cpp`).
While the active server is offline it logs at **warn**: `Still trying to reach
server <id-prefix>...; offline for <N>s (retrying)`. Unlike the failover timer
(which only arms with more than one endpoint), this heartbeat arms unconditionally,
so the single-server "client started before its server" case gets the periodic
signal too. It stays quiet once online. Verified live: a client pointed at an
offline peer logged `Still trying to reach server 0499DFE0...; offline for 32s
(retrying)`.

## 4. Server-side allowlist rejections are invisible to the client

When the allowlist named the wrong key (consequence of #1), the client-side
experience was an immediate `Connection closed by 127.0.0.1 port 2222` with
nothing in the client log explaining why. The server knows exactly why it
refused. Propagating a rejection reason back over the tunnel protocol — even a
coarse `TUNNEL_OPEN_DENIED(reason=not_allowed)` surfaced as a client log line —
would turn a blind bisect into a one-line diagnosis.

**Status (v0.4.9): fixed.** On an allowlist rejection the server now sends a
`TUNNEL_ERROR` frame (code 1) carrying the reason — `"Access denied"` or
`"No matching allow rule (default deny)"` (`src/app/tunnel_server.cpp:821-841`) —
and the client logs it as `Tunnel <n> received TUNNEL_ERROR: code=1, desc='...'`
(`src/tunnel/tunnel.cpp:704`). The blind bisect this note describes is now a
one-line diagnosis in the client log.

## 5. `bootstrap_mode: lan` silently cannot cross networks

The pre-existing server config on the Mac used `bootstrap_mode: lan` from an
earlier same-LAN setup. After the machine moved behind NAT this cannot work, but
nothing says so: the server starts, reports `Connected to Tox DHT`, and simply
never becomes reachable. A startup warning when `lan` is combined with a
non-loopback/non-private peer expectation — or simply logging the effective
bootstrap node list and node count at info — would make the misconfiguration
self-evident.

**Status: fixed (2026-08-18).** In addition to the load-time validation that
`bootstrap_mode: lan` requires `udp_enabled: true` (`src/util/config.cpp`),
`ToxAdapter::bootstrap()` now emits a **warn**-level line whenever LAN mode is in
effect: "LAN bootstrap only discovers peers on the local network; a peer behind
NAT or on a different network will never become reachable. Use 'bootstrap_mode:
auto' for DHT/NAT traversal across networks." (`src/tox/tox_adapter.cpp`). The
misconfiguration is now self-evident from the log instead of silent.

## 6. A far-end SSH auth failure is indistinguishable from a dead tunnel

Second session on the same lane (2026-08-14, multi-hour agent-driven workload).
Mid-session, `ssh mac` started returning:

```
Permission denied (publickey,password,keyboard-interactive)
Received disconnect from 127.0.0.1 port 2222:2: Too many authentication failures
```

The tunnel was **completely healthy** the whole time — `client.log` kept showing
`Tunnel <n> connected (received open ACK)` → `TUNNEL_CLOSE` → `sent local
half-close`. The real cause was on the far end: macOS `sshd` had reverted to
refusing pubkey auth after the home directory became group-writable
(`StrictModes`). But from the caller's side that is exactly what a half-open or
misrouted tunnel looks like, and the first instinct is to restart the tunnel —
which fixes nothing and costs a friend-link re-establishment.

This is the same *class* as #4 (invisible allowlist rejections) but one layer
further out: there, the tunnel refuses; here, the tunnel succeeds and the
tunneled service refuses.

**Suggested fix — give the client a health surface**, so "is the tunnel up?" is
answerable directly instead of by inference:

- a `toxtunnel status` / `health` subcommand printing friend-link state, peer
  online-since, active tunnel count, and last successful open-ACK timestamp;
- or, much cheaper: a periodic `client.log` summary line
  (`active_tunnels=N peer=online last_ack=<ts>`), so tailing the log answers it.

A tunnel that opens, carries bytes both ways, then closes quickly and
*repeatedly* is a strong signal of upper-layer rejection. Logging that shape
explicitly ("tunnel completed, peer closed after N bytes") would point the
operator at the far-end service rather than at the transport.

**Status: largely fixed (2026-08-18).** A health surface exists:
`toxtunnel inspect status` (Unix socket / Windows named pipe) returns
`mode`, `version`, `friends_online`, `tunnels_active`, `bytes_in`, `bytes_out`,
and `toxtunnel inspect tunnels` lists the live tunnels. That answers "is the peer
online and how many tunnels are open?" directly — the #7 concern below is covered
by `tunnels_active`. The 2026-08-18 change adds **`peer_online_seconds`** to
`/status` (`src/app/inspect_server.cpp`, wired from the client's active-endpoint
`online_since`), so "is the tunnel up, and since when" is now a direct query
rather than an inference from the lifecycle log. Verified live: offline reports
`peer_online_seconds:0`. Not added: a *last successful open-ACK timestamp* —
surfacing it would require a per-tunnel → client callback for marginal value over
`peer_online_seconds` plus the existing `Tunnel <n> connected (received open ACK)`
log line, so it was judged not worth the coupling.

This session (2026-08-18) re-confirmed the underlying scenario: `ssh mac` returned
`Permission denied (publickey)` while the tunnel was demonstrably healthy — the
server log showed `TCP connected to 127.0.0.1:22 for tunnel 2874` at the same
instant, i.e. bytes reached the Mac's sshd and sshd refused them (group-writable
home / `StrictModes`), exactly the failure this item warns about.

## 7. No visibility into concurrent tunnel count

Tunnel ids climbed past 42 in a single session with no periodic summary of how
many were open at once, so there is no cheap way to spot a tunnel leak on a
long-lived lane. Folded into the summary-line proposal in #6.

**Status (v0.4.9): addressed on demand.** `toxtunnel inspect status` reports
`tunnels_active`, so the concurrent count is now queryable at any time (see #6).
A *periodic* summary line in the log is still not emitted — spotting a slow leak
still means polling `inspect status`, not just tailing the log.

## 8. The DHT socket is IPv4-only, and silently steals inbound UDP from every other Tox app on the host

Third session on the same lane (2026-08-16). This one is the most expensive
entry in the file: it was misdiagnosed for hours as an iOS-Simulator networking
fault and became a tracked to-do item in the *consuming* project before anyone
looked at the tunnel.

The server had been running for two days. What it holds:

```
$ lsof -nP -iUDP:33445
COMMAND     PID    USER   FD   TYPE  DEVICE  SIZE/OFF NODE NAME
toxtunnel 76450 bin.gao    5u  IPv4  0xb27…       0t0  UDP *:33445
```

**IPv4 wildcard**, on the standard Tox DHT port. Three facts from the source
explain how it gets there and why nothing else can see the problem:

- `include/toxtunnel/tox/tox_adapter.hpp:90` — `bool ipv6_enabled = false;`, a
  hardcoded default. `src/tox/tox_adapter.cpp:121` passes it straight to
  `tox_options_set_ipv6_enabled`, so the socket is IPv4-only.
- `docs/CONFIGURATION.md`'s `tox:` block exposes `udp_enabled`, `tcp_port`,
  `bootstrap_mode` and `bootstrap_nodes` — there is **no** key for `ipv6` and
  none for our own UDP port. An operator cannot move either one.
- `grep -rn 'start_port\|end_port' include/ src/` is **empty**, so toxcore's
  defaults apply: try 33445, walk up to 33545 if busy.

The collision, on macOS/BSD:

1. ToxTunnel starts first and binds `0.0.0.0:33445`.
2. Any later Tox application with IPv6 enabled binds `[::]:33445` and the
   `bind()` **succeeds** — the IPv4 and IPv6 wildcards are separate pcbs. Its
   port walk therefore never advances to 33446; it believes 33445 was free.
3. Outbound works perfectly. Inbound IPv4 datagrams are delivered to the more
   specific IPv4 pcb — ToxTunnel — so the other application is permanently deaf
   on IPv4 while looking healthy.

The reason this costs so much time is step 3's invisibility to the victim:
`tox_self_get_udp_port()` still returns 33445, so the application cannot even
report "UDP unavailable". It just judges every bootstrap node unreachable and
blames the network. Note the asymmetry — ToxTunnel is only ever the *thief*
here, never the victim, so nothing in its own logs will ever hint at this.

Scope, honestly: the mechanism above is confirmed (repeated `lsof`, plus the
source facts). What was *not* confirmed is the original symptom attribution — a
later run showed the specific test case being chased had its peers on ports
34700/34900, so that case was not a victim after all. The hazard is real for any
Tox client left on the default port; the first diagnosis simply reached for it
too early.

**Suggested fixes, best value first:**

1. **Default `ipv6_enabled` to true**, or at minimum expose it in YAML. This
   alone converts a silent failure into correct behaviour: a dual-stack bind
   makes the *second* process's `bind()` fail, so its existing port walk moves
   to 33446 and both work.
2. **Set `start_port`/`end_port` explicitly and log the port actually bound.**
   Today an operator has no way to know which port ToxTunnel took.
3. **Warn at startup when 33445 is already held by another process** — one
   `getsockname` plus an info line would have ended this in seconds.

**Status: fixed (2026-08-18) — suggested fixes 1 and 3 implemented.**
- **Fix 1 (dual-stack by default):** `ToxConfig::ipv6_enabled` now defaults to
  **true** (matching toxcore) and is exposed in YAML as `tox.ipv6_enabled`
  (encode/decode/`to_yaml`, wired into both server and client `ToxAdapterConfig`).
  A dual-stack bind makes a second Tox process's `bind()` fail, so its port walk
  advances to 33446 and both work — this is the "best value" fix the note calls
  for. Operators on an IPv4-only host can still set `tox.ipv6_enabled: false`.
- **Fix 3 (log the bound port):** `ToxAdapter::initialize()` now logs the port
  toxcore actually bound, e.g. `Tox UDP socket bound to port 33446 (IPv6
  enabled)`, via `tox_self_get_udp_port()`. Verified live: with the existing
  client already holding 33445, a second instance logged 33446 — the walk works
  and is now visible.

Suggested fix 2 (explicit `start_port`/`end_port` config) was **not** done: with
IPv6 on by default the port collision no longer occurs silently, so an explicit
port-range knob was judged unnecessary for now. ToxTunnel remains the only party
that ever *held* the wildcard here, so this closes the hazard for well-behaved
peers.

## What worked well (worth not regressing)

- Zero-config NAT traversal did what it says: no port forwarding, no relay, and
  the LAN-direct path was not needed.
- Reusing an existing `data_dir` kept the server's Tox ID stable across
  restarts, so the client config did not need editing between sessions.
- The per-friend `rules.yaml` allowlist made it easy to expose *only* port 22 to
  *only* one key — a good default posture for this use case.
- Release `.deb` artifacts unpack cleanly without root (`dpkg-deb -x`), which
  mattered on a machine where we did not want to install system packages. The
  only extra step was providing `libsodium23`.
- **Long single commands are fine.** A 600 s `du` over a 23 GB tree, plus
  repeated `flutter` / `xcrun simctl` invocations and a full `flutter test` run
  streamed back over the tunnel with no truncation, stall, or timeout
  (2026-08-14 session).
- Tunnel lifecycle logging is legible enough to *exonerate* the transport: it
  was what proved the tunnel healthy while #6 was being diagnosed.
