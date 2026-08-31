# Architecture

## Overview

```
+-------------------+
|    CLI / Config   |    YAML config, CLI11 argument parsing
+-------------------+
         |
+-------------------+
| Application Layer |    TunnelServer / TunnelClient / RulesEngine
+-------------------+
         |
+--------+----------+
|  TCP   |   Tox    |
|  I/O   | Protocol |    asio thread pool / dedicated Tox thread
+--------+----------+
```

## Components

| Component           | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| `TunnelServer`      | Accepts Tox friend connections, forwards to local TCP services. Replies to `INFO_REQUEST` with a `server.disclose.*`-filtered `INFO_REPLY`. |
| `TunnelClient`      | Listens on local TCP ports, tunnels through Tox to the server. Sends `INFO_REQUEST` on friend-online; persists results to `KnownServersStore`. |
| `TunnelManager`     | Manages multiple concurrent tunnels per friend connection        |
| `Tunnel`            | State machine for a single bidirectional tunnel                  |
| `ProtocolFrame`     | Binary frame serialization/deserialization                       |
| `ToxAdapter`        | High-level wrapper for the toxcore C API. Owns the one dedicated Tox thread and its `tox_iterate` loop — all new Tox-thread work belongs here. |
| `RulesEngine`       | Per-friend access control (allow/deny rules)                     |
| `KnownServersStore` | Client-only YAML-backed registry of previously-connected servers (`<data_dir>/known_servers.yaml`); provides alias resolution for `--server-id` and `client.server_id`. |
| `SystemInfo`        | Server-side platform probes gated by `ServerInfoDisclose` policy (hostname / os / arch / uptime / version). Used to build `INFO_REPLY` payloads. |
| `IoContext`         | Async I/O thread pool wrapping asio                              |
| `Config`            | YAML configuration loading, validation, and CLI override merging |
| `ConfigReload`      | Atomically swaps the reloadable subset (rules, forwards, log level) of `Config` on SIGHUP / reload-pipe; rejects changes to non-reloadable fields. See [Operational Endpoints](#operational-endpoints). |
| `FailoverConfig`    | Per-client failover policy (`timeout_seconds`, `prefer_primary_grace_seconds`); consumed by `TunnelClient`'s per-endpoint state machine. |
| `MetricsRegistry`   | Lock-free registry of atomic counters / gauges / summaries; updated from any thread. |
| `MetricsServer`     | Asio HTTP/1.1 listener that renders `MetricsRegistry` as Prometheus text format on `GET /metrics`. Default-off; see [Operational Endpoints](#operational-endpoints). |
| `InspectServer`     | Local IPC server (Unix-domain socket on POSIX, named pipe on Windows) for the `toxtunnel inspect` CLI. Default-on, loopback-only by construction — no remote attack surface. |
| `Socks5Listener`    | Client-side TCP listener that auto-detects SOCKS5 v5 vs HTTP CONNECT by sniffing the first byte; binds loopback-only (enforced at config validation). Pipelined CONNECT payloads are preserved across the handshake. The tunnel layer reports why an open failed (`TunnelOpenOutcome`), so a rules denial answers `0x02` / `403` rather than a generic unreachable. |
| `OwnedBufferView`   | `shared_ptr<vector<uint8_t>>` slice handed from the Tox callback down to `TcpConnection::write`. Eliminates one copy on the inbound path (see [Inbound Copy Path](#inbound-copy-path)). |
| `WriteQueue`        | Per-tunnel write coalescer in `TunnelManager`. Accumulates small writes for up to `tunnel.coalesce_max_delay_us` (200µs default) or `tunnel.coalesce_max_bytes` (1362 = TUNNEL_DATA MTU) before flushing one TUNNEL_DATA frame. Wire-format unchanged. |
| `OwnedFrameBuffer`  | Outbound zero-copy buffer (Wave B). Reserves 6 bytes of prefix (`0xA0` lossless byte + 5-byte tunnel frame header) inside a single `shared_ptr<vector<uint8_t>>` allocation; the TCP read path writes directly into the payload region and `ProtocolFrame::serialize_tunnel_data_in_place()` fills in the header before toxcore is called. See [Outbound Copy Path](#outbound-copy-path). |
| `WriteCoalescer`    | Per-tunnel EWMA + policy state machine. Selects between `Bypass`, `Drain`, and `Batch` policies based on `avg_write_size` vs MTU and `avg_write_gap` vs `4 × max_delay_us`. α = 1/8, 4-tick hysteresis. Operator pins mode via `tunnel.coalesce_mode`. |
| `BdpFlowControl`    | Per-tunnel send-window state. Tracks RTT (PING/PONG round-trip) and bandwidth (cumulative-ACK delta) as EWMAs; recomputes the target window as `bdp × safety_factor` clamped to `[min, max]`. In `mode: fixed` the window is pinned to the v0.3.0 value; `mode: bdp` (the default since v0.4.1) sizes it dynamically. |
| `RateLimiter`       | Per-friend token-bucket layer that runs before `RulesEngine` on TUNNEL_OPEN. Modes: `off \| report \| enforce`. Hot-reloadable via the rules file. Defaults to `off` (no v0.3.0 behaviour change). A per-friend `rate_limit:` block **overrides only the fields it names**, inheriting the rest from `rate_limit_defaults`. Byte limiting (`bytes_per_sec` / `bytes_burst`) is live since v0.4.11: inbound `TUNNEL_DATA` from the friend is metered per friend, and `enforce` defers and replays over-budget frames in arrival order rather than dropping them. It is self-bounding — a parked frame emits no `TUNNEL_ACK`, so the peer's window fills and it stops sending. A receiver-side deferral cannot hold an average rate against a peer that ignores flow control; `max_concurrent_tunnels` / `open_per_sec` remain the anti-DoS knobs. |
| `ToxWatchdog`       | Heartbeat-based detector for a stalled `tox_iterate`. The Tox thread bumps the counter on every return; a 1 Hz observer on the main IO context calls `std::abort()` if the deadline is exceeded. Persistent abort count lives at `<data_dir>/abort_count`. |
| `TunnelIdAllocator` | Bitset-backed 1..65535 allocator with a roving cursor and an explicit `reserve(id)` API for the tunnel-resume path. |
| `TunnelResumeStore` | **Not wired up.** Client-side `<data_dir>/tunnel_resume_state.yaml` persistence (schema-versioned, age-pruned), written against the day resume survives a process restart. Nothing constructs it today: resume is live-reconnect only, so there is no restart for it to survive, and `tunnel.resume.state_path` is parsed but never read. Kept deliberately — see `docs/CONFIGURATION.md`, which already calls the store reserved. |
| `atomic_write_file` | Shared helper: write to `<path>.tmp.<pid>`, fsync, rename, optional parent-dir fsync (`F_FULLFSYNC` on macOS). Used by `ToxSave::persist` and `KnownServersStore::save` (and by `TunnelResumeStore::save`, which nothing calls). |

## Configuration Model

ToxTunnel now uses a shared top-level `tox` configuration block for toxcore network settings used
by both server and client.

- `tox.udp_enabled`
- `tox.tcp_port`
- `tox.bootstrap_mode`
- `tox.bootstrap_nodes`

`server` and `client` sections remain mode-specific and only contain application-level settings
such as `rules_file`, `server_id`, `forwards`, and `pipe`.

## Protocol

Binary framing over Tox lossless custom packets:

```
Offset  Size  Field
------  ----  -----
0       1     type       (FrameType)
1       2     tunnel_id  (uint16, big-endian)
3       2     length     (uint16, big-endian)
5       N     payload
```

### Frame Types

| Type            | Value | Description                                       |
| --------------- | ----- | ------------------------------------------------- |
| `TUNNEL_OPEN`   | 0x01  | Request to open a new tunnel                      |
| `TUNNEL_DATA`   | 0x02  | Data frame                                        |
| `TUNNEL_CLOSE`  | 0x03  | Close tunnel gracefully                           |
| `TUNNEL_ACK`    | 0x04  | Acknowledge tunnel open                           |
| `TUNNEL_ERROR`  | 0x05  | Error. Payload: `[code:1][utf-8 description]`. See **TUNNEL_ERROR categories** below — the code, not the text, is the contract. |
| `INFO_REQUEST`  | 0x06  | Client → Server: ask peer for system info (`tunnel_id` = 0, empty payload). Sent once when the friend transitions to online. |
| `INFO_REPLY`    | 0x07  | Server → Client response (`tunnel_id` = 0, UTF-8 YAML map filtered by `server.disclose.*`). Empty payload = "policy is to disclose nothing"; client persists the result to `known_servers.yaml`. Old servers ignore `INFO_REQUEST` — client falls back to locally-observable metadata only. |
| `TUNNEL_RESUME_REQUEST` | 0x08 | Client → Server: reattach a tunnel that survived a brief disconnect (the server held it for `resume.max_age_seconds`). Binary payload: `[version:1=0x01][prior_id:2][recv:8][send:8][host_len:1][host:N][port:2]`. Wire-inactive when `tunnel.resume.enabled: false` (the default). Old servers ignore unknown opcodes; the client falls back to `TUNNEL_OPEN` if the server declines or doesn't recognise the tunnel. |
| `TUNNEL_RESUME_ACK`     | 0x09 | Server → Client: result of the resume attempt. Binary payload: `[version:1=0x01][new_id:2][server_recv:8][server_send:8][status:1]` where `status ∈ {0=Ok, 1=TargetUnreachable, 2=RulesDenied, 3=TooOld, 4=Unknown}`. |
| `PING`          | 0x10  | Keep-alive ping                                   |
| `PONG`          | 0x11  | Keep-alive response                               |

> Every frame is prepended with a single `kLosslessPacketByte` (0xA0) when
> handed to toxcore's lossless custom packet API. ToxTunnel does **not**
> implement remote command execution — `INFO_REPLY` is the only metadata
> channel and the server operator opts in per field.

### TUNNEL_ERROR categories (v0.4.12+)

The error code is a **category**, and the three values are disjoint so a peer
can act on the number alone. The description is for humans; it carries no
protocol meaning.

| Code | Category | Emitted for | Client outcome |
| ---- | -------- | ----------- | -------------- |
| 1 | Policy-denied open | Rules denial, rate limit, concurrent-tunnel cap — anything the server *operator's* configuration refused | `Denied` → SOCKS5 `0x02` / HTTP `403` |
| 2 | General non-policy failure | DNS failure, any connect failure that is not a refusal, "Tunnel ID in use", "Tunnel not found", target lost before the tunnel was established, half-close linger timeout | `Unreachable` → SOCKS5 `0x04` / HTTP `502` |
| 3 | Actively refused | The target's TCP stack refused the connection, and nothing else | `Refused` → SOCKS5 `0x05` / HTTP `502` |

The **Client outcome** column applies while an open is still pending — that is
the window in which a SOCKS5 or HTTP CONNECT caller is waiting for its reply.
Some code 2 emitters are inherently post-open ("Tunnel not found", the
half-close linger timeout): by the time they arrive the reply has already been
sent, so they tear down the established connection instead of producing a fresh
`0x04` / `502`. Their code still matters — it is what the peer logs and what any
future consumer classifies on.

Code 2 is the whole non-policy bucket, deliberately not "cannot reach target":
a new failure mode belongs there unless it genuinely fits 1 or 3.

**Why the categories exist.** Up to v0.4.11 code 3 conflated policy denials,
target failures and teardowns, so a rate-limited `TUNNEL_OPEN` reached a SOCKS5
caller as `0x04` "host unreachable" — indistinguishable from a dead target. The
client compensated by searching the description for `"refused"`, which is not
portable: C++ only requires `error_code::message()` to *describe* the error, and
on Windows asio takes that text from `FormatMessage`, whose language follows the
machine locale. The server therefore classifies numerically
(`ec == asio::error::connection_refused`, in
`app::detail::open_failure_for_connect_error`) rather than by string.

**Mixed versions.** A v0.4.12+ client keeps a compatibility shim for servers
≤ v0.4.11 (`app::tunnel_open_outcome_for`): under code 3 it treats the exact
strings `"Rate limit exceeded"` and `"Tunnel limit exceeded"` as denials, then
falls back to the legacy `"refused"` substring, then to `Unreachable`. Code 3
cannot simply be redefined as "refused" on the client, because an old server
also sends 3 for a connect *timeout*. In the other direction an un-upgraded
client benefits too: the new server's policy denials arrive as code 1, which
v0.4.11 already mapped to `Denied`. The refused branch emits the fixed
lowercase literal `"TCP connection refused: "` so old clients' substring check
keeps working regardless of the platform's message language. The shim is
deletable once no ≤ v0.4.11 server remains in service.

## Threading Model

```
+-------------+     +-------------+     +-------------+
| Main Thread |---->| Tox Thread  |<--->| Tox Network |
+-------------+     +-------------+     +-------------+
       |                   ^
       v                   |
+-------------+     +-------------+
| I/O Pool    |<--->| Tunnel Mgr  |
| (10 threads)|     +-------------+
+-------------+
       ^
       |
+-------------+
| TCP Sockets |
+-------------+
```

- **Main thread**: Signal handling, orchestration
- **Tox thread**: Single dedicated thread for all toxcore API calls (toxcore is not thread-safe)
- **I/O pool**: Async TCP operations via asio (default: 10 threads)

v0.3.0 introduced four new I/O participants — `MetricsServer`, `InspectServer`,
`Socks5Listener`, and the reload watcher. On POSIX **none of them add a thread**:
all four live on the existing asio I/O pool. Windows is the one exception — it
has no SIGHUP, so the reload named pipe is served by one small dedicated thread
(`WindowsReloadPipeServer` in `cli/main.cpp`) that only posts the reload:

- `MetricsServer` is a plain asio acceptor with per-connection strands. `InspectServer`
  is too on POSIX (AF_UNIX); on Windows it serves its per-pid named pipe from one
  dedicated thread (`pipe_thread_`).
- `Socks5Listener` shares the pool with the regular forward listeners.
- SIGHUP is wired through `asio::signal_set` bound to the main `IoContext` on POSIX. On
  Windows there is no SIGHUP — `ConfigReload` watches a named pipe at
  `\\.\pipe\toxtunnel-reload-<pid>` (path hard-coded by PID, not configurable) on a
  small dedicated thread. The `toxtunnel reload` CLI helper writes `RELOAD\n` to it,
  resolving the pid from `<data_dir>/toxtunnel.pid`.
- `MetricsRegistry` is updated lock-free (atomic increments) from any thread, including
  the Tox thread, without marshalling.

### Outbound send seam

Every per-tunnel send callback returns `tunnel::SendOutcome`
(`Sent` / `SendqFull` / `PermanentFail`), not a bool. The distinction is
load-bearing rather than cosmetic: `SendqFull` means the frame never reached
toxcore and the caller still owns it, so a caller that reads it as "delivered"
goes on to release the tunnel id while the frame is still queued — and ids are
recycled per friend.

Two owners exist for a backpressured frame, and exactly one owns any given one:

| Frame | Retry owner |
|---|---|
| `TUNNEL_OPEN`, `TUNNEL_ACK` | the tunnel / the server's `OpenAckGate` (retained, re-sent on the SENDQ backoff in `tunnel/sendq_retry.hpp`) |
| `TUNNEL_DATA` | the per-tunnel coalesce buffer |
| everything else | `TunnelManager::pending_outbound_` (raw wire bytes, drained on a timer) |

The manager queue carries no tunnel identity or generation, which is why the
handshake frames were moved off it. All four production tunnel paths (the
client's forward, SOCKS5 and pipe tunnels, and the server's target tunnel) are
wired from one place, `app::detail::make_tunnel_senders()`.

**Outbound FIFO barrier.** A per-tunnel send goes straight to toxcore, bypassing
`TunnelManager::send_frame()`, so it must consult
`TunnelManager::outbound_queue_busy()` *before* sending — otherwise a new
`TUNNEL_OPEN` for a recycled id can be accepted ahead of the old, still-parked
`TUNNEL_CLOSE` for that same id, and the CLOSE then kills the new tunnel. The
barrier covers frames already parked *and* one popped by the drain and still
inside the transport call. It is applied to `TUNNEL_OPEN` and `TUNNEL_ACK` only;
`TUNNEL_DATA` is ordered behind them transitively (it cannot flow before the
tunnel is `Connected`), and the still-parked control frames keep their existing
best-effort ordering until they too move to driver ownership. The guarantee is
causal, not total: the check releases `pending_mutex_` before calling toxcore, so
a frame parked by an unrelated thread in that gap can still be overtaken.

Design rationale and the remaining slices: `docs/design/outbound-send-driver.md`.

## Data Flow

### Client -> Server (Outbound Tunnel)

```
1. TCP client connects to client's local port (e.g., :2222)
2. TunnelClient creates Tunnel, sends TUNNEL_OPEN to server
3. Server's TunnelServer receives TUNNEL_OPEN
4. Server connects to target (e.g., 127.0.0.1:22)
5. Server sends TUNNEL_ACK
6. Bidirectional data flow begins:
   - TCP data -> TUNNEL_DATA -> Tox -> TUNNEL_DATA -> TCP
```

### Tunnel Lifecycle

```
          Client                          Server
            |                               |
            |------- TUNNEL_OPEN --------->|
            |                               |--- connect() --->
            |<------ TUNNEL_ACK ------------|
            |                               |
            |<====== TUNNEL_DATA ==========>|
            |                               |
            |------- TUNNEL_CLOSE --------->|  (or <-)
            |                               |
```

#### Handshake ownership and the OPEN_ACK barrier

Neither handshake frame is "fire and forget"; each is owned by a driver that
retries it until the transport gives a definite answer.

**Client, `TUNNEL_OPEN`.** `TunnelImpl::open()` moves to `Connecting` and sends.
`SendqFull` keeps the frame and re-arms a dedicated retry timer — deliberately
*not* the coalesce timer's delay, which is legally `0` (the effective Windows
default) and would spin. Only `PermanentFail` rolls back to `None`. The
`OpenPhase` state machine (`Pending → Sending → Sent | Abandoned | Failed`)
records whether the peer can possibly know the id, which decides one invariant:

> A local close before the OPEN was ever sent resolves the tunnel locally and
> emits **no** `TUNNEL_CLOSE` — the peer has never heard of the id, and after
> recycling that CLOSE would tear down an unrelated tunnel. Once the OPEN is
> sent, the CLOSE becomes mandatory.

`open()`, `retry_open_send()`, `close()` and `force_close()` can all race for the
same tunnel. The phase claim excludes the two OPEN attempts from each other;
`open()` and `close()` claim their terminal edges with
`TunnelImpl::transition_state_if()`, a compare-exchange on `state_`, and
`transition_state()` itself refuses to leave a terminal state so the remaining
blind writers cannot resurrect one.

`force_close()` goes further, through `TunnelImpl::claim_terminal()`: it publishes
the terminal state AND the decision about whether a `TUNNEL_CLOSE` is owed in a
single critical section. Those were two steps once, and the instant between them
was observable as "terminal, owes nothing" — which is exactly the state that means
the id is free, so a resolver could recycle the id and the claimant would then
emit its CLOSE against whatever took it. `id_releasable()` reads the tunnel state
under that same lock, which is what makes the pair atomic to every observer.

**Server, `TUNNEL_ACK` (the OPEN_ACK).** `app::detail::OpenAckGate` puts the
`Connected` transition, the open metrics, `start_read()` and therefore all DATA
admission behind the *same* `Sent` transition of the ACK. Publishing any of them
earlier lets TCP reads start while the ACK is still parked, and DATA — which
travels the per-tunnel path, not the manager queue — then reaches a peer still in
`Connecting`, which silently discards it. The gate's phases
(`Pending → Sending → Committing → Committed | Abandoned`) exist because
resolution is not instantaneous and the gap is observable from the TCP strand:
`Sending` stops an abandonment from emitting `TUNNEL_ERROR` while an ACK is still
in flight, and `Committing` stops a target death mid-commit being answered as
"the tunnel is live" when `Tunnel::close()` would still be a no-op.

If the target dies while the ACK is backpressured, the waiting client is resolved
with a terminal `TUNNEL_ERROR`, not a `TUNNEL_CLOSE` — a CLOSE received in
`Connecting` does not complete that state. Reaching that path needs
`TcpConnection::watch_peer_close()`: with `start_read()` held back there is no
outstanding read, and a socket with no outstanding read never surfaces a FIN. The
watch is a readability wait plus an `available()` probe; data seen there is read
into a bounded holdback buffer and the watch re-arms, so a target that writes a
banner and *then* closes is still detected. The holdback is replayed to `on_data_`
by `start_read()`, ahead of the first live read — reads happen early, deliveries
do not, so the barrier holds. The whole watch-to-read takeover is dispatched onto
the connection's strand: `start_read()` is called from a generic I/O worker (the
gate's commit can run from a retry timer), and a stand-down flag alone cannot stop
a watch handler that is already past its own check.

## Operational Endpoints

ToxTunnel v0.3.0 exposes three out-of-band channels that operators use to
observe, inspect, and reload a running daemon. None of them carry tunnel data
and none of them open additional threads.

### `/metrics` HTTP (Prometheus)

`MetricsServer` is a small asio HTTP/1.1 listener that renders `MetricsRegistry`
in Prometheus text exposition format. **Default-off**; enable per
`docs/CONFIGURATION.md` → "metrics".

Exposed series (subject to growth — names are stable once shipped):

| Metric | Type | Description |
|---|---|---|
| `toxtunnel_build_info{version=…}` | gauge | Always-1 series carrying build version label |
| `toxtunnel_tunnels_active{role=…}` | gauge | Tunnels currently open, split by `role` (server/client) |
| `toxtunnel_tunnels_opened_total{result=…}` | counter | Open attempts (`ok`/`denied`/`failed`) |
| `toxtunnel_tunnels_closed_total{reason=…}` | counter | Closes (`local`/`remote`/`timeout`/`error`); reaper-driven closes appear as `reason="timeout"` |
| `toxtunnel_bytes_in_total` | counter | Bytes received from Tox peers (unlabeled total) |
| `toxtunnel_bytes_out_total` | counter | Bytes sent to Tox peers (unlabeled total) |
| `toxtunnel_friends_online` | gauge | Tox friends currently online |
| `toxtunnel_tox_iterate_lag_milliseconds_{count,sum,max}` | summary | `tox_iterate()` elapsed-time samples |

There is no remote-command channel; the daemon does not export per-frame
counts or a self-connection-status gauge.

Bind to loopback if you do not want public scraping; reverse-proxy with TLS +
auth if you do.

### `toxtunnel inspect` IPC

`InspectServer` accepts connections on a local Unix-domain socket (POSIX) or
named pipe (Windows). Default path follows `data_dir/toxtunnel.sock` /
`\\.\pipe\toxtunnel-<pid>`. **Default-on, loopback-only by
construction** — there is no TCP listener and no auth layer because the OS
permission bits on the socket file (POSIX) / the pipe DACL (Windows: daemon
user, SYSTEM, Administrators) are the access control. The daemon writes its
pid to `<data_dir>/toxtunnel.pid` (`util::PidFileGuard`) so the CLI can derive
the per-pid pipe name; `TOXTUNNEL_INSPECT_PID` overrides it.

Wire format is intentionally trivial:

1. Client opens the socket, writes one HTTP-style request line terminated by
   `\n`. Only two paths are accepted: `GET /tunnels` and `GET /status`.
2. Server replies with one JSON object on a single line terminated by `\n`,
   then closes.

```
> GET /tunnels
< {"mode":"client","version":"0.4.5","friends_online":1,"tunnels":[{"id":17,"friend_pk_prefix":"AA…","target":"127.0.0.1:22","state":"Connected","bytes_in":4096,"bytes_out":8192,"idle_seconds":3}]}

> GET /status
< {"mode":"client","version":"0.4.5","friends_online":1,"tunnels_active":4,"bytes_in":12345,"bytes_out":67890}
```

The CLI ships only two subactions — `toxtunnel inspect tunnels` (default) and
`toxtunnel inspect status` — and they pretty-print the reply. Any other
subaction string is rejected by the argument parser (`CLI::IsMember`). An
unknown request path sent straight down the socket gets
`{"error":"unknown request"}`. `idle_seconds` is an integer and is omitted
entirely for a tunnel that has never been idle. Tooling that wants structured output should
either pass `--json` or speak the socket directly with `socat - UNIX-CONNECT:…`.

### Friend list and the per-friend manager map

Two pieces of server state need their concurrency protocol stated, because both
have produced real bugs.

**Friend list.** The server's Tox friend list is seeded from `rules.yaml`, at
startup and again after every rules reload (`preseed_friends_from_rules`).
Without this, `on_friend_request` was the only path that ever added a friend —
and it refuses a public key that is not yet in the rules. Since toxcore does not
re-send a friend request the peer has already recorded, the ordinary first-run
mistake (client started before its key was added) was **unrecoverable** without
minting a new client identity. The pre-seed makes adding the rule sufficient.

Keys removed from `rules.yaml` are deliberately **not** deleted from the friend
list. The access decision is already enforced by default-deny on `TUNNEL_OPEN`,
and the rate limiter drops the friend's spec on reload, so a stale friend entry
grants nothing; deleting it would additionally drop live tunnels and the
transport relationship for what is usually a reversible administrative edit. The
cost is a friend-list slot. (Note that `tox_friend_delete` does not notify the
peer, so deletion is recoverable — the reason to avoid it is the disruption, not
irreversibility.)

The pre-seed snapshots the rule keys under `rules_mutex_` and **releases it
before** calling the Tox adapter: those calls marshal onto the Tox thread, which
takes `rules_mutex_` itself on its inbound paths, so holding it across the call
would deadlock. At startup the adapter is not yet running and the marshalling
degenerates to an inline call.

**`managers_` / `held_managers_`.** Two mechanisms protect this state, and both
are needed.

*Serialisation.* Every friend-lifecycle transition — `connected`, `disconnected`,
a keepalive peer-dead teardown, and the resume hold's prune timer — is posted
onto `inbound_strand_`, the same strand that runs inbound frame handling. Map
locking alone is not sufficient, because each transition classifies state under
`managers_mutex_` and then acts after releasing it: two transitions for one
friend could interleave in that gap (a `connected` deciding to keep a live
manager while a queued teardown moves that very manager to the held map, leaving
no live manager behind). On one strand they cannot overlap, so a decision is
still true when it is acted on. Sharing the strand with frame handling also means
a `TUNNEL_RESUME_REQUEST` can never land halfway through a teardown.

*Locking.* `managers_mutex_` guards both maps, and the invariant is that a friend
is in at most one of them. Teardown performs {look up live, stop maintenance,
decide hold, insert held, erase live} in a single critical section, erasing last
— an earlier version erased first and inserted the hold later, and a `connected`
landing in that window produced a live manager *and* a held one for the same
friend, so every `TUNNEL_RESUME_REQUEST` routed to the fresh manager and declined
tunnels that were still being held.

Only work that cannot re-enter `managers_mutex_` runs under it
(`TunnelManager::empty()`, `disable_keepalive()`, `disable_reaper()` — a map read
and two timer cancellations). Anything that can — `close_all()`, tunnel
callbacks, frame sends — runs after the lock is released (the "H-01 discipline").
Insertions use `try_emplace` so a concurrent installer wins rather than being
silently overwritten; a manager that loses such a race is torn down with
`close_all_local()`, because tunnel ids are recycled per friend and the winner
may already own the same ids. That call releases local state, emits no teardown
frame of its own, and closes an outbound gate after which no further send can be
authorised. It does **not** suppress a send another thread authorised just
before the gate closed — the stronger "nothing of this session reaches the wire"
form was withdrawn because waiting for those sends deadlocked against the data
path's `coalesce_mutex_`. The exact residual is documented on
`TunnelManager::close_all_local()`.

toxcore does not guarantee a `disconnected` before every `connected`, so
`setup_tunnel_manager` classifies the event (`classify_connected_event`) instead
of assuming: an unpaired `connected` for a friend whose manager is still live
keeps the existing manager and logs a warning, rather than replacing it.

### SIGHUP / reload pipe

POSIX: `kill -HUP <pid>` (or `systemctl reload toxtunnel`) is delivered to an
`asio::signal_set` on the main `IoContext`. Windows has no SIGHUP, so the
equivalent path is a named pipe. `toxtunnel reload [-d DIR | -c CONFIG]` wraps
both: it reads `<data_dir>/toxtunnel.pid`, checks the pid still names a
toxtunnel process (Linux `/proc/<pid>/comm`, macOS `proc_pidpath`) and sends
SIGHUP, or on Windows writes `RELOAD\n` to `\\.\pipe\toxtunnel-reload-<pid>`.

Either trigger runs `reload_config_from_disk()` (cli/main.cpp) followed by
`TunnelServer::reload()` / `TunnelClient::reload()`, with
`util::check_reloadable()` as the gate. Together they:

1. Re-reads the original config file.
2. Diffs the parsed result against the live `Config`.
3. **Rejects** the reload (no changes applied) if any non-reloadable field
   changed: `mode`, `data_dir`, `tox.*`, `server.disclose.*`, `client.server_id`,
   `client.failover.*`, `metrics.*`, `inspect.*`, `client.socks5.*`, the entire
   `tunnel.*` block (`coalesce_*`, `idle_timeout_seconds`, `reaper_tick_seconds`,
   `keepalive_*`, `resume.*`), `flow_control.*`, and `watchdog.*`.
4. Otherwise atomically swaps the reloadable subset — `rules_file` contents,
   `client.forwards`, and `logging.level` — under the strand that owns each
   consumer. Existing tunnels are **never** torn down by a reload — not even
   ones the new rules would now deny. Only the next `TUNNEL_OPEN` is judged
   against the new rules.

A successful reload is logged at INFO as `config reloaded (rules: N rules)`
(server) or `config reloaded (forwards: +A -B)` (client). A rejected reload is
logged at ERROR as `reload rejected: config reload rejected: field '<name>'
requires a restart (not in the reloadable subset)` and leaves the running config
untouched. On the client, an added forward whose local port cannot bind is not
a rejection: the rest of the reload is applied and the daemon logs
`reload applied with warnings: <address>:<port>: <reason>` (the address is
the forward's effective `local_address`, so the message identifies which
forward failed when several share a port number across interfaces).

## Inbound Copy Path

Pre-v0.3.0 the inbound path (Tox → local TCP) made three copies: toxcore's
internal buffer → ToxTunnel framing buffer → per-tunnel queue → kernel via
`asio::async_write`. The Wave A zero-copy rework collapses the middle two into
a single shared owner.

```
toxcore packet callback (Tox thread)
   │  std::vector<uint8_t>  ← framed payload, one allocation
   ▼
make_shared<vector<uint8_t>>   ← OwnedBufferView
   │  post() to TunnelManager strand on the I/O pool
   ▼
TunnelManager::route(OwnedBufferView)
   │  slice → asio::buffer pointing into the same vector
   ▼
TcpConnection::write(buffer, keep_alive = OwnedBufferView)
   │  asio::async_write — buffer stays valid until completion
   ▼
kernel writev()
```

Key properties:

- One heap allocation per inbound Tox frame, regardless of fan-out.
- `OwnedBufferView` keeps the backing vector alive across the async write; the
  shared_ptr is captured by the completion handler.
- Strand discipline is unchanged — the buffer is only **read** off-strand by
  asio's writer, never mutated.
- The outbound path (TCP → Tox) was not changed in v0.3.0; the write
  coalescer (`WriteQueue`) reuses the existing `TUNNEL_DATA` framing buffer.

## Outbound Copy Path

The v0.4.0 Wave B work makes the symmetric outbound path
(local TCP → Tox) single-copy. The TCP read writes directly into an
`OwnedFrameBuffer`'s payload region, which reserves 6 header bytes in
front of the payload inside the same allocation. `serialize_in_place()`
fills in the header before the buffer is handed to
`ToxAdapter::send_lossless_packet`, so toxcore sees one contiguous wire
view per frame.

```
TcpConnection::async_read_some  (I/O pool worker thread)
   │  reads N bytes into the OwnedFrameBuffer payload region
   │  (allocation = [0xA0][type:1][tunnel_id:2][length:2][payload:N])
   ▼
TunnelImpl::send_data_to_tox
   │  consults the adaptive coalescer; on bypass/drain → emit directly
   │  on batch → buffer for up to coalesce_max_delay_us
   ▼
ProtocolFrame::serialize_tunnel_data_in_place(OwnedFrameBuffer&, id)
   │  writes the 6 prefix bytes into the reserved header room
   ▼
ToxAdapter::send_lossless_packet(friend, wire_view.data(), size)
   │  toxcore copies into its own buffer (single unavoidable copy)
   ▼
encrypted UDP / TCP relay
```

Key properties:

- One heap allocation per outbound TUNNEL_DATA frame; no separate
  framing buffer.
- `OwnedFrameBuffer` shares ownership through `shared_ptr`; the
  async-send completion handler keeps the allocation alive until
  toxcore returns.
- The adaptive `WriteCoalescer` selects `Bypass` for bulk transfers
  with MTU-sized writes (zero hold latency), `Drain` for bursty
  sub-MTU writes (emit on overflow only), and `Batch` for trickle
  workloads (the v0.3.0 default behaviour, with a 200 µs hold timer).
- The `BdpFlowControl` window resizes between `min_window_bytes` and
  `max_window_bytes` when `flow_control.mode: bdp`; in `fixed` mode
  the v0.3.0 256 KiB / 16 KiB cadence is preserved.
- When the tunnel send window is full, the currently-read TCP chunk is
  retained in `pending_tcp_input_`, `TcpConnection::pause_read()` stops
  further socket reads, and later `TUNNEL_ACK`s retry that backlog before
  `resume_read()` is posted. This avoids silently dropping the chunk that
  happened to cross the window boundary.
- If a deferred `TUNNEL_ACK` itself hits toxcore lossless-send backpressure,
  the unacked byte count is restored and a short ACK retry timer is armed.
  This matters when the receiver's TCP queue has already drained: without the
  timer there may be no later writable callback to reopen the sender's window.
- Control frames routed through `TunnelManager::send_frame` (notably
  `TUNNEL_OPEN_ACK` on the server side, plus `PING`/`PONG`) get the same
  treatment via `TunnelManager::pending_outbound_`: on toxcore SENDQ-full,
  the serialized frame is parked FIFO and a 20 ms drain timer retries until
  it lands. Without this, a burst of concurrent `TUNNEL_OPEN`s could silently
  lose `TUNNEL_OPEN_ACK`s and wedge the client peer in `Connecting` forever
  (the v0.4.5 SENDQ-loss bug). The queue is capped at 4096 frames per
  manager; exceeding the cap is the only path that surfaces `send_frame` →
  `false` to the caller.
- The per-tunnel `on_send_to_tox` callback path (`TUNNEL_OPEN` from a client
  opening a tunnel, `TUNNEL_CLOSE` emitted by either side after the local
  TCP socket FIN's) routes through `tox_adapter_->send_lossless_packet`
  directly — but on SENDQ-full failure it forwards the (non-DATA) frame to
  `TunnelManager::queue_outbound_for_retry`, the same drain queue described
  above. `TUNNEL_DATA` frames keep using the per-tunnel coalesce buffer's
  retry-on-timer mechanism rather than double-queueing into the manager;
  the frame-type byte at offset 0 is used to discriminate. Without this,
  a `TUNNEL_CLOSE` lost to SENDQ-full would leave the peer's tunnel hung
  in `Disconnecting` (the bidirectional-bulk-transfer close-handshake hang).
- TCP close is directional. Local EOF does **not** emit `TUNNEL_CLOSE`
  until both `pending_tcp_input_` and the coalesce buffer have drained
  into ordered Tox DATA frames; peer `TUNNEL_CLOSE` maps to
  `TcpConnection::shutdown_send()` so the local application sees EOF on
  the receive side while the reverse direction can continue. This is what
  keeps full-duplex protocols such as SSH / SCP from truncating tail data.

## Operational Endpoints (v0.4 additions)

- `toxtunnel_outbound_buffer_{allocs,reuse,overflow}_total` — outbound
  `OwnedFrameBuffer` accounting.
- `toxtunnel_coalesce_policy_transitions_total` — state-machine moves
  between adaptive policies.
- `toxtunnel_tunnel_rtt_microseconds_{count,sum,max}`,
  `_send_window_bytes_{count,sum,max}`, and
  `_bandwidth_bytes_per_second_{count,sum,max}` — summaries from
  `BdpFlowControl`.
- `toxtunnel_rate_limit_open_rejected_total`,
  `toxtunnel_rate_limit_bytes_throttled_total` — per-friend rate limiter.
- `toxtunnel_tox_iterate_lag_ms` — gauge from `ToxWatchdog`; updated on
  every 1 Hz observer tick.
- `toxtunnel_watchdog_aborts_total` — cumulative aborts since process
  start; persistent count in `<data_dir>/abort_count`.
- `toxtunnel_resume_attempts_total`, `_successes_total`, `_failures_total` —
  tunnel-resume protocol counters (client-side).

## Dependencies

| Library                                          | Version | Purpose                                         |
| ------------------------------------------------ | ------- | ----------------------------------------------- |
| [c-toxcore](https://github.com/TokTok/c-toxcore) | v0.2.22 | Tox protocol (git submodule, built from source) |
| [asio](https://github.com/chriskohlhoff/asio)    | 1.28.0  | Async I/O (FetchContent, header-only)           |
| [spdlog](https://github.com/gabime/spdlog)       | 1.17.0  | Logging (FetchContent; bumped from 1.12 for Apple Clang 17 compat) |
| [CLI11](https://github.com/CLIUtils/CLI11)       | 2.6.2   | CLI argument parsing (FetchContent)             |
| [yaml-cpp](https://github.com/jbeder/yaml-cpp)   | 0.9.0   | YAML parsing (FetchContent)                     |
| libsodium                                        | system  | Cryptography (required by toxcore)              |
| [Google Test](https://github.com/google/googletest) | latest | Testing (FetchContent, test builds only)     |

## Project Structure

```
tox-tcp-tunnel/
  cli/
    main.cpp                    # CLI entry point
  include/toxtunnel/
    core/                       # Async I/O primitives
      io_context.hpp
      tcp_connection.hpp
      tcp_listener.hpp
    tox/                        # Tox protocol layer
      types.hpp
      tox_adapter.hpp
      tox_connection.hpp
      tox_save.hpp
      bootstrap_source.hpp
    tunnel/                     # Tunnel protocol
      protocol.hpp
      tunnel.hpp
      tunnel_manager.hpp
    app/                        # Application logic
      tunnel_server.hpp
      tunnel_client.hpp
      rules_engine.hpp
      stdio_pipe_bridge.hpp
    util/                       # Utilities
      config.hpp
      logger.hpp
      error.hpp
      expected.hpp
      circular_buffer.hpp
  src/                          # Implementations (mirrors include/)
  tests/
    unit/                       # Unit tests
    integration/                # Integration tests
    packaging/                  # CPack layout verification scripts run by CI
    soak/                       # Bounded smoke tests (`ctest` or `ctest -L soak`)
    chaos/                      # Bounded smoke test (`ctest` or `ctest -L chaos`)
                                # (~535 tests total across all suites)
  third_party/
    c-toxcore/                  # toxcore git submodule
  docs/                         # Documentation
```

## Security Considerations

1. **End-to-end encryption**: All traffic is encrypted by Tox using NaCl/libsodium
2. **No central server**: Direct P2P connection, no MITM risk from server operator
3. **Access control**: Use `rules_file` to restrict what friends can access
4. **Identity protection**: Back up `tox_save.dat` (contains private key)
5. **NAT traversal**: Uses Tox's built-in NAT hole punching, no port forwarding needed
6. **LAN bootstrap**: `tox.bootstrap_mode: lan` relies on local discovery and optional private
   bootstrap nodes rather than the public node list
