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
| `ToxAdapter`        | High-level wrapper for the toxcore C API                         |
| `ToxThread`         | Dedicated thread for the toxcore event loop                      |
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
| `Socks5Listener`    | Client-side TCP listener that auto-detects SOCKS5 v5 vs HTTP CONNECT by sniffing the first byte; binds loopback-only (enforced at config validation). Pipelined CONNECT payloads are preserved across the handshake. |
| `OwnedBufferView`   | `shared_ptr<vector<uint8_t>>` slice handed from the Tox callback down to `TcpConnection::write`. Eliminates one copy on the inbound path (see [Inbound Copy Path](#inbound-copy-path)). |
| `WriteQueue`        | Per-tunnel write coalescer in `TunnelManager`. Accumulates small writes for up to `tunnel.coalesce_max_delay_us` (200µs default) or `tunnel.coalesce_max_bytes` (1362 = TUNNEL_DATA MTU) before flushing one TUNNEL_DATA frame. Wire-format unchanged. |
| `OwnedFrameBuffer`  | Outbound zero-copy buffer (Wave B). Reserves 6 bytes of prefix (`0xA0` lossless byte + 5-byte tunnel frame header) inside a single `shared_ptr<vector<uint8_t>>` allocation; the TCP read path writes directly into the payload region and `ProtocolFrame::serialize_tunnel_data_in_place()` fills in the header before toxcore is called. See [Outbound Copy Path](#outbound-copy-path). |
| `WriteCoalescer`    | Per-tunnel EWMA + policy state machine. Selects between `Bypass`, `Drain`, and `Batch` policies based on `avg_write_size` vs MTU and `avg_write_gap` vs `4 × max_delay_us`. α = 1/8, 4-tick hysteresis. Operator pins mode via `tunnel.coalesce_mode`. |
| `BdpFlowControl`    | Per-tunnel send-window state. Tracks RTT (PING/PONG round-trip) and bandwidth (cumulative-ACK delta) as EWMAs; recomputes the target window as `bdp × safety_factor` clamped to `[min, max]`. In `mode: fixed` the window is pinned to the v0.3.0 value; `mode: bdp` opts in to dynamic sizing. |
| `RateLimiter`       | Per-friend token-bucket layer that runs before `RulesEngine` on TUNNEL_OPEN and (optionally) alongside the data path. Modes: `off | report | enforce`. Hot-reloadable via the rules file. Defaults to `off` (no v0.3.0 behaviour change). |
| `ToxWatchdog`       | Heartbeat-based detector for a stalled `tox_iterate`. The Tox thread bumps the counter on every return; a 1 Hz observer on the main IO context calls `std::abort()` if the deadline is exceeded. Persistent abort count lives at `<data_dir>/abort_count`. |
| `TunnelIdAllocator` | Bitset-backed 1..65535 allocator with a roving cursor and an explicit `reserve(id)` API for the tunnel-resume path. |
| `TunnelResumeStore` | Client-side `<data_dir>/tunnel_resume_state.yaml` persistence (schema-versioned, age-pruned). Wipes itself when the active server's Tox ID changes. Persisted via `util::atomic_write_file`. |
| `atomic_write_file` | Shared helper: write to `<path>.tmp.<pid>`, fsync, rename, optional parent-dir fsync (`F_FULLFSYNC` on macOS). Used by `ToxSave::persist`, `KnownServersStore::save`, and `TunnelResumeStore::save`. |

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
| `TUNNEL_ERROR`  | 0x05  | Error (connect failed, etc.)                      |
| `INFO_REQUEST`  | 0x06  | Client → Server: ask peer for system info (`tunnel_id` = 0, empty payload). Sent once when the friend transitions to online. |
| `INFO_REPLY`    | 0x07  | Server → Client response (`tunnel_id` = 0, UTF-8 YAML map filtered by `server.disclose.*`). Empty payload = "policy is to disclose nothing"; client persists the result to `known_servers.yaml`. Old servers ignore `INFO_REQUEST` — client falls back to locally-observable metadata only. |
| `TUNNEL_RESUME_REQUEST` | 0x08 | Client → Server: fast-reattach a prior tunnel after a server restart. Binary payload: `[version:1=0x01][prior_id:2][recv:8][send:8][host_len:1][host:N][port:2]`. Wire-inactive when `tunnel.resume.enabled: false` (the v0.4.0 default). Old servers ignore unknown opcodes; client times out the resume attempt and falls back to `TUNNEL_OPEN`. |
| `TUNNEL_RESUME_ACK`     | 0x09 | Server → Client: result of the resume attempt. Binary payload: `[version:1=0x01][new_id:2][server_recv:8][server_send:8][status:1]` where `status ∈ {0=Ok, 1=TargetUnreachable, 2=RulesDenied, 3=TooOld, 4=Unknown}`. |
| `PING`          | 0x10  | Keep-alive ping                                   |
| `PONG`          | 0x11  | Keep-alive response                               |

> Every frame is prepended with a single `kLosslessPacketByte` (0xA0) when
> handed to toxcore's lossless custom packet API. ToxTunnel does **not**
> implement remote command execution — `INFO_REPLY` is the only metadata
> channel and the server operator opts in per field.

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
`Socks5Listener`, and the SIGHUP reload watcher — **none of which add new
threads**. All four live entirely on the existing asio I/O pool:

- `MetricsServer` and `InspectServer` are plain asio acceptors with per-connection strands.
- `Socks5Listener` shares the pool with the regular forward listeners.
- SIGHUP is wired through `asio::signal_set` bound to the main `IoContext` on POSIX. On
  Windows there is no SIGHUP — `ConfigReload` watches a named pipe (configurable via
  `service.reload_pipe`) on the same pool.
- `MetricsRegistry` is updated lock-free (atomic increments) from any thread, including
  the Tox thread, without marshalling.

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
| `toxtunnel_tunnels_open` | gauge | Tunnels currently in OPEN state |
| `toxtunnel_tunnels_opened_total` | counter | Cumulative tunnels opened |
| `toxtunnel_tunnels_closed_total{reason}` | counter | Closures, labelled by reason |
| `toxtunnel_bytes_in_total{direction}` | counter | Bytes received on each direction |
| `toxtunnel_bytes_out_total{direction}` | counter | Bytes sent on each direction |
| `toxtunnel_frames_total{type}` | counter | Frames seen, labelled by frame type |
| `toxtunnel_active_friends` | gauge | Friends currently online |
| `toxtunnel_reaper_closed_total` | counter | Tunnels closed by the idle reaper |
| `toxtunnel_reloads_total{result}` | counter | SIGHUP / reload-pipe reloads (success / rejected) |
| `toxtunnel_failover_switchovers_total` | counter | Active-server changes on the client |
| `toxtunnel_tox_self_connection_status` | gauge | Toxcore self-connection enum (0=none, 1=TCP, 2=UDP) |

Bind to loopback if you do not want public scraping; reverse-proxy with TLS +
auth if you do.

### `toxtunnel inspect` IPC

`InspectServer` accepts connections on a local Unix-domain socket (POSIX) or
named pipe (Windows). Default path follows `data_dir/inspect.sock` /
`\\.\pipe\toxtunnel-inspect-<pid>`. **Default-on, loopback-only by
construction** — there is no TCP listener and no auth layer because the OS
permission bits on the socket file are the access control.

Wire format is intentionally trivial:

1. Client opens the socket, writes one JSON request line terminated by `\n`.
2. Server replies with one JSON reply line terminated by `\n`, then closes.

```
> {"cmd": "tunnels"}
< {"ok": true, "tunnels": [{"id": 17, "peer": "AA…", "state": "OPEN", "bytes_in": 4096, "bytes_out": 8192, "idle_seconds": 3.2}]}

> {"cmd": "status"}
< {"ok": true, "mode": "client", "self_tox_id": "…", "uptime_seconds": 1294, "active_server": "primary", "tunnels_open": 4}
```

The CLI subcommands (`toxtunnel inspect tunnels|status|friends|metrics`) are
thin wrappers that compose the JSON request, write it, and pretty-print the
reply. Tooling that wants structured output should call the IPC socket
directly.

### SIGHUP / reload pipe

POSIX: `kill -HUP <pid>` (or `systemctl reload toxtunnel`) is delivered to an
`asio::signal_set` on the main `IoContext`. Windows has no SIGHUP, so the
equivalent path is a named pipe — write a single byte to it, or run
`toxtunnel reload --pipe <path>`.

Either trigger calls `ConfigReload::apply()`, which:

1. Re-reads the original config file.
2. Diffs the parsed result against the live `Config`.
3. **Rejects** the reload (no changes applied) if any non-reloadable field
   changed: `mode`, `data_dir`, `tox.*`, `server.disclose.*`, `client.server_id`,
   `client.failover.*`, `metrics.*`, `inspect.*`, `client.socks5.*`.
4. Otherwise atomically swaps the reloadable subset — `rules_file` contents,
   `client.forwards`, and `logging.level` — under the strand that owns each
   consumer. Existing tunnels are **not** torn down on a successful reload
   unless their friend or destination is no longer allowed by the new rules.

A `Reload applied: …` line is emitted at INFO. A rejected reload emits a
`Reload rejected: field <name> is not reloadable` line at WARN and leaves the
running config untouched.

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

## Operational Endpoints (v0.4 additions)

- `toxtunnel_outbound_buffer_allocs_total` — outbound `OwnedFrameBuffer`
  allocations.
- `toxtunnel_coalesce_policy_transitions_total` — state-machine moves
  between adaptive policies.
- `toxtunnel_tunnel_rtt_microseconds`, `_send_window_bytes`, and
  `_bandwidth_bytes_per_second` — summaries from `BdpFlowControl`.
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
      tox_thread.hpp
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
    unit/                       # Unit tests (232 tests)
    integration/                # Integration tests (41 tests)
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
