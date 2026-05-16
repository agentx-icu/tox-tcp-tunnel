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
