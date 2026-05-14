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
