# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Standard build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Parallel build
cmake --build build -j$(nproc)              # Linux
cmake --build build -j$(sysctl -n hw.ncpu)  # macOS

# Debug build with AddressSanitizer
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTOXTUNNEL_ENABLE_ASAN=ON
cmake --build build
```

## Running Tests

```bash
# Run all tests via CTest
cd build && ctest --output-on-failure

# Run unit / integration binaries directly
./build/tests/unit_tests
./build/tests/integration_tests

# Filter to a single test or fixture
./build/tests/unit_tests --gtest_filter=ConfigTest*
./build/tests/integration_tests --gtest_filter=TunnelDataFlowTest*
```

## Packaging

```bash
# Build platform-native packages (DEB/RPM on Linux, .pkg on macOS, WIX/MSI on Windows)
cd build && cpack

# Build a specific format
cd build && cpack -G DEB
cd build && cpack -G RPM
cd build && cpack -G productbuild   # macOS .pkg
cd build && cpack -G WIX            # Windows MSI

# Inspect package contents
dpkg -c build/*.deb
rpm -qlp build/*.rpm
```

CPack configuration lives in `cmake/Packaging.cmake`; platform assets are under
`packaging/{linux,macos,windows}/`. End-user install instructions (one-line
installers, per-platform packages, service setup) live in `README.md` —
prefer linking there rather than duplicating here.

## Code Style

- Google style, 4-space indentation, 100-column limit
- Run `clang-format` before committing
- Warnings are errors (`-Werror`)
- C++20

## Architecture

ToxTunnel forwards TCP ports through the Tox P2P network with end-to-end encryption.

```
CLI/Config Layer → Application Layer (TunnelServer / TunnelClient / RulesEngine)
                              ↓
              TCP I/O Layer (asio)  |  Tox Layer (dedicated thread)
```

Deep architecture detail (data flow diagrams, lifecycle, error paths) lives in
`docs/ARCHITECTURE.md` — extend that file for non-trivial design changes rather
than expanding this section.

### Key Components

| Layer | Components |
|-------|------------|
| Application | `TunnelServer`, `TunnelClient`, `RulesEngine`, `InspectServer`, `Socks5Listener`, `RateLimiter`, `TunnelResumeStore` |
| TCP I/O | `IoContext`, `TcpConnection`, `TcpListener`, `OwnedBuffer` |
| Tox | `ToxAdapter`, `ToxConnection`, `ToxThread`, `ToxWatchdog` |
| Tunnel | `Tunnel`, `TunnelManager`, `ProtocolFrame`, `OwnedFrameBuffer`, `WriteCoalescer`, `BdpFlowControl`, `TunnelIdAllocator` |
| Util | `QrCode`, `WindowsService`, `SystemdNotify`, `Config`, `config_reload`, `MetricsRegistry`, `MetricsServer`, `Logger`, `atomic_write_file` |

`TunnelClient` owns a `FailoverConfig`-driven state machine that promotes/demotes
between primary and fallback Tox IDs. `InspectServer` accepts local IPC
(Unix socket at `<data_dir>/toxtunnel.sock`; Windows named pipe
`\\.\pipe\toxtunnel-inspect-<pid>`) and serves JSON snapshots gathered via the
`InspectProviders` struct. `config_reload` computes the reloadable diff
(rules, forwards, log level) between an on-disk YAML and the live config.

### Threading Model

- **I/O thread pool** — async TCP via asio; `MetricsServer`, `InspectServer`,
  and `Socks5Listener` all run on this same `IoContext` (no new threads)
- **Dedicated Tox thread** — all toxcore API calls funnel through one thread; **toxcore is not thread-safe**, so cross-thread calls must marshal through `ToxThread`
- **Main thread** — signal handling (`SIGHUP` triggers `config_reload`) and orchestration
- **Windows reload pipe thread** — Windows lacks `SIGHUP`; a small dedicated
  thread serves `\\.\pipe\toxtunnel-reload-<pid>` and posts reload onto the
  signal `io_context`

### Protocol

Binary framing over Tox lossless custom packets. Header: `[type:1][tunnel_id:2][length:2]`.

Frame types: `TUNNEL_OPEN`, `TUNNEL_DATA`, `TUNNEL_CLOSE`, `TUNNEL_ACK`, `TUNNEL_ERROR`,
`PING`, `PONG`, `INFO_REQUEST` (0x06), `INFO_REPLY` (0x07),
`TUNNEL_RESUME_REQUEST` (0x08), `TUNNEL_RESUME_ACK` (0x09).

The resume opcodes are wire-inactive when `tunnel.resume.enabled: false` (the
v0.4.0 default); v0.3.0 peers see no behavioural change. Wiring the live
resume handshake into the data flow is tracked separately — see
`docs/plans/2026-05-15-tunnel-resume-protocol-partial.md`.

`INFO_REQUEST` / `INFO_REPLY` carry only the metadata the server has explicitly
opted into via `server.disclose.*` (all fields default to `false`). There is **no**
remote command execution — disclosure is the only metadata channel. Servers that
predate these opcodes ignore unknown frames, and the client falls back to
local-only metadata.

## Known-Servers Registry

The client persists every server it connects to at `<data_dir>/known_servers.yaml`
(tox_id, optional alias, first/last seen, last transport, any server-disclosed info).
After `toxtunnel servers add <alias> <tox_id>`, both `--server-id` and
`client.server_id` accept the alias. Full user-facing CLI reference is in `README.md`.

## Project Structure

```
include/toxtunnel/   # Headers organized by layer: core/, tox/, tunnel/, app/, util/
src/                 # Implementations mirroring include/
cli/main.cpp         # CLI entry (subcommands: print-id, servers, inspect, reload,
                     #            install-windows-service; --service / --socks5 /
                     #            --server-id-fallback flags)
tests/unit/          # Unit tests
tests/integration/   # Integration tests
tests/packaging/     # Package-layout tests (run via ctest)
tests/soak/          # Long-running soak fixtures (ctest -L soak)
tests/chaos/         # Chaos / fault-injection fixtures (ctest -L chaos)
                     # Total test count: ~493 across all suites.
third_party/c-toxcore/   # Git submodule — required for build
cmake/Packaging.cmake    # CPack configuration
packaging/{linux,macos,windows}/   # Service units, installer scripts, MSI/WIX fragments
docs/                # ARCHITECTURE.md, CONFIGURATION.md, BUILDING.md, scenario guides
```

## v0.3.0 Default Behavior (read before changing config defaults)

- **Inspect IPC** — `inspect.enabled: true` by default. Listener is local-only
  (Unix socket / Windows named pipe, never TCP). Disable per-host by setting
  `inspect.enabled: false`.
- **Metrics** — `metrics.enabled: false` by default (opt-in). When enabled,
  binds `127.0.0.1:9100` and serves `GET /metrics` only; other paths 404.
- **SOCKS5 / HTTP CONNECT** — `client.socks5.enabled: false` by default.
  When enabled, **loopback binds only** are accepted (the listener rejects
  non-loopback listen addresses at startup).
- **Idle tunnel reaper** — `tunnel.idle_timeout_seconds: 0` means disabled by
  default. Setting any positive value enables the reaper, which ticks every
  `tunnel.reaper_tick_seconds` (default 10).
- **Write coalescing** — on by default with safe values:
  `tunnel.coalesce_max_delay_us = 200`, `tunnel.coalesce_max_bytes = 1362`
  (one Tox-MTU worth). Set delay to 0 to disable.
- **Multi-server failover** — engaged whenever `client.server_id` resolves to
  more than one ID (`server_id` may itself be a YAML list, plus optional
  `client.fallback_server_ids`). `FailoverConfig` controls timing.
  The client prefers the primary (index 0) once it has been continuously
  online for `prefer_primary_grace_seconds`.
- **Hot-reload scope** — `SIGHUP` (POSIX) / `toxtunnel reload` (Windows
  named-pipe IPC) reloads only: `server.rules_file` contents,
  `client.forwards`, and `logging.level`. Everything else requires a restart.

## v0.4.0 Default Behavior (additions on top of v0.3.0)

- **Outbound zero-copy (Wave B)** — `OwnedFrameBuffer` carries the
  TUNNEL_DATA wire bytes from the TCP read into the toxcore lossless send
  in a single allocation. Wire format unchanged.
- **Adaptive coalescing** — `tunnel.coalesce_mode: fixed` is the default
  (v0.3.0 behaviour). Other options: `adaptive` (EWMA state machine that
  selects between `bypass`, `drain`, `batch` per tunnel), `bypass` (no
  hold ever), `drain` (emit on overflow only). Non-reloadable.
- **BDP-aware flow control** — `flow_control.mode: fixed` (default;
  256 KiB window / 16 KiB ACK). `flow_control.mode: bdp` opts in to a
  per-tunnel `BdpFlowControl` that resizes the window from RTT × bandwidth
  EWMA. Non-reloadable.
- **Per-friend rate limiting** — absent from `rules.yaml` means no
  limiting (v0.3.0 behaviour). When `rate_limit_defaults:` or a per-friend
  `rate_limit:` block is present, `RateLimiter` runs before `RulesEngine`
  on the TUNNEL_OPEN path. Modes: `off | report | enforce`.
- **Tox-thread watchdog** — `watchdog.enabled: true` by default. The
  Tox thread bumps a heartbeat after every `tox_iterate` return; a
  1 Hz observer on the main `IoContext` calls `std::abort()` if the
  deadline (default 30 s, min 5 s) is exceeded. systemd / launchd
  handles the restart. Persisted abort count in
  `<data_dir>/abort_count`.
- **Atomic writes** — `tox_save.dat` and `known_servers.yaml` go through
  `util::atomic_write_file` (tmp + fsync + rename, plus parent-dir
  fsync; `F_FULLFSYNC` on macOS for the identity file).
- **Tunnel resume** — `tunnel.resume.enabled: false` by default. New
  opcodes `0x08 / 0x09` are wire-inactive in that mode. Driver wiring
  is partial in v0.4.0; see
  `docs/plans/2026-05-15-tunnel-resume-protocol-partial.md`.

## Dependencies

- **c-toxcore** — git submodule, built from source (`git clone --recursive` or `git submodule update --init`)
- **asio, spdlog, CLI11, yaml-cpp** — fetched via CMake FetchContent
- **qrcodegen** (Nayuki) — fetched via FetchContent, used for terminal QR output
- **libsodium** — system package (required by toxcore)
- **Google Test** — fetched via FetchContent (test builds only)
