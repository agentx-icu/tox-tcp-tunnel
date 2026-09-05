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
- Run `clang-format` before committing. CI pins **clang-format 20.1.6**
  (`.github/workflows/ci.yml` installs `clang-format==20.1.6` from PyPI); match
  it locally so `clang-format --version` reports exactly `20.1.6`
  (`pip install clang-format==20.1.6` is the reliable pin; a Homebrew `llvm`
  may float within LLVM 20) — other versions disagree on edge cases (e.g.
  `struct flock fl{}` spacing, empty-body block collapsing) and will fail the
  `code-style-check` job
- Warnings are errors (`-Werror`)
- C++20

## Mandatory Independent Review (codex)

Every non-trivial change — bug fix, feature, refactor, CI/packaging change —
MUST get an independent second opinion from OpenAI Codex **before commit/PR**
(via the `/codex` skill or `codex exec`):

1. Send the complete diff plus a root-cause/intent summary and explicit
   questions to challenge (not just "review this").
2. Address every finding, then run a **second pass on the final diff** —
   code written after the first review (including implementations of
   codex's own suggestions) is unreviewed until codex has seen it.
3. Record the verdict and findings-addressed in the PR description.

Exempt: typo/comment/doc-only edits. When in doubt, review.

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
| Application | `TunnelServer`, `TunnelClient`, `RulesEngine`, `InspectServer`, `Socks5Listener`, `RateLimiter` |
| TCP I/O | `IoContext`, `TcpConnection`, `TcpListener`, `OwnedBuffer` |
| Tox | `ToxAdapter` (owns the iterate thread), `ToxConnection`, `ToxWatchdog`. NOTE: `ToxAdapter` owns the **only** Tox event loop — wire all new tox-thread work into it. |
| Tunnel | `Tunnel`, `TunnelManager`, `ProtocolFrame`, `OwnedFrameBuffer`, `WriteCoalescer`, `BdpFlowControl`, `TunnelIdAllocator` |
| Util | `QrCode`, `WindowsService`, `SystemdNotify`, `Config`, `config_reload`, `MetricsRegistry`, `MetricsServer`, `Logger`, `atomic_write_file`, `PidFileGuard` |

`TunnelClient` owns a `FailoverConfig`-driven state machine that promotes/demotes
between primary and fallback Tox IDs. `InspectServer` accepts local IPC
(Unix socket at `<data_dir>/toxtunnel.sock`; Windows named pipe
`\\.\pipe\toxtunnel-<pid>`, DACL = daemon user + SYSTEM + Administrators) and
serves JSON snapshots gathered via the `InspectProviders` struct. The daemon
publishes its pid in `<data_dir>/toxtunnel.pid` (`util::PidFileGuard`, constructed
**before** `initialize()` — it doubles as the data-dir lock, and `initialize()`
already opens `tox_save.dat` and the inspect socket, none of
which two daemons may share; removed on clean exit) — that is how `toxtunnel inspect`
finds the pipe on Windows and how `toxtunnel reload` finds the process on both
platforms (POSIX sends SIGHUP; a stale pid is refused via `pid_is_toxtunnel`). `config_reload` computes the reloadable diff
(rules, forwards, log level) between an on-disk YAML and the live config.

### Threading Model

- **I/O thread pool** — async TCP via asio; `MetricsServer` and `Socks5Listener`
  run on this same `IoContext` (no new threads). `InspectServer` does too on
  POSIX; on Windows it owns one dedicated named-pipe thread
- **Dedicated Tox thread** — all toxcore API calls funnel through one thread owned by `ToxAdapter` (`iterate_thread_id_`); **toxcore is not thread-safe**, so cross-thread calls marshal through `ToxAdapter`'s task queue (`process_tox_tasks`)
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
default); v0.3.0 peers see no behavioural change. When enabled, the handshake is
live: the server holds a disconnected friend's tunnels (and their target TCP
connections) for `tunnel.resume.max_age_seconds` and reattaches them on
reconnect, while the client re-sends `TUNNEL_RESUME_REQUEST` per surviving tunnel
and reconciles byte offsets. There is no app-level retransmit buffer, so any gap
(bytes lost in the disconnect) is handled by `tunnel.resume.on_gap`
(`close` = drop the tunnel, `passthrough` = continue with a logged hole). Resume
covers the live-reconnect case only (both processes stay up); it cannot survive a
process restart, since the local TCP sockets do not.

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
tests/packaging/     # Package-layout verification scripts (run by packaging CI)
tests/soak/          # Bounded smoke tests (bare ctest or ctest -L soak)
tests/chaos/         # Bounded fault-injection smoke test (bare ctest or ctest -L chaos)
                     # Total test count: ~525 across all suites.
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
  `tunnel.reaper_tick_seconds` (default 10). The reaper is wired into both
  `TunnelServer` (per-friend manager) and `TunnelClient`; it reaps any
  non-`Connecting` tunnel idle (no TUNNEL_DATA either direction) past the
  timeout.
- **Write coalescing** — on by default with safe values:
  `tunnel.coalesce_max_delay_us = 200`, `tunnel.coalesce_max_bytes = 1362`
  (one Tox-MTU worth). Set delay to 0 to disable.
- **Multi-server failover** — engaged whenever `client.server_id` resolves to
  more than one ID (`server_id` may itself be a YAML list, plus optional
  `client.fallback_server_ids`). `FailoverConfig` controls timing.
  The client prefers the primary (index 0) once it has been continuously
  online for `prefer_primary_grace_seconds`.
- **Hot-reload scope** — `SIGHUP` (POSIX) / `toxtunnel reload` (any platform:
  SIGHUP via the pid file on POSIX, named-pipe IPC on Windows) reloads only: `server.rules_file` contents,
  `client.forwards`, and `logging.level`. Everything else requires a restart.

## v0.4.0 Default Behavior (additions on top of v0.3.0)

- **Outbound zero-copy (Wave B)** — `OwnedFrameBuffer` carries the
  TUNNEL_DATA wire bytes from the TCP read into the toxcore lossless send
  in a single allocation. Wire format unchanged.
- **Adaptive coalescing** — `tunnel.coalesce_mode: fixed` is the default
  (v0.3.0 behaviour). Other options: `adaptive` (EWMA state machine that
  selects between `bypass`, `drain`, `batch` per tunnel), `bypass` (no
  hold ever), `drain` (emit on overflow only). Non-reloadable.
- **BDP-aware flow control** — `flow_control.mode: bdp` is the default
  since v0.4.1. The per-tunnel `BdpFlowControl` starts at the fixed
  256 KiB seed window and dynamically resizes it (between 64 KiB and 4 MiB)
  from RTT × bandwidth EWMA samples fed by `handle_tunnel_ack_frame`.
  Set `flow_control.mode: fixed` to lock to the legacy v0.3.0 behaviour.
  Non-reloadable.
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
  fsync; `F_FULLFSYNC` on macOS for the identity file). Parent-dir
  computation is deliberately **string-based** (`parent_dir_of`), never
  `fs::path::parent_path()` — the manylinux devtoolset toolchain
  mis-parses path components (v0.4.8 shipped Linux binaries that created
  `tox_save.dat` as a directory and lost the identity every restart; the
  release containers are manylinux_2_28 since v0.4.9 for the same
  reason). An empty directory squatting on the target is rmdir'd before
  writing (self-heals 0.4.8-damaged data dirs). A present-but-unreadable
  save file aborts startup instead of minting a fresh identity.
- **Tunnel resume** — `tunnel.resume.enabled: false` by default (opcodes
  `0x08 / 0x09` wire-inactive in that mode). When enabled the live
  hold-across-reconnect handshake runs: the server holds a disconnected
  friend's manager (tunnels + target TCPs) for `resume.max_age_seconds`
  and resurrects it on reconnect; the client re-sends `TUNNEL_RESUME_REQUEST`
  for surviving tunnels and reconciles offsets, with gaps handled per
  `resume.on_gap` (`close` / `passthrough`). Live-reconnect only — does not
  survive a process restart (local TCP sockets are lost).
- **Application keepalive** — `tunnel.keepalive_interval_seconds: 0`
  (disabled) by default. When >0, each peer is PINGed every interval and
  declared dead after 3× of no PONG: the server drops that friend's tunnels;
  the client marks the active server offline so failover promotes a fallback.
  Catches an application that is wedged while its toxcore link still looks
  alive (toxcore's own connection tracking covers transport-level death).
- **Half-close linger cap** — `tunnel.half_close_timeout_seconds: 120` by
  default (0 disables). After a one-sided TCP close a tunnel sits in
  `Disconnecting` awaiting the peer's reciprocal `TUNNEL_CLOSE`; if the peer
  abandons its socket without closing, the tunnel would otherwise pin a
  half-open fd forever. The cap force-closes any `Disconnecting` tunnel idle
  past the timeout (analogous to Linux `tcp_fin_timeout`). It shares the
  reaper's maintenance timer but is a distinct, on-by-default policy — the
  general idle reaper above stays opt-in. Paused on a resume-hold, re-armed on
  resurrection.

## v0.5.0 Default Behavior (additions on top of v0.4.x)

- **Open handshake deadline** — `tunnel.open_timeout_seconds: 30` by
  default (0 disables). Client-side: a tunnel whose TUNNEL_OPEN gets no
  OPEN_ACK in time is closed through the handshake-close path and counted
  under `tunnels_opened_total{result="failed"}`; failed opens are now
  counted at all (issue #36).
- **Fixed DHT UDP port** — `tox.udp_port: 0` by default (toxcore's
  33445..33545 walk). Non-zero binds exactly that port (issue #32).
- **Bootstrap retry** — while not DHT-connected, `ToxAdapter` re-contacts
  its node list on a 10 s–5 min backoff and re-fetches the public list
  when it has none (worker thread; only the Tox thread touches toxcore).
  `inspect status` reports `dht_connected`; `/metrics` exports
  `toxtunnel_dht_connected` (issue #34).
- **Abnormal target end** — a target reset / transport error after the
  tunnel is established is `TUNNEL_ERROR` code 4; the client answers with a
  local RST (`TcpConnection::abort()`), and a declined resume ends the tunnel
  through `TunnelImpl::fail_locally()` instead of a clean close (issue #35).
- **Close bookkeeping** — `tunnels_closed_total` is booked once per tunnel
  (`book_close_once`); a half-close no longer counts. Manager removal after a
  tunnel's own graceful completion drains the local socket
  (`force_close(ResourceRelease::DrainIfClosed)`) instead of discarding queued
  writes, the pre-ACK peer-close watch keeps banked bytes and reports the
  FIN after replaying them, and `TcpConnection::shutdown_send()` now takes
  effect in strand order (the request flag is raised on the strand, not at
  call time) so a peer CLOSE can no longer FIN the local socket ahead of
  DATA writes still queued behind it — the actual field mechanism of the
  1362-byte-aligned truncation (issue #33).
- **Watchdog confirmation** — the abort requires 5 consecutive over-deadline
  checks with no heartbeat progress, and a check after which the observer
  itself was stalled past the deadline is discarded (host sleep / VM pause
  immunity, issue #38). The critical line names the Tox thread's phase.
- **Windows service** — `install-windows-service` updates an existing
  registration in place; the daemon re-applies the restart-on-failure policy
  at every service start if it is missing.

## Dependencies

- **c-toxcore** — git submodule, built from source (`git clone --recursive` or `git submodule update --init`)
- **asio, spdlog, CLI11, yaml-cpp** — fetched via CMake FetchContent
- **qrcodegen** (Nayuki) — fetched via FetchContent, used for terminal QR output
- **libsodium** — system package (required by toxcore)
- **Google Test** — fetched via FetchContent (test builds only)
