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
| Application | `TunnelServer`, `TunnelClient`, `RulesEngine` |
| TCP I/O | `IoContext`, `TcpConnection`, `TcpListener` |
| Tox | `ToxAdapter`, `ToxConnection`, `ToxThread` |
| Tunnel | `Tunnel`, `TunnelManager`, `ProtocolFrame` |
| Util | `QrCode`, `WindowsService`, `SystemdNotify`, `Config`, `Logger` |

### Threading Model

- **I/O thread pool** — async TCP via asio
- **Dedicated Tox thread** — all toxcore API calls funnel through one thread; **toxcore is not thread-safe**, so cross-thread calls must marshal through `ToxThread`
- **Main thread** — signal handling and orchestration

### Protocol

Binary framing over Tox lossless custom packets. Header: `[type:1][tunnel_id:2][length:2]`.

Frame types: `TUNNEL_OPEN`, `TUNNEL_DATA`, `TUNNEL_CLOSE`, `TUNNEL_ACK`, `TUNNEL_ERROR`,
`PING`, `PONG`, `INFO_REQUEST` (0x06), `INFO_REPLY` (0x07).

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
cli/main.cpp         # CLI entry (subcommands: print-id, servers, install-windows-service; --service flag)
tests/unit/          # Unit tests (~265 tests)
tests/integration/   # Integration tests (~41 tests)
tests/packaging/     # Package-layout tests (run via ctest)
third_party/c-toxcore/   # Git submodule — required for build
cmake/Packaging.cmake    # CPack configuration
packaging/{linux,macos,windows}/   # Service units, installer scripts, MSI/WIX fragments
docs/                # ARCHITECTURE.md, CONFIGURATION.md, BUILDING.md, scenario guides
```

## Dependencies

- **c-toxcore** — git submodule, built from source (`git clone --recursive` or `git submodule update --init`)
- **asio, spdlog, CLI11, yaml-cpp** — fetched via CMake FetchContent
- **qrcodegen** (Nayuki) — fetched via FetchContent, used for terminal QR output
- **libsodium** — system package (required by toxcore)
- **Google Test** — fetched via FetchContent (test builds only)
