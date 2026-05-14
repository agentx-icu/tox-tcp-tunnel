# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Standard build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Parallel build
cmake --build build -j$(nproc)        # Linux
cmake --build build -j$(sysctl -n hw.ncpu)  # macOS

# Debug build with AddressSanitizer
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTOXTUNNEL_ENABLE_ASAN=ON
cmake --build build
```

## Running Tests

```bash
# Run all tests via CTest
cd build && ctest --output-on-failure

# Run unit tests directly
./build/tests/unit_tests

# Run integration tests directly
./build/tests/integration_tests

# Run specific test with Google Test filter
./build/tests/unit_tests --gtest_filter=ConfigTest*
./build/tests/integration_tests --gtest_filter=TunnelDataFlowTest*
```

## Packaging

```bash
# Build platform-native packages (DEB/RPM on Linux, .pkg on macOS, WIX/MSI on Windows)
cd build && cpack

# Build specific format
cd build && cpack -G DEB
cd build && cpack -G RPM
cd build && cpack -G productbuild   # macOS .pkg
cd build && cpack -G WIX            # Windows MSI installer

# Inspect package contents
dpkg -c build/*.deb                 # DEB
rpm -qlp build/*.rpm                # RPM
```

CPack configuration lives in `cmake/Packaging.cmake`. Packaging assets are under `packaging/`.

## Installation (from packages)

### One-line install

```bash
# macOS / Linux (server default; pass `--mode client` for client scaffold)
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh -s -- --mode client
```

```powershell
# Windows (Administrator PowerShell)
irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex
$env:TOXTUNNEL_MODE='client'; irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex
```

`scripts/install.sh` and `scripts/install.ps1` auto-detect arch, download the
matching native package from GitHub Releases (`-latest` alias), install it, and
seed `config.yaml` based on `--mode`. Client mode writes a config scaffold and
leaves the system service idled (exit 0) until the user fills in
`client.server_id` and sets `service.allow_client_daemon: true`.

### Manual download

Each release publishes both versioned and stable `-latest` aliases. Pull the
latest assets from
`https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-<System>-<arch>-latest.<ext>`
where `<System>` is `Linux` / `Darwin` / `Windows` and `<ext>` is `deb` / `rpm` / `pkg` / `msi`.

### Linux (DEB/RPM)

```bash
sudo dpkg -i toxtunnel-*.deb         # or: sudo rpm -i toxtunnel-*.rpm
sudo systemctl start toxtunnel       # Usually unnecessary (postinst enables + starts)
sudo systemctl enable toxtunnel      # Enable on boot (no-op if postinst already did this)
```

Postinst seeds `/etc/toxtunnel/config.yaml` from `config.yaml.example` if absent,
creates the `toxtunnel` system user, reloads systemd, and runs `systemctl enable --now`.

Packaged server configs seed `service.auto_start: true`; client-oriented configs default to an idle
service unless `service.allow_client_daemon` is enabled — see `packaging/config.yaml.example`.

### macOS

```bash
sudo installer -pkg toxtunnel-*.pkg -target /

# The .pkg installs the launchd plist under /Library/LaunchDaemons and bootstraps it.
# You still need to seed /usr/local/etc/toxtunnel/config.yaml:
sudo mkdir -p /usr/local/etc/toxtunnel
sudo cp /usr/local/share/toxtunnel/config.yaml.example /usr/local/etc/toxtunnel/config.yaml
```

Binary: `/usr/local/bin/toxtunnel`. Example config: `/usr/local/share/toxtunnel/config.yaml.example`.

### Windows

Run the MSI installer as Administrator. It installs into `C:\Program Files\ToxTunnel\` and registers
the **ToxTunnel** Windows service to run `toxtunnel.exe --service` with
`-c C:\ProgramData\ToxTunnel\config.yaml`.

Create the config before relying on the service:

```powershell
mkdir 'C:\ProgramData\ToxTunnel'
notepad 'C:\ProgramData\ToxTunnel\config.yaml'

sc start ToxTunnel
```

Optional manual registration/repair:

```powershell
& 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' install-windows-service -c 'C:\ProgramData\ToxTunnel\config.yaml'
```

## Known-Servers Registry (client side)

Client persists every server it connects to under
`<data_dir>/known_servers.yaml`: tox_id, optional alias, first/last connection
timestamps, transport (UDP direct vs TCP relay), and any system info the
server explicitly opted into via `server.disclose.*`.

```bash
toxtunnel servers list                  # list with short Tox IDs
toxtunnel servers list --full           # show full 76-char Tox IDs
toxtunnel servers show <alias_or_id>    # full record incl. disclosed info
toxtunnel servers add <alias> <tox_id>  # register an alias
toxtunnel servers remove <alias_or_id>  # forget
```

After `servers add homelab DE47F2...`, both `--server-id homelab` and
`client.server_id: homelab` resolve from the registry at startup.

Server-side disclosure is opt-in per field (defaults all `false`). Set under
`server.disclose:` in YAML — see README.md for the full list of fields.
Protocol additions: `INFO_REQUEST` (0x06) sent by client on friend-online,
`INFO_REPLY` (0x07) returned by server filtered by its disclose policy. There
is no remote command execution; only the metadata the server publishes.

## Code Style

- Google style with 4-space indentation, 100-character column limit
- Run `clang-format` before committing
- Compiler warnings are treated as errors (`-Werror`)
- C++20 standard

## Architecture

ToxTunnel forwards TCP ports through the Tox P2P network with end-to-end encryption.

```
CLI/Config Layer → Application Layer (TunnelServer/TunnelClient/RulesEngine)
                              ↓
              TCP I/O Layer (asio)  |  Tox Layer (dedicated thread)
```

### Key Components

| Layer | Components |
|-------|------------|
| Application | `TunnelServer`, `TunnelClient`, `RulesEngine` |
| TCP I/O | `IoContext`, `TcpConnection`, `TcpListener` |
| Tox | `ToxAdapter`, `ToxConnection`, `ToxThread` |
| Tunnel | `Tunnel`, `TunnelManager`, `ProtocolFrame` |
| Util | `QrCode`, `WindowsService`, `SystemdNotify`, `Config`, `Logger` |

### Threading Model

- **I/O thread pool**: Async TCP operations via asio
- **Dedicated Tox thread**: Single thread for all toxcore API calls (toxcore is not thread-safe)
- **Main thread**: Signal handling and orchestration

### Protocol

Binary framing over Tox lossless custom packets:
- Header: `[type:1][tunnel_id:2][length:2]`
- Frame types: `TUNNEL_OPEN`, `TUNNEL_DATA`, `TUNNEL_CLOSE`, `TUNNEL_ACK`, `TUNNEL_ERROR`, `PING`, `PONG`

## Project Structure

```
include/toxtunnel/   # Headers organized by layer (core/, tox/, tunnel/, app/, util/)
src/                 # Implementations mirroring include/ structure
cli/main.cpp         # CLI entry point (print-id subcommand, --service flag)
tests/unit/          # Unit tests (232 tests)
tests/integration/   # Integration tests (41 tests)
third_party/c-toxcore/  # Git submodule
cmake/Packaging.cmake   # CPack configuration
packaging/              # Platform-specific packaging assets
  linux/                #   systemd unit, postinst/prerm scripts
  macos/                #   launchd plist, pkg postinstall script
```

## Dependencies

- **c-toxcore**: Git submodule, built from source
- **asio, spdlog, CLI11, yaml-cpp**: Fetched via CMake FetchContent
- **qrcodegen** (Nayuki): Fetched via FetchContent, used for terminal QR code output
- **libsodium**: System package (required by toxcore)
- **Google Test**: Fetched via FetchContent (test builds only)
