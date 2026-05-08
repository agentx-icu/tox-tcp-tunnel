# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

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
```

CPack configuration lives in `cmake/Packaging.cmake`. Packaging assets are under `packaging/`.

## Installation (from packages)

Each release publishes both versioned and stable `-latest` aliases. Pull the
latest assets from
`https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-<System>-<arch>-latest.<ext>`
where `<System>` is `Linux` / `Darwin` / `Windows` and `<ext>` is `deb` / `rpm` / `pkg` / `msi`.

### Linux (DEB/RPM)

```bash
sudo dpkg -i toxtunnel-*.deb         # or: sudo rpm -i toxtunnel-*.rpm
sudo systemctl start toxtunnel       # Start service (postinst already enables it)
sudo systemctl enable toxtunnel      # Enable on boot (no-op if postinst already did this)
```

Postinst seeds `/etc/toxtunnel/config.yaml` from `config.yaml.example` if absent,
creates the `toxtunnel` system user, and enables the unit.

Config: `/etc/toxtunnel/config.yaml`, data: `/var/lib/toxtunnel`, binary: `/usr/bin/toxtunnel`.

### macOS

```bash
sudo installer -pkg toxtunnel-*.pkg -target /

# The .pkg does NOT seed a config or load the launchd job — do that manually:
sudo mkdir -p /usr/local/etc/toxtunnel
sudo cp /usr/local/share/toxtunnel/config.yaml.example /usr/local/etc/toxtunnel/config.yaml
sudo cp /usr/local/share/toxtunnel/com.toxtunnel.daemon.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.toxtunnel.daemon.plist
```

Binary: `/usr/local/bin/toxtunnel`. Example config: `/usr/local/share/toxtunnel/config.yaml.example`.

### Windows

Run the MSI installer as Administrator. It installs files into `C:\Program Files\ToxTunnel\`.
The MSI does NOT register a Windows service or seed a config — register the service manually
after writing a config file:

```powershell
mkdir 'C:\ProgramData\ToxTunnel'
notepad 'C:\ProgramData\ToxTunnel\config.yaml'

sc create ToxTunnel binPath= "\"C:\Program Files\ToxTunnel\bin\toxtunnel.exe\" -c \"C:\ProgramData\ToxTunnel\config.yaml\" --service" start= auto
sc start ToxTunnel
```

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
  macos/                #   launchd plist
```

## Dependencies

- **c-toxcore**: Git submodule, built from source
- **asio, spdlog, CLI11, yaml-cpp**: Fetched via CMake FetchContent
- **qrcodegen** (Nayuki): Fetched via FetchContent, used for terminal QR code output
- **libsodium**: System package (required by toxcore)
- **Google Test**: Fetched via FetchContent (test builds only)
