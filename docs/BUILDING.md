# Building ToxTunnel

> **Most users do not need to build from source.** Released `.deb` / `.rpm` /
> `.pkg` / `.msi` packages are published for every tag, and the one-line
> installers handle download + install + service registration:
>
> ```bash
> # macOS / Linux
> curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh
> ```
>
> ```powershell
> # Windows (Administrator PowerShell)
> irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex
> ```
>
> Build from source when you need: a non-released git revision, a custom
> compile flag, a cross-compile target, or development on the daemon itself.

## Prerequisites

| Dependency   | Version                           | Notes                                                      |
| ------------ | --------------------------------- | ---------------------------------------------------------- |
| C++ compiler | GCC 10+, Clang 13+, or MSVC 2019+ | Must support C++20                                         |
| CMake        | 3.16+                             | Build system generator                                     |
| git          | any                               | For cloning and submodules                                 |
| pkg-config   | any                               | Required by c-toxcore's build (not needed on Windows/MSVC) |
| libsodium    | any                               | Cryptography library, required by c-toxcore                |

toxcore is included as a git submodule and built from source. Other C++ dependencies (asio, spdlog, CLI11, yaml-cpp, googletest) are fetched automatically by CMake.

## Platform-Specific Instructions

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install dependencies via Homebrew
brew install cmake pkg-config libsodium

# Clone and build
git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(sysctl -n hw.ncpu)
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential cmake git pkg-config libsodium-dev

git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

`build-essential` provides GCC with C++20 support on Ubuntu 22.04+ / Debian 12+.

### Fedora / RHEL

```bash
sudo dnf install -y gcc-c++ cmake git pkgconf-pkg-config libsodium-devel

git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Arch Linux

```bash
sudo pacman -S --needed base-devel cmake git pkgconf libsodium

git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Windows

#### Option A: MSVC + vcpkg

1. Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with "Desktop development with C++" workload.
2. Install [CMake](https://cmake.org/download/).
3. Install [vcpkg](https://github.com/microsoft/vcpkg) and libsodium:

```powershell
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install libsodium:x64-windows      # for x86_64
.\vcpkg install libsodium:arm64-windows    # for aarch64
```

Build with vcpkg toolchain:

```powershell
git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

#### Option B: MSYS2 / MinGW-w64

1. Install [MSYS2](https://www.msys2.org/).
2. Open MSYS2 UCRT64 shell:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-pkg-config mingw-w64-ucrt-x86_64-libsodium git

git clone --recursive https://github.com/anonymoussoft/tox-tcp-tunnel.git
cd tox-tcp-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## CMake Options

| Option                         | Default | Description                            |
| ------------------------------ | ------- | -------------------------------------- |
| `TOXTUNNEL_BUILD_TESTS`        | `ON`    | Build unit and integration tests       |
| `TOXTUNNEL_ENABLE_ASAN`        | `OFF`   | Enable AddressSanitizer (debug builds) |
| `TOXTUNNEL_WARNINGS_AS_ERRORS` | `ON`    | Treat compiler warnings as errors      |

## Running Tests

```bash
./build/tests/unit_tests
./build/tests/integration_tests

# Or via CTest
cd build && ctest --output-on-failure
```

The throughput benchmarks are compiled into the integration binary but are
disabled under normal CTest runs so CI stays quick. Run them explicitly when
touching the tunnel data path:

```bash
./build/tests/integration_tests --gtest_also_run_disabled_tests \
    --gtest_filter='TunnelDataFlowTest.*Throughput'
```

For release candidates or data-path fixes, also run one local end-to-end check:
start a server and client with separate `data_dir`s, allow the client's
64-character public key in `rules.yaml`, then exercise SSH and a bulk transfer
through the forwarded port. Use `toxtunnel print-id --data-dir <dir>` when you
need the Tox address for a non-default identity; `print-id` does not read
`-c/--config`.

On Windows with MSVC:

```powershell
.\build\tests\Release\unit_tests.exe
.\build\tests\Release\integration_tests.exe
```

## Docker Build

### Quick Build

```bash
docker build -t toxtunnel .
docker run --rm toxtunnel --help
```

The resulting image is ~120MB.

### Multi-Architecture Build

```bash
docker buildx create --name multiarch --use
docker buildx build --platform linux/amd64,linux/arm64 -t toxtunnel:latest --push .
```

### Extract Binary from Docker

```bash
docker build -t toxtunnel-build .
docker create --name extract toxtunnel-build
docker cp extract:/usr/local/bin/toxtunnel ./toxtunnel
docker rm extract
```

### Quick Build Without Dockerfile

```bash
docker run --rm -v "$(pwd)":/src -w /src ubuntu:24.04 bash -c '
    apt-get update &&
    apt-get install -y build-essential cmake git pkg-config libsodium-dev &&
    cmake -B build -DCMAKE_BUILD_TYPE=Release &&
    cmake --build build -j$(nproc)
'
```

The binary will be at `build/toxtunnel`.
