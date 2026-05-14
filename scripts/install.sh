#!/usr/bin/env sh
# One-line installer for tox-tcp-tunnel on macOS and Linux.
#
# Quick start:
#   curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh -s -- --mode client
#
# Flags / env overrides:
#   --mode {server|client}        TOXTUNNEL_MODE      (default: server)
#   --version {latest|vX.Y.Z}     TOXTUNNEL_VERSION   (default: latest)
#   --repo OWNER/REPO             TOXTUNNEL_REPO      (default: anonymoussoft/tox-tcp-tunnel)
#
# What it does:
#   1. Downloads the latest .deb/.rpm/.pkg from GitHub Releases
#   2. Installs via apt-get/dnf/yum/dpkg/rpm/installer
#   3. If --mode client: rewrites the seeded config to a client scaffold and
#      restarts the system service (which then idles via exit 0 until
#      service.allow_client_daemon is set to true). The server flow leaves
#      the package's seeded server config untouched.
#
# Exits 0 on success. The service remains "active (exited)" / stopped (cleanly)
# until the user fills in `client.server_id` and flips `service.allow_client_daemon`.

set -eu

REPO="${TOXTUNNEL_REPO:-anonymoussoft/tox-tcp-tunnel}"
VERSION="${TOXTUNNEL_VERSION:-latest}"
MODE="${TOXTUNNEL_MODE:-server}"

usage() {
    cat <<EOF
ToxTunnel installer

Usage:
  install.sh [--mode server|client] [--version latest|vX.Y.Z] [--repo OWNER/REPO]

Env vars (lower priority than flags):
  TOXTUNNEL_MODE, TOXTUNNEL_VERSION, TOXTUNNEL_REPO
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)        MODE="${2:?--mode requires value}"; shift 2 ;;
        --mode=*)      MODE="${1#*=}"; shift ;;
        --version)     VERSION="${2:?--version requires value}"; shift 2 ;;
        --version=*)   VERSION="${1#*=}"; shift ;;
        --repo)        REPO="${2:?--repo requires value}"; shift 2 ;;
        --repo=*)      REPO="${1#*=}"; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown flag: $1" >&2; usage; exit 2 ;;
    esac
done

case "$MODE" in
    server|client) ;;
    *) echo "Invalid --mode: $MODE (expected 'server' or 'client')" >&2; exit 2 ;;
esac

if [ "$(id -u)" != "0" ]; then
    echo "This installer needs root (it installs system packages and writes /etc/toxtunnel)." >&2
    echo "Re-run with sudo, e.g.:" >&2
    echo "  curl -fsSL .../install.sh | sudo sh -s -- --mode $MODE" >&2
    exit 1
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$ARCH" in
    arm64|aarch64)  ARCH_NORM="aarch64" ;;
    x86_64|amd64)   ARCH_NORM="x86_64" ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# Map to release filename conventions and pick installer.
SYS=
EXT=
ARCH_RELEASE="$ARCH_NORM"
DEFAULT_DATA_DIR=
CONFIG_PATH=
case "$OS" in
    Linux)
        SYS="Linux"
        DEFAULT_DATA_DIR="/var/lib/toxtunnel"
        CONFIG_PATH="/etc/toxtunnel/config.yaml"
        if command -v dpkg >/dev/null 2>&1; then
            EXT="deb"
        elif command -v rpm >/dev/null 2>&1; then
            EXT="rpm"
        else
            echo "No supported package manager (need dpkg or rpm)." >&2
            exit 1
        fi
        ;;
    Darwin)
        SYS="Darwin"
        EXT="pkg"
        # macOS release filenames use 'arm64' not 'aarch64'.
        [ "$ARCH_NORM" = "aarch64" ] && ARCH_RELEASE="arm64"
        DEFAULT_DATA_DIR="/usr/local/var/toxtunnel"
        CONFIG_PATH="/usr/local/etc/toxtunnel/config.yaml"
        ;;
    *)
        echo "Unsupported OS: $OS (this installer covers Linux + macOS)." >&2
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/toxtunnel-${SYS}-${ARCH_RELEASE}-latest.${EXT}"
else
    VER_NUM="${VERSION#v}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/toxtunnel-${VER_NUM}-${SYS}-${ARCH_RELEASE}.${EXT}"
fi

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t toxtunnel)"
trap 'rm -rf "$TMP"' EXIT
PKG="${TMP}/toxtunnel.${EXT}"

echo "==> Downloading ${URL}"
if command -v curl >/dev/null 2>&1; then
    curl -fSL --retry 3 -o "$PKG" "$URL"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$PKG" "$URL"
else
    echo "Neither curl nor wget is installed." >&2
    exit 1
fi

echo "==> Installing ${PKG}"
case "$EXT" in
    deb)
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$PKG"
        else
            dpkg -i "$PKG" || true
        fi
        ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$PKG"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "$PKG"
        else
            rpm -i --replacepkgs "$PKG"
        fi
        ;;
    pkg)
        installer -pkg "$PKG" -target /
        ;;
esac

# The package's postinst (Linux) and postinstall (macOS) seed a server config.
# For --mode server we leave that alone. For --mode client we overwrite — but
# only if the existing config still says `mode: server` (i.e. user has not yet
# customized) OR the file is missing entirely.
write_client_config() {
    cat > "$1" <<YAML
mode: client
data_dir: ${DEFAULT_DATA_DIR}

service:
  # The system service exits 0 immediately while allow_client_daemon is false,
  # so it never silently binds local forward ports on a desktop. After you fill
  # in client.server_id and forwards below, set allow_client_daemon: true (and
  # optionally auto_start: true) and restart the service.
  auto_start: false
  allow_client_daemon: false

logging:
  level: info

tox:
  udp_enabled: true
  bootstrap_mode: auto

client:
  # Paste the server's 76-character Tox ID. Get it on the server with:
  #   toxtunnel print-id --qr
  server_id: REPLACE_WITH_SERVER_TOX_ID
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22
YAML
    chmod 0644 "$1"
}

restart_service() {
    case "$OS" in
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart toxtunnel.service || true
            fi
            ;;
        Darwin)
            if launchctl print system/com.toxtunnel.daemon >/dev/null 2>&1; then
                launchctl kickstart -k system/com.toxtunnel.daemon || true
            fi
            ;;
    esac
}

if [ "$MODE" = "client" ]; then
    if [ -f "$CONFIG_PATH" ] && grep -q "^mode:[[:space:]]*client" "$CONFIG_PATH"; then
        echo "==> ${CONFIG_PATH} already in client mode — leaving as-is."
    elif [ -f "$CONFIG_PATH" ] && ! grep -q "^mode:[[:space:]]*server" "$CONFIG_PATH"; then
        # Existing config is neither `mode: server` nor `mode: client`. The
        # user almost certainly hand-edited it; refuse to clobber.
        echo "WARNING: ${CONFIG_PATH} exists but isn't the seeded server template." >&2
        echo "         Skipping client rewrite. Edit it manually to switch to client mode." >&2
    else
        # File doesn't exist OR is the seeded server template. Warn loudly
        # BEFORE writing — switching --mode is documented as destructive
        # (replaces in-place customisations with the canonical client template).
        if [ -f "$CONFIG_PATH" ]; then
            echo >&2
            echo "WARNING: ${CONFIG_PATH} is currently in server mode." >&2
            echo "         About to OVERWRITE it with the canonical client template." >&2
            echo "         Any in-place customisations (rules_file, forwards, …) WILL be lost." >&2
            echo "         (Press Ctrl-C now to abort.)" >&2
            echo >&2
        fi
        echo "==> Writing client config at ${CONFIG_PATH}"
        mkdir -p "$(dirname "$CONFIG_PATH")"
        write_client_config "$CONFIG_PATH"
        restart_service
    fi
fi

echo
echo "==> Installed."
echo "    binary:  $(command -v toxtunnel 2>/dev/null || echo '/usr/bin/toxtunnel or /usr/local/bin/toxtunnel')"
echo "    config:  ${CONFIG_PATH}"
echo "    mode:    ${MODE}"
echo
if [ "$MODE" = "server" ]; then
    cat <<EOF
Next steps (server):
  - The service is enabled and running. Get your Tox ID:
      toxtunnel print-id --qr
  - Hand the printed Tox ID (or QR code) to the client side.
  - Optional: tighten access with rules_file in ${CONFIG_PATH}.
EOF
else
    cat <<EOF
Next steps (client):
  - Edit ${CONFIG_PATH}:
      * client.server_id: <76-char Tox ID from your server>
      * client.forwards:  add or modify the local_port / remote_host / remote_port lines
  - Then enable the daemon:
      * service.allow_client_daemon: true   (required to bind local ports)
      * service.auto_start: true            (optional, for auto-start on boot)
  - Apply changes:
EOF
    case "$OS" in
        Linux)  echo "      systemctl restart toxtunnel.service" ;;
        Darwin) echo "      sudo launchctl kickstart -k system/com.toxtunnel.daemon" ;;
    esac
    cat <<EOF
  - Or run client in the foreground:
      toxtunnel -c ${CONFIG_PATH}
EOF
fi
