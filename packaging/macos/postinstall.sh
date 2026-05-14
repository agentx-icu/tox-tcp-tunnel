#!/bin/bash
# CPack productbuild postflight for component toxtunnel_runtime:
# install launchd plist and load the system daemon (runs as root during pkg install).
set -euo pipefail

# Matches cmake/Packaging.cmake CPACK_PACKAGING_INSTALL_PREFIX for Darwin packages.
readonly SHARE_ROOT="/usr/local/share/toxtunnel"
readonly PLIST_SRC="${SHARE_ROOT}/com.toxtunnel.daemon.plist"
readonly PLIST_DST="/Library/LaunchDaemons/com.toxtunnel.daemon.plist"
readonly LABEL="com.toxtunnel.daemon"
readonly CONFIG_DIR="/usr/local/etc/toxtunnel"
readonly CONFIG_DST="${CONFIG_DIR}/config.yaml"
readonly CONFIG_SRC="${SHARE_ROOT}/config.yaml.example"

if [[ ! -f "${PLIST_SRC}" ]]; then
  echo "postinstall: missing ${PLIST_SRC}; skipping launchd registration." >&2
  exit 0
fi

# Seed /usr/local/etc/toxtunnel/config.yaml from the bundled example so that
# launchd's KeepAlive { SuccessfulExit: false } does not loop on a fresh install:
# without a config file the daemon would exit 1 (config not found) and launchd
# would respawn it forever (subject to the 10 s throttle), polluting
# /var/log/toxtunnel.log. Mirrors the Linux postinst seeding step.
mkdir -p "${CONFIG_DIR}"
if [[ -f "${CONFIG_SRC}" && ! -f "${CONFIG_DST}" ]]; then
  install -m 0644 -o root -g wheel "${CONFIG_SRC}" "${CONFIG_DST}"
fi

install -m 0644 -o root -g wheel "${PLIST_SRC}" "${PLIST_DST}"

# Reload job if already loaded (upgrade path).
if launchctl print "system/${LABEL}" &>/dev/null; then
  launchctl bootout "system/${LABEL}" || true
fi

launchctl bootstrap system "${PLIST_DST}" || {
  echo "postinstall: launchctl bootstrap failed (may require GUI consent on some macOS versions)." >&2
  exit 0
}

exit 0
