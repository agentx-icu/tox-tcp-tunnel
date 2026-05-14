#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <package-path> <expected-version>" >&2
    exit 2
fi

package_path="$1"
expected_version="$2"

if [[ ! -f "${package_path}" ]]; then
    echo "package not found: ${package_path}" >&2
    exit 1
fi

tmpdir_ctrl="$(mktemp -d)"
trap 'rm -rf "${tmpdir_ctrl}"' EXIT
dpkg-deb -e "${package_path}" "${tmpdir_ctrl}"
if ! grep -Fq "systemctl enable --now toxtunnel.service" "${tmpdir_ctrl}/postinst"; then
    echo "expected deb postinst to run: systemctl enable --now toxtunnel.service" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
# apt requires local deb paths to be absolute or prefixed with ./.
if [[ "${package_path}" = /* ]]; then
    install_target="${package_path}"
else
    install_target="./${package_path}"
fi
apt-get install -y --no-install-recommends "${install_target}"

binary_path="/usr/bin/toxtunnel"
if [[ ! -x "${binary_path}" ]]; then
    echo "expected installed binary at ${binary_path}" >&2
    exit 1
fi

unit_path="/usr/lib/systemd/system/toxtunnel.service"
if [[ ! -f "${unit_path}" ]]; then
    echo "expected installed systemd unit at ${unit_path}" >&2
    exit 1
fi

if ! grep -Fxq "StateDirectory=toxtunnel" "${unit_path}"; then
    echo "expected ${unit_path} to declare StateDirectory=toxtunnel" >&2
    exit 1
fi

if ! grep -Fxq "RemainAfterExit=yes" "${unit_path}"; then
    echo "expected ${unit_path} to declare RemainAfterExit=yes (so policy-gated exit 0 shows as active(exited), not inactive(dead))" >&2
    exit 1
fi

example_config="/usr/share/toxtunnel/config.yaml.example"
if [[ ! -f "${example_config}" ]]; then
    echo "expected installed example config at ${example_config}" >&2
    exit 1
fi

if grep -Fq "rules_file:" "${example_config}"; then
    echo "expected ${example_config} to omit a default rules_file entry" >&2
    exit 1
fi

known_servers_example="/usr/share/toxtunnel/known_servers.yaml.example"
if [[ ! -f "${known_servers_example}" ]]; then
    echo "expected installed known-servers schema reference at ${known_servers_example}" >&2
    exit 1
fi
if ! grep -Fq "tox_id:" "${known_servers_example}"; then
    echo "expected ${known_servers_example} to document the tox_id field" >&2
    exit 1
fi

seeded_config="/etc/toxtunnel/config.yaml"
if [[ ! -f "${seeded_config}" ]]; then
    echo "expected seeded config at ${seeded_config}" >&2
    exit 1
fi

if grep -Fq "rules_file:" "${seeded_config}"; then
    echo "expected ${seeded_config} to boot without a required rules_file" >&2
    exit 1
fi

if ! grep -Fq "auto_start: true" "${seeded_config}"; then
    echo "expected ${seeded_config} to set service.auto_start: true for packaged server policy" >&2
    exit 1
fi

if ldd "${binary_path}" | grep -Fq "not found"; then
    echo "installed binary has unresolved runtime dependencies" >&2
    ldd "${binary_path}" >&2
    exit 1
fi

reported_version="$("${binary_path}" --version)"
if [[ "${reported_version}" != "${expected_version}" ]]; then
    echo "expected version ${expected_version}, got ${reported_version}" >&2
    exit 1
fi

echo "Debian package install verification passed for ${package_path}"
