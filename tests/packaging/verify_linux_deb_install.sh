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

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends "${package_path}"

binary_path="/usr/bin/toxtunnel"
if [[ ! -x "${binary_path}" ]]; then
    echo "expected installed binary at ${binary_path}" >&2
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
