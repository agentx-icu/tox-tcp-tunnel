#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <binary-path> <max-glibc-version>"
    exit 1
fi

binary_path="$1"
max_glibc="$2"

if [[ ! -f "${binary_path}" ]]; then
    echo "Binary not found: ${binary_path}"
    exit 1
fi

if ! command -v objdump >/dev/null 2>&1; then
    echo "objdump is required for ABI verification"
    exit 1
fi

required_glibc="$(
    objdump -T "${binary_path}" \
        | awk '/GLIBC_[0-9]+\.[0-9]+/ { match($0, /GLIBC_[0-9]+\.[0-9]+/); print substr($0, RSTART + 6, RLENGTH - 6) }' \
        | sort -V \
        | tail -n1
)"

if [[ -z "${required_glibc}" ]]; then
    echo "Unable to determine required GLIBC version from ${binary_path}"
    exit 1
fi

if [[ "$(printf '%s\n%s\n' "${required_glibc}" "${max_glibc}" | sort -V | tail -n1)" != "${max_glibc}" ]]; then
    echo "GLIBC requirement too new: ${required_glibc} (max allowed ${max_glibc})"
    exit 1
fi

if ldd "${binary_path}" | grep -Eq 'libstdc\+\+\.so\.6|libgcc_s\.so\.1'; then
    echo "Binary still depends on dynamic libstdc++/libgcc."
    ldd "${binary_path}"
    exit 1
fi

echo "ABI verification passed: GLIBC <= ${max_glibc}, no dynamic libstdc++/libgcc"
