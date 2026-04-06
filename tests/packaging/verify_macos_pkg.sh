#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <package-path> <expected-version>" >&2
    exit 2
fi

pkg_path="$1"
expected_version="$2"

payload_listing="$(pkgutil --payload-files "$pkg_path")"

if ! grep -qx './usr/local/bin/toxtunnel' <<<"$payload_listing"; then
    echo "expected pkg payload to install ./usr/local/bin/toxtunnel" >&2
    echo "$payload_listing" >&2
    exit 1
fi

expand_dir="$(mktemp -d "${TMPDIR:-/tmp}/toxtunnel_pkg_expand_XXXXXX")"
rmdir "$expand_dir"
pkgutil --expand "$pkg_path" "$expand_dir" >/dev/null

component_pkg="$(find "$expand_dir" -maxdepth 2 -name '*.pkg' | head -n 1)"
if [[ -z "$component_pkg" ]]; then
    echo "failed to find component package inside $pkg_path" >&2
    exit 1
fi

payload_dir="$(mktemp -d "${TMPDIR:-/tmp}/toxtunnel_pkg_payload_XXXXXX")"
(
    cd "$payload_dir"
    gzip -dc "$component_pkg/Payload" | cpio -idm >/dev/null 2>&1
)

binary_path="$payload_dir/usr/local/bin/toxtunnel"
if [[ ! -x "$binary_path" ]]; then
    echo "expected extracted binary at $binary_path" >&2
    exit 1
fi

reported_version="$("$binary_path" --version)"
if [[ "$reported_version" != "$expected_version" ]]; then
    echo "expected version $expected_version, got $reported_version" >&2
    exit 1
fi

binary_deps="$(otool -L "$binary_path")"
if grep -Eq '/(opt/homebrew|usr/local)/(Cellar|opt)/' <<<"$binary_deps"; then
    echo "binary still links against Homebrew absolute paths" >&2
    echo "$binary_deps" >&2
    exit 1
fi
