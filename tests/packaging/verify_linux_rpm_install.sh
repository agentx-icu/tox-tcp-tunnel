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

if ! rpm -qp --scripts "${package_path}" | grep -Fq "systemctl enable --now toxtunnel.service"; then
    echo "expected rpm postinstall script to run: systemctl enable --now toxtunnel.service" >&2
    exit 1
fi

for repo_file in /etc/yum.repos.d/CentOS-*.repo; do
    if [[ -f "${repo_file}" ]]; then
        sed -i \
            -e 's/^mirrorlist=/#mirrorlist=/' \
            -e 's|^#baseurl=http://mirror.centos.org/centos/\$releasever|baseurl=http://vault.centos.org/7.9.2009|g' \
            -e 's|^#baseurl=http://mirror.centos.org/altarch/\$releasever|baseurl=http://vault.centos.org/altarch/7.9.2009|g' \
            "${repo_file}"
    fi
done

cat >/etc/yum.repos.d/epel-archive.repo <<'EOF'
[epel-archive]
name=EPEL 7 archive - $basearch
baseurl=https://archive.fedoraproject.org/pub/archive/epel/7/$basearch
enabled=1
gpgcheck=0
EOF

yum clean all
yum makecache
yum install -y "${package_path}"

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

echo "RPM package install verification passed for ${package_path}"
