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
