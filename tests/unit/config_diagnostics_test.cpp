// Unknown-config-key diagnostics.
//
// The parser reads keys ad hoc (`if (node["x"])`), so anything it does not know
// is silently ignored. That has bitten real deployments: `tox.local_discovery_
// enabled` looks like a setting, appears in hand-written configs, and does
// nothing (LAN discovery follows `tox.bootstrap_mode`). These tests pin the
// warning pass that surfaces such keys — and, just as importantly, pin that
// every *valid* shape stays silent, including the legacy flat layout.

#include "toxtunnel/util/config_diagnostics.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace toxtunnel::test {
namespace {

std::vector<std::string> paths_of(std::string_view yaml) {
    std::vector<std::string> out;
    for (const auto& k : util::find_unknown_config_keys_in_string(yaml)) {
        out.push_back(k.path);
    }
    std::sort(out.begin(), out.end());
    return out;
}

TEST(ConfigDiagnosticsTest, CanonicalConfigHasNoUnknownKeys) {
    constexpr std::string_view yaml = R"(
mode: client
data_dir: /tmp/tt
logging:
  level: info
  file: /tmp/tt.log
service:
  auto_start: true
  allow_client_daemon: true
metrics:
  enabled: true
  listen: 127.0.0.1:9100
  path: /metrics
inspect:
  enabled: true
tox:
  udp_enabled: true
  ipv6_enabled: false
  udp_port: 33445
  tcp_port: 33445
  bootstrap_mode: auto
  bootstrap_nodes:
    - address: 1.2.3.4
      port: 33445
      public_key: AA
tunnel:
  coalesce_max_delay_us: 200
  coalesce_max_bytes: 1362
  coalesce_mode: fixed
  idle_timeout_seconds: 0
  reaper_tick_seconds: 10
  keepalive_interval_seconds: 0
  half_close_timeout_seconds: 120
  open_timeout_seconds: 30
  resume:
    enabled: false
    max_age_seconds: 300
    on_gap: passthrough
flow_control:
  mode: bdp
  send_window_min_bytes: 65536
  send_window_max_bytes: 4194304
  safety_factor_x100: 150
  fixed_window_bytes: 262144
watchdog:
  enabled: true
  deadline_seconds: 30
  systemd_notify: true
client:
  server_id: AABB
  failover:
    timeout_seconds: 60
    prefer_primary_grace_seconds: 30
  socks5:
    enabled: false
    listen: 127.0.0.1:1080
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22
)";
    EXPECT_TRUE(paths_of(yaml).empty()) << "canonical config must not warn";
}

TEST(ConfigDiagnosticsTest, ServerBlockAndDiscloseAreUnderstood) {
    constexpr std::string_view yaml = R"(
mode: server
server:
  rules_file: /etc/toxtunnel/rules.yaml
  disclose:
    hostname: true
    os: true
    os_version: false
    arch: true
    uptime: false
    toxtunnel_version: true
)";
    EXPECT_TRUE(paths_of(yaml).empty());
}

TEST(ConfigDiagnosticsTest, DiscloseShorthandBoolIsNotAMapAndDoesNotWarn) {
    constexpr std::string_view yaml = R"(
mode: server
server:
  rules_file: r.yaml
  disclose: true
)";
    EXPECT_TRUE(paths_of(yaml).empty());
}

TEST(ConfigDiagnosticsTest, LegacyFlatLayoutDoesNotWarn) {
    // The parser still honours these at the root when server:/client: are
    // absent; warning about them would be a false positive on old configs.
    constexpr std::string_view yaml = R"(
mode: server
rules_file: rules.yaml
tcp_port: 33445
udp_enabled: true
bootstrap_nodes:
  - address: 1.2.3.4
    port: 33445
    public_key: BB
)";
    EXPECT_TRUE(paths_of(yaml).empty());
}

TEST(ConfigDiagnosticsTest, ReportsTheRealWorldNonExistentToxKey) {
    constexpr std::string_view yaml = R"(
mode: client
tox:
  udp_enabled: true
  bootstrap_mode: auto
  local_discovery_enabled: true
)";
    EXPECT_EQ(paths_of(yaml), std::vector<std::string>{"tox.local_discovery_enabled"});
}

TEST(ConfigDiagnosticsTest, ReportsTyposAtEveryNestingLevel) {
    constexpr std::string_view yaml = R"(
mode: client
tunel:
  idle_timeout_seconds: 5
tunnel:
  idle_timeout: 600
client:
  server_id: AA
  socks5:
    enabled: true
    auth: none
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_prot: 22
)";
    const std::vector<std::string> expected{"client.forwards[0].remote_prot", "client.socks5.auth",
                                            "tunel", "tunnel.idle_timeout"};
    EXPECT_EQ(paths_of(yaml), expected);
}

TEST(ConfigDiagnosticsTest, DoesNotDescendIntoAnUnknownBlock) {
    // One warning for the unknown block itself, not one per key inside it —
    // otherwise a single mis-indented section produces a wall of noise.
    constexpr std::string_view yaml = R"(
mode: client
mystery:
  a: 1
  b: 2
  c:
    d: 3
)";
    EXPECT_EQ(paths_of(yaml), std::vector<std::string>{"mystery"});
}

TEST(ConfigDiagnosticsTest, MalformedYamlYieldsNoDiagnostics) {
    // Reporting a parse error is the loader's job; this pass stays quiet.
    EXPECT_TRUE(paths_of("mode: client\n  bad indent: [").empty());
}

}  // namespace
}  // namespace toxtunnel::test
