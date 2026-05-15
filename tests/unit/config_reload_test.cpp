#include "toxtunnel/util/config_reload.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "toxtunnel/util/config.hpp"

using namespace toxtunnel;
using util::check_reloadable;
using util::diff_forwards;

namespace {

Config make_server_config() {
    Config c = Config::default_server();
    c.data_dir = "/var/lib/toxtunnel";
    return c;
}

Config make_client_config() {
    Config c = Config::default_client();
    c.data_dir = "/var/lib/toxtunnel";
    ClientConfig client;
    client.server_id.assign(76, 'A');
    client.forwards.push_back({2222, "127.0.0.1", 22});
    c.client = client;
    return c;
}

}  // namespace

// ---------------------------------------------------------------------------
// diff_forwards
// ---------------------------------------------------------------------------

TEST(DiffForwardsTest, EmptyDiffWhenIdentical) {
    std::vector<ForwardRule> a = {{2222, "h1", 22}, {3333, "h2", 80}};
    auto diff = diff_forwards(a, a);
    EXPECT_TRUE(diff.empty());
    EXPECT_TRUE(diff.added.empty());
    EXPECT_TRUE(diff.removed.empty());
}

TEST(DiffForwardsTest, EmptyDiffWhenReordered) {
    std::vector<ForwardRule> a = {{2222, "h1", 22}, {3333, "h2", 80}};
    std::vector<ForwardRule> b = {{3333, "h2", 80}, {2222, "h1", 22}};
    auto diff = diff_forwards(a, b);
    EXPECT_TRUE(diff.empty());
}

TEST(DiffForwardsTest, DetectsAdded) {
    std::vector<ForwardRule> a = {{2222, "h1", 22}};
    std::vector<ForwardRule> b = {{2222, "h1", 22}, {3333, "h2", 80}};
    auto diff = diff_forwards(a, b);
    EXPECT_TRUE(diff.removed.empty());
    ASSERT_EQ(diff.added.size(), 1u);
    EXPECT_EQ(diff.added[0].local_port, 3333);
    EXPECT_EQ(diff.added[0].remote_host, "h2");
    EXPECT_EQ(diff.added[0].remote_port, 80);
}

TEST(DiffForwardsTest, DetectsRemoved) {
    std::vector<ForwardRule> a = {{2222, "h1", 22}, {3333, "h2", 80}};
    std::vector<ForwardRule> b = {{2222, "h1", 22}};
    auto diff = diff_forwards(a, b);
    EXPECT_TRUE(diff.added.empty());
    ASSERT_EQ(diff.removed.size(), 1u);
    EXPECT_EQ(diff.removed[0].local_port, 3333);
}

TEST(DiffForwardsTest, DetectsAddedAndRemovedTogether) {
    std::vector<ForwardRule> a = {{2222, "h1", 22}, {3333, "h2", 80}};
    std::vector<ForwardRule> b = {{2222, "h1", 22}, {4444, "h3", 443}};
    auto diff = diff_forwards(a, b);
    ASSERT_EQ(diff.added.size(), 1u);
    EXPECT_EQ(diff.added[0].local_port, 4444);
    ASSERT_EQ(diff.removed.size(), 1u);
    EXPECT_EQ(diff.removed[0].local_port, 3333);
}

TEST(DiffForwardsTest, DifferentRemoteHostIsAddedAndRemoved) {
    // Same local_port but different remote => natural-key compare flags both.
    std::vector<ForwardRule> a = {{2222, "h1", 22}};
    std::vector<ForwardRule> b = {{2222, "h2", 22}};
    auto diff = diff_forwards(a, b);
    EXPECT_EQ(diff.added.size(), 1u);
    EXPECT_EQ(diff.removed.size(), 1u);
}

// ---------------------------------------------------------------------------
// check_reloadable — allow cases
// ---------------------------------------------------------------------------

TEST(CheckReloadableTest, AcceptsNoChange) {
    auto a = make_server_config();
    auto b = a;
    auto res = check_reloadable(a, b);
    EXPECT_TRUE(res.has_value()) << (res.has_value() ? "" : res.error());
}

TEST(CheckReloadableTest, AcceptsLoggingLevelChange) {
    auto a = make_server_config();
    auto b = a;
    b.logging.level = util::LogLevel::Debug;
    auto res = check_reloadable(a, b);
    EXPECT_TRUE(res.has_value());
}

TEST(CheckReloadableTest, AcceptsServerRulesFilePathChange) {
    auto a = make_server_config();
    auto b = a;
    a.server->rules_file = std::string("/etc/toxtunnel/rules_a.yaml");
    b.server->rules_file = std::string("/etc/toxtunnel/rules_b.yaml");
    auto res = check_reloadable(a, b);
    EXPECT_TRUE(res.has_value()) << (res.has_value() ? "" : res.error());
}

TEST(CheckReloadableTest, AcceptsForwardsChange) {
    auto a = make_client_config();
    auto b = a;
    b.client->forwards.push_back({3333, "h2", 80});
    auto res = check_reloadable(a, b);
    EXPECT_TRUE(res.has_value()) << (res.has_value() ? "" : res.error());
}

// ---------------------------------------------------------------------------
// check_reloadable — reject cases
// ---------------------------------------------------------------------------

TEST(CheckReloadableTest, RejectsModeChange) {
    auto a = make_server_config();
    auto b = make_client_config();
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("mode"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsDataDirChange) {
    auto a = make_server_config();
    auto b = a;
    b.data_dir = "/tmp/elsewhere";
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("data_dir"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsToxUdpEnabledChange) {
    auto a = make_server_config();
    auto b = a;
    b.tox.udp_enabled = !a.tox.udp_enabled;
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("tox"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsServerTcpPortChange) {
    auto a = make_server_config();
    auto b = a;
    b.server->tcp_port = static_cast<uint16_t>(a.server->tcp_port + 1);
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("server.tcp_port"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsServerDiscloseChange) {
    auto a = make_server_config();
    auto b = a;
    b.server->disclose.hostname = !a.server->disclose.hostname;
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("server.disclose"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsClientServerIdChange) {
    auto a = make_client_config();
    auto b = a;
    b.client->server_id.assign(76, 'B');
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("client.server_id"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsMetricsChange) {
    auto a = make_server_config();
    auto b = a;
    b.metrics.enabled = !a.metrics.enabled;
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("metrics"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsTunnelCoalesceChange) {
    auto a = make_server_config();
    auto b = a;
    b.tunnel.coalesce_max_delay_us = a.tunnel.coalesce_max_delay_us + 1;
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("tunnel"), std::string::npos) << res.error();
}

TEST(CheckReloadableTest, RejectsLoggingFileChange) {
    auto a = make_server_config();
    auto b = a;
    b.logging.file = std::string("/tmp/toxtunnel.log");
    auto res = check_reloadable(a, b);
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().find("logging.file"), std::string::npos) << res.error();
}

// ---------------------------------------------------------------------------
// End-to-end: parse YAML + check_reloadable
// ---------------------------------------------------------------------------

TEST(ReloadParseTest, ChangedForwardsParseAndDiffOk) {
    const char* yaml_a = R"(
mode: client
data_dir: /var/lib/toxtunnel
client:
  server_id: 11111111111111111111111111111111111111111111111111111111111111111111111111111111
  forwards:
    - local_port: 2222
      remote_host: a.example
      remote_port: 22
)";
    const char* yaml_b = R"(
mode: client
data_dir: /var/lib/toxtunnel
client:
  server_id: 11111111111111111111111111111111111111111111111111111111111111111111111111111111
  forwards:
    - local_port: 2222
      remote_host: a.example
      remote_port: 22
    - local_port: 3333
      remote_host: b.example
      remote_port: 80
)";

    auto a = Config::from_string(yaml_a);
    auto b = Config::from_string(yaml_b);
    ASSERT_TRUE(a.has_value()) << a.error();
    ASSERT_TRUE(b.has_value()) << b.error();

    auto check = check_reloadable(a.value(), b.value());
    EXPECT_TRUE(check.has_value()) << (check.has_value() ? "" : check.error());

    auto diff = diff_forwards(a.value().client->forwards, b.value().client->forwards);
    ASSERT_EQ(diff.added.size(), 1u);
    EXPECT_EQ(diff.added[0].local_port, 3333);
    EXPECT_TRUE(diff.removed.empty());
}

TEST(ReloadParseTest, ChangedToxUdpFlagRejected) {
    // Note: Config parsing propagates tox.udp_enabled into server.udp_enabled
    // for backward compatibility, so this YAML difference manifests as a
    // server.udp_enabled rejection — which is the more specific (and equally
    // valid) error path. Either substring would be acceptable for the test;
    // we accept both so we don't pin to the current reorder.
    const char* yaml_a = R"(
mode: server
data_dir: /var/lib/toxtunnel
tox:
  udp_enabled: true
)";
    const char* yaml_b = R"(
mode: server
data_dir: /var/lib/toxtunnel
tox:
  udp_enabled: false
)";

    auto a = Config::from_string(yaml_a);
    auto b = Config::from_string(yaml_b);
    ASSERT_TRUE(a.has_value()) << a.error();
    ASSERT_TRUE(b.has_value()) << b.error();

    auto check = check_reloadable(a.value(), b.value());
    ASSERT_FALSE(check.has_value());
    const bool mentions_tox = check.error().find("tox") != std::string::npos ||
                              check.error().find("udp_enabled") != std::string::npos;
    EXPECT_TRUE(mentions_tox) << check.error();
}
