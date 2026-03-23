// Integration tests for RulesEngine combined with Config loading and realistic
// access-control scenarios.
//
// These tests exercise the full YAML parse -> evaluate -> serialize round-trip
// pipeline, ensuring that the RulesEngine and Config subsystems compose
// correctly under non-trivial rule configurations.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "toxtunnel/app/rules_engine.hpp"
#include "toxtunnel/util/config.hpp"

namespace toxtunnel::integration {
namespace {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr const char* kFriendA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* kFriendB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr const char* kFriendC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

// ---------------------------------------------------------------------------
// Test Fixture
// ---------------------------------------------------------------------------

class RulesIntegrationTest : public ::testing::Test {
   protected:
    /// Helper to build an AccessRequest concisely.
    static AccessRequest make_request(const std::string& friend_pk, const std::string& host,
                                      uint16_t port) {
        AccessRequest req;
        req.friend_pk = friend_pk;
        req.target_host = host;
        req.target_port = port;
        return req;
    }

    /// Helper that creates a temporary file path, writes content, and returns
    /// the path.  The caller is responsible for cleanup (see cleanup_file).
    static std::filesystem::path write_temp_file(std::string_view content) {
        auto path = make_temp_path();
        std::ofstream ofs(path);
        EXPECT_TRUE(ofs.good());
        ofs << content;
        ofs.close();
        return path;
    }

    /// Generate a unique temporary file path.
    static std::filesystem::path make_temp_path() {
        static std::mt19937 rng(
            static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<unsigned> dist(0, 999999);
        auto temp_dir = std::filesystem::temp_directory_path();
        return temp_dir / ("toxtunnel_test_rules_" + std::to_string(dist(rng)));
    }

    /// Remove a temporary file if it exists.
    static void cleanup_file(const std::filesystem::path& p) {
        std::error_code ec;
        std::filesystem::remove(p, ec);
    }
};

// ============================================================================
// 1. LoadRulesFromYamlAndEvaluate
// ============================================================================

TEST_F(RulesIntegrationTest, LoadRulesFromYamlAndEvaluate) {
    // Friend A is allowed localhost:22 and localhost:80.
    // Friend B is denied everything on port 22 (deny *:22).
    const std::string yaml = R"(
rules:
  - friend_pk: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    allow:
      - host: "localhost"
        ports: [22, 80]
    deny:
      - host: "*.evil.com"
  - friend_pk: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    allow:
      - host: "*"
        ports: [80, 443]
    deny:
      - host: "*"
        ports: [22]
)";

    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const RulesEngine& engine = result.value();

    // Friend A: allowed to localhost:22
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 22)), AccessResult::Allowed);
    // Friend A: allowed to localhost:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 80)), AccessResult::Allowed);
    // Friend A: localhost:443 not in allow list -> Default
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 443)), AccessResult::Default);
    // Friend A: denied *.evil.com
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "malware.evil.com", 80)),
              AccessResult::Denied);

    // Friend B: denied *:22 (deny takes precedence)
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "somehost", 22)), AccessResult::Denied);
    // Friend B: allowed *:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "somehost", 80)), AccessResult::Allowed);
    // Friend B: allowed *:443
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "anyhost", 443)), AccessResult::Allowed);
    // Friend B: port 8080 not in allow ports -> Default
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "anyhost", 8080)), AccessResult::Default);

    // Friend C: no rules at all -> Default
    EXPECT_EQ(engine.evaluate(make_request(kFriendC, "localhost", 22)), AccessResult::Default);
}

// ============================================================================
// 2. RoundTripYamlSerialization
// ============================================================================

TEST_F(RulesIntegrationTest, RoundTripYamlSerialization) {
    // Build rules programmatically.
    RulesEngine original;
    original.add_rule(FriendRule{
        .friend_pk = std::string(kFriendA),
        .allow = {{.host = "localhost", .ports = {22, 80}}, {.host = "10.0.0.1", .ports = {}}},
        .deny = {{.host = "*.internal.corp", .ports = {}}},
    });
    original.add_rule(FriendRule{
        .friend_pk = std::string(kFriendB),
        .allow = {{.host = "10.0.0.*", .ports = {}}},
        .deny = {{.host = "*", .ports = {22}}},
    });

    // Serialize to YAML.
    const std::string yaml = original.to_yaml();
    ASSERT_FALSE(yaml.empty());

    // Reload from the serialized YAML.
    auto reloaded = RulesEngine::from_string(yaml);
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error();

    // Verify that both engines produce identical evaluation results on a range
    // of access requests.
    const std::vector<AccessRequest> probes = {
        make_request(kFriendA, "localhost", 22),
        make_request(kFriendA, "localhost", 80),
        make_request(kFriendA, "localhost", 443),
        make_request(kFriendA, "10.0.0.1", 8080),
        make_request(kFriendA, "db.internal.corp", 3306),
        make_request(kFriendB, "10.0.0.5", 80),
        make_request(kFriendB, "10.0.0.5", 22),
        make_request(kFriendB, "example.com", 443),
        make_request(kFriendC, "localhost", 22),
    };

    for (const auto& probe : probes) {
        EXPECT_EQ(original.evaluate(probe), reloaded.value().evaluate(probe))
            << "Mismatch for friend=" << probe.friend_pk << " host=" << probe.target_host
            << " port=" << probe.target_port;
    }
}

// ============================================================================
// 3. FileRoundTrip
// ============================================================================

TEST_F(RulesIntegrationTest, FileRoundTrip) {
    // Build a RulesEngine.
    RulesEngine original;
    original.add_rule(FriendRule{
        .friend_pk = std::string(kFriendA),
        .allow = {{.host = "localhost", .ports = {22}}},
        .deny = {},
    });
    original.add_rule(FriendRule{
        .friend_pk = std::string(kFriendB),
        .allow = {},
        .deny = {{.host = "*", .ports = {}}},
    });

    // Save to a temporary file.
    std::string tmpl = "/tmp/toxtunnel_test_rules_XXXXXX";
    int fd = mkstemp(tmpl.data());
    ASSERT_NE(fd, -1) << "mkstemp failed";
    close(fd);
    std::filesystem::path filepath(tmpl);

    auto save_result = original.save(filepath);
    ASSERT_TRUE(save_result.has_value()) << save_result.error();

    // Load from the file.
    auto loaded = RulesEngine::from_file(filepath);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();

    // Verify the same evaluation results.
    EXPECT_EQ(loaded.value().evaluate(make_request(kFriendA, "localhost", 22)),
              AccessResult::Allowed);
    EXPECT_EQ(loaded.value().evaluate(make_request(kFriendA, "localhost", 80)),
              AccessResult::Default);
    EXPECT_EQ(loaded.value().evaluate(make_request(kFriendB, "anything", 80)),
              AccessResult::Denied);
    EXPECT_EQ(loaded.value().evaluate(make_request(kFriendC, "localhost", 22)),
              AccessResult::Default);

    // Verify rule counts match.
    EXPECT_EQ(loaded.value().rules().size(), original.rules().size());

    cleanup_file(filepath);
}

// ============================================================================
// 4. ComplexAccessControl
// ============================================================================

TEST_F(RulesIntegrationTest, ComplexAccessControl) {
    // Friend A: allowed localhost:22, localhost:80; denied *.internal.corp:*
    // Friend B: allowed 10.0.0.*:*; denied *:22
    // Friend C: no rules

    RulesEngine engine;

    engine.add_rule(FriendRule{
        .friend_pk = std::string(kFriendA),
        .allow = {{.host = "localhost", .ports = {22, 80}}},
        .deny = {{.host = "*.internal.corp", .ports = {}}},
    });

    engine.add_rule(FriendRule{
        .friend_pk = std::string(kFriendB),
        .allow = {{.host = "10.0.0.*", .ports = {}}},
        .deny = {{.host = "*", .ports = {22}}},
    });

    // -- Friend A tests --

    // Allowed: localhost:22
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 22)), AccessResult::Allowed);
    // Allowed: localhost:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 80)), AccessResult::Allowed);
    // Not explicitly allowed: localhost:443 -> Default
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "localhost", 443)), AccessResult::Default);
    // Denied: db.internal.corp:3306
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "db.internal.corp", 3306)),
              AccessResult::Denied);
    // Denied: web.internal.corp:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "web.internal.corp", 80)),
              AccessResult::Denied);
    // Not matching any rule: google.com:443 -> Default
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "google.com", 443)), AccessResult::Default);

    // -- Friend B tests --

    // Denied: 10.0.0.1:22 (deny *:22 takes precedence over allow 10.0.0.*:*)
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "10.0.0.1", 22)), AccessResult::Denied);
    // Allowed: 10.0.0.1:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "10.0.0.1", 80)), AccessResult::Allowed);
    // Allowed: 10.0.0.255:443
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "10.0.0.255", 443)), AccessResult::Allowed);
    // Denied: 10.0.0.50:22
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "10.0.0.50", 22)), AccessResult::Denied);
    // Denied: example.com:22
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "example.com", 22)), AccessResult::Denied);
    // Not in 10.0.0.*: 192.168.1.1:80 -> Default (no allow match)
    EXPECT_EQ(engine.evaluate(make_request(kFriendB, "192.168.1.1", 80)), AccessResult::Default);

    // -- Friend C tests (no rules) --

    EXPECT_EQ(engine.evaluate(make_request(kFriendC, "localhost", 22)), AccessResult::Default);
    EXPECT_EQ(engine.evaluate(make_request(kFriendC, "10.0.0.1", 80)), AccessResult::Default);
    EXPECT_EQ(engine.evaluate(make_request(kFriendC, "anything", 9999)), AccessResult::Default);

    // -- Verify has_rules_for_friend --

    EXPECT_TRUE(engine.has_rules_for_friend(kFriendA));
    EXPECT_TRUE(engine.has_rules_for_friend(kFriendB));
    EXPECT_FALSE(engine.has_rules_for_friend(kFriendC));
}

// ============================================================================
// 5. ConfigWithRulesFile
// ============================================================================

TEST_F(RulesIntegrationTest, ConfigWithRulesFile) {
    // Build a server-mode config that references a rules file.
    const std::string yaml = R"(
mode: server
data_dir: /tmp/toxtunnel_test_data
logging:
  level: info
tcp_port: 33445
udp_enabled: true
rules_file: "/etc/toxtunnel/rules.yaml"
bootstrap_nodes:
  - address: "node.example.com"
    port: 33445
    public_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)";

    auto cfg_result = Config::from_string(yaml);
    ASSERT_TRUE(cfg_result.has_value()) << cfg_result.error();

    const Config& cfg = cfg_result.value();

    // Verify basic structure.
    EXPECT_TRUE(cfg.is_server());
    EXPECT_FALSE(cfg.is_client());
    EXPECT_TRUE(cfg.server.has_value());

    // Verify the rules_file field is preserved.
    ASSERT_TRUE(cfg.server->rules_file.has_value());
    EXPECT_EQ(cfg.server->rules_file.value(), "/etc/toxtunnel/rules.yaml");

    // Verify the config round-trips through to_yaml / from_string with the
    // rules_file field intact.
    const std::string reserialized = cfg.to_yaml();
    ASSERT_FALSE(reserialized.empty());

    auto reloaded = Config::from_string(reserialized);
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error();
    ASSERT_TRUE(reloaded.value().server.has_value());
    ASSERT_TRUE(reloaded.value().server->rules_file.has_value());
    EXPECT_EQ(reloaded.value().server->rules_file.value(), "/etc/toxtunnel/rules.yaml");
}

// ============================================================================
// 6. WildcardPatternIntegration
// ============================================================================

TEST_F(RulesIntegrationTest, WildcardPatternIntegration) {
    // ---- host_matches tests ----

    // *.example.com should match sub.example.com
    EXPECT_TRUE(RulesEngine::host_matches("sub.example.com", "*.example.com"));
    // *.example.com should not match bare example.com (prefix "." must appear)
    // Note: the implementation checks prefix+suffix; "*.example.com" splits into
    // prefix="" and suffix=".example.com", so "example.com" does match the suffix
    // and the prefix is empty so it is trivially satisfied.  The actual behavior
    // depends on length: "example.com" has length 11, suffix ".example.com" has
    // length 12 -- so this will return false because the host is shorter than the
    // suffix.
    EXPECT_FALSE(RulesEngine::host_matches("example.com", "*.example.com"));

    // Single-star matches everything.
    EXPECT_TRUE(RulesEngine::host_matches("anything.at.all", "*"));

    // ---- ip_matches tests ----

    // 192.168.*.* matches 192.168.1.1
    EXPECT_TRUE(RulesEngine::ip_matches("192.168.1.1", "192.168.*.*"));
    // 192.168.*.* does not match 10.0.0.1 (different first octet)
    EXPECT_FALSE(RulesEngine::ip_matches("10.0.0.1", "192.168.*.*"));
    // 10.0.0.* matches 10.0.0.1
    EXPECT_TRUE(RulesEngine::ip_matches("10.0.0.1", "10.0.0.*"));
    // 10.0.0.* does not match 10.0.1.1
    EXPECT_FALSE(RulesEngine::ip_matches("10.0.1.1", "10.0.0.*"));
    // Exact match
    EXPECT_TRUE(RulesEngine::ip_matches("127.0.0.1", "127.0.0.1"));
    // Mismatch
    EXPECT_FALSE(RulesEngine::ip_matches("127.0.0.1", "127.0.0.2"));

    // ---- port_allowed tests ----

    // Empty list = all ports allowed.
    EXPECT_TRUE(RulesEngine::port_allowed(22, {}));
    EXPECT_TRUE(RulesEngine::port_allowed(80, {}));
    EXPECT_TRUE(RulesEngine::port_allowed(65535, {}));

    // Specific list restricts to listed ports only.
    const std::vector<uint16_t> allowed = {22, 80, 443};
    EXPECT_TRUE(RulesEngine::port_allowed(22, allowed));
    EXPECT_TRUE(RulesEngine::port_allowed(80, allowed));
    EXPECT_TRUE(RulesEngine::port_allowed(443, allowed));
    EXPECT_FALSE(RulesEngine::port_allowed(8080, allowed));
    EXPECT_FALSE(RulesEngine::port_allowed(21, allowed));
    EXPECT_FALSE(RulesEngine::port_allowed(1, allowed));

    // ---- End-to-end wildcard evaluation in the engine ----

    RulesEngine engine;
    engine.add_rule(FriendRule{
        .friend_pk = std::string(kFriendA),
        .allow =
            {
                {.host = "*.example.com", .ports = {80, 443}},
                {.host = "192.168.*", .ports = {}},  // all ports
            },
        .deny = {},
    });

    // Allowed: sub.example.com:80
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "sub.example.com", 80)),
              AccessResult::Allowed);
    // Allowed: deep.sub.example.com:443
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "deep.sub.example.com", 443)),
              AccessResult::Allowed);
    // Not allowed: sub.example.com:8080 (port not in list)
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "sub.example.com", 8080)),
              AccessResult::Default);
    // Not allowed: bare example.com:80 (wildcard prefix requires characters
    // before ".example.com")
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "example.com", 80)), AccessResult::Default);

    // 192.168.* with empty ports -> all ports allowed
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "192.168.1.1", 22)), AccessResult::Allowed);
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "192.168.255.255", 9999)),
              AccessResult::Allowed);
    // Not matching the IP pattern.
    EXPECT_EQ(engine.evaluate(make_request(kFriendA, "10.0.0.1", 80)), AccessResult::Default);
}

}  // namespace
}  // namespace toxtunnel::integration
