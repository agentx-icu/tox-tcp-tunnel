#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <thread>

#include "toxtunnel/app/rules_engine.hpp"

using namespace toxtunnel;

// A valid 64-character hex public key for testing.
static constexpr const char* kTestPk1 =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static constexpr const char* kTestPk2 =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

// ============================================================================
// Pattern matching utilities
// ============================================================================

TEST(RulesEngineHostMatches, ExactMatch) {
    EXPECT_TRUE(RulesEngine::host_matches("localhost", "localhost"));
    EXPECT_TRUE(RulesEngine::host_matches("example.com", "example.com"));
}

TEST(RulesEngineHostMatches, WildcardAll) {
    EXPECT_TRUE(RulesEngine::host_matches("anything", "*"));
    EXPECT_TRUE(RulesEngine::host_matches("example.com", "*"));
}

TEST(RulesEngineHostMatches, PrefixWildcard) {
    EXPECT_TRUE(RulesEngine::host_matches("sub.example.com", "*.example.com"));
    EXPECT_FALSE(RulesEngine::host_matches("example.com", "*.example.com"));
}

TEST(RulesEngineHostMatches, SuffixWildcard) {
    EXPECT_TRUE(RulesEngine::host_matches("localhost", "local*"));
    EXPECT_TRUE(RulesEngine::host_matches("localnet", "local*"));
    EXPECT_FALSE(RulesEngine::host_matches("remote", "local*"));
}

TEST(RulesEngineHostMatches, EmptyPattern) {
    EXPECT_FALSE(RulesEngine::host_matches("anything", ""));
}

TEST(RulesEngineHostMatches, CaseInsensitive) {
    EXPECT_TRUE(RulesEngine::host_matches("LOCALHOST", "localhost"));
    EXPECT_TRUE(RulesEngine::host_matches("localhost", "LOCALHOST"));
}

// C-3 / 2026-05-20 finding: wildcard host matching used to be
// case-sensitive, so a deny rule of `*.EXAMPLE.COM` would not block a
// request to `sub.example.com` (and vice versa) — a bypass for any
// admin who happened to type the rule in uppercase. Hostnames are
// case-insensitive per RFC 1035 §2.3.3.
TEST(RulesEngineHostMatches, WildcardIsCaseInsensitive) {
    // Pattern upper, host lower.
    EXPECT_TRUE(RulesEngine::host_matches("sub.example.com", "*.EXAMPLE.COM"));
    EXPECT_TRUE(RulesEngine::host_matches("LOCALNET", "local*"));
    // Pattern lower, host upper (the original failure mode).
    EXPECT_TRUE(RulesEngine::host_matches("SUB.EXAMPLE.COM", "*.example.com"));
    EXPECT_TRUE(RulesEngine::host_matches("LOCALHOST", "local*"));
    // Negative case: case-folding doesn't make non-matches match.
    EXPECT_FALSE(RulesEngine::host_matches("OTHER.NET", "*.example.com"));
}

// ============================================================================
// IP matching
// ============================================================================

TEST(RulesEngineIpMatches, ExactMatch) {
    EXPECT_TRUE(RulesEngine::ip_matches("192.168.1.1", "192.168.1.1"));
    EXPECT_FALSE(RulesEngine::ip_matches("192.168.1.1", "192.168.1.2"));
}

TEST(RulesEngineIpMatches, WildcardAll) {
    EXPECT_TRUE(RulesEngine::ip_matches("10.0.0.1", "*"));
}

TEST(RulesEngineIpMatches, OctetWildcard) {
    EXPECT_TRUE(RulesEngine::ip_matches("192.168.1.1", "192.168.*.*"));
    EXPECT_TRUE(RulesEngine::ip_matches("192.168.99.200", "192.168.*.*"));
    EXPECT_FALSE(RulesEngine::ip_matches("10.0.1.1", "192.168.*.*"));
}

TEST(RulesEngineIpMatches, EmptyPattern) {
    EXPECT_FALSE(RulesEngine::ip_matches("10.0.0.1", ""));
}

// ============================================================================
// Port matching
// ============================================================================

TEST(RulesEnginePortAllowed, EmptyListAllowsAll) {
    EXPECT_TRUE(RulesEngine::port_allowed(80, {}));
    EXPECT_TRUE(RulesEngine::port_allowed(443, {}));
}

TEST(RulesEnginePortAllowed, SpecificPorts) {
    std::vector<uint16_t> ports = {80, 443, 8080};
    EXPECT_TRUE(RulesEngine::port_allowed(80, ports));
    EXPECT_TRUE(RulesEngine::port_allowed(443, ports));
    EXPECT_FALSE(RulesEngine::port_allowed(22, ports));
}

// ============================================================================
// RulesEngine construction
// ============================================================================

TEST(RulesEngineConstruction, DefaultIsEmpty) {
    RulesEngine engine;
    EXPECT_TRUE(engine.rules().empty());
}

TEST(RulesEngineConstruction, ConstructWithRules) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80, 443}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    EXPECT_EQ(engine.rules().size(), 1u);
}

TEST(RulesEngineConstruction, AddRule) {
    RulesEngine engine;
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80}});
    engine.add_rule(rule);

    EXPECT_EQ(engine.rules().size(), 1u);
    EXPECT_TRUE(engine.has_rules_for_friend(kTestPk1));
    EXPECT_FALSE(engine.has_rules_for_friend(kTestPk2));
}

// ============================================================================
// Evaluate - default deny
// ============================================================================

TEST(RulesEngineEvaluate, NoRulesReturnsDefault) {
    RulesEngine engine;
    AccessRequest req{kTestPk1, "localhost", 80, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Default);
}

TEST(RulesEngineEvaluate, UnknownFriendReturnsDefault) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    AccessRequest req{kTestPk2, "localhost", 80, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Default);
}

// S14 / 2026-05-20 follow-up: a friend that has a rule entry but whose
// request matches neither an allow nor a deny target also returns
// Default. The TunnelServer must treat this as deny — see the header
// doc "It follows a default-deny policy unless explicitly allowed".
// This unit test pins the engine-side contract; the server-side
// enforcement is unit-tested above the abstraction and verified by
// inspection of TunnelServer::handle_tunnel_open.
TEST(RulesEngineEvaluate, MissingAllowReturnsDefaultDeny) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"explicit.allowed.host", {80}});
    rule.deny.push_back(TargetSpec{"explicit.denied.host", {}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    // Friend known, but the requested target matches neither list.
    AccessRequest req{kTestPk1, "neither.list.host", 443, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Default)
        << "engine must return Default when no allow rule matches; "
        << "TunnelServer is contract-bound to treat that as deny";
}

// ============================================================================
// Evaluate - allow rules
// ============================================================================

TEST(RulesEngineEvaluate, AllowMatchesExactHostAndPort) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    AccessRequest req{kTestPk1, "localhost", 80, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Allowed);
}

TEST(RulesEngineEvaluate, AllowAllPortsWhenEmpty) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {}});

    RulesEngine engine(std::vector<FriendRule>{rule});

    AccessRequest req1{kTestPk1, "localhost", 80, {}, {}};
    EXPECT_EQ(engine.evaluate(req1), AccessResult::Allowed);

    AccessRequest req2{kTestPk1, "localhost", 443, {}, {}};
    EXPECT_EQ(engine.evaluate(req2), AccessResult::Allowed);
}

TEST(RulesEngineEvaluate, AllowWildcardHost) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"*", {80}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    AccessRequest req{kTestPk1, "anything.example.com", 80, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Allowed);
}

TEST(RulesEngineEvaluate, AllowDoesNotMatchWrongPort) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    AccessRequest req{kTestPk1, "localhost", 443, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Default);
}

TEST(RulesEngineEvaluate, AllowDoesNotMatchWrongHost) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80}});

    RulesEngine engine(std::vector<FriendRule>{rule});
    AccessRequest req{kTestPk1, "example.com", 80, {}, {}};

    EXPECT_EQ(engine.evaluate(req), AccessResult::Default);
}

// ============================================================================
// Evaluate - deny rules
// ============================================================================

TEST(RulesEngineEvaluate, DenyTakesPrecedenceOverAllow) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"*", {}});
    rule.deny.push_back(TargetSpec{"secret.internal", {}});

    RulesEngine engine(std::vector<FriendRule>{rule});

    // Allowed host
    AccessRequest req1{kTestPk1, "public.example.com", 80, {}, {}};
    EXPECT_EQ(engine.evaluate(req1), AccessResult::Allowed);

    // Denied host takes precedence
    AccessRequest req2{kTestPk1, "secret.internal", 80, {}, {}};
    EXPECT_EQ(engine.evaluate(req2), AccessResult::Denied);
}

TEST(RulesEngineEvaluate, DenySpecificPort) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {}});
    rule.deny.push_back(TargetSpec{"localhost", {22}});

    RulesEngine engine(std::vector<FriendRule>{rule});

    // Port 80 should be allowed
    AccessRequest req1{kTestPk1, "localhost", 80, {}, {}};
    EXPECT_EQ(engine.evaluate(req1), AccessResult::Allowed);

    // Port 22 should be denied
    AccessRequest req2{kTestPk1, "localhost", 22, {}, {}};
    EXPECT_EQ(engine.evaluate(req2), AccessResult::Denied);
}

// ============================================================================
// YAML parsing (from_string)
// ============================================================================

TEST(RulesEngineYaml, ParseSimpleAllowRule) {
    const char* yaml = R"(
rules:
  - friend: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    allow:
      - host: localhost
        ports: [80, 443]
)";

    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& engine = result.value();
    ASSERT_EQ(engine.rules().size(), 1u);
    EXPECT_EQ(engine.rules()[0].friend_pk, kTestPk1);
    ASSERT_EQ(engine.rules()[0].allow.size(), 1u);
    EXPECT_EQ(engine.rules()[0].allow[0].host, "localhost");
    ASSERT_EQ(engine.rules()[0].allow[0].ports.size(), 2u);
}

TEST(RulesEngineYaml, ParseDenyRule) {
    const char* yaml = R"(
rules:
  - friend: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    deny:
      - host: "*.internal"
)";

    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& engine = result.value();
    ASSERT_EQ(engine.rules().size(), 1u);
    EXPECT_EQ(engine.rules()[0].deny.size(), 1u);
    EXPECT_EQ(engine.rules()[0].deny[0].host, "*.internal");
}

TEST(RulesEngineYaml, ParseEmptyYaml) {
    auto result = RulesEngine::from_string("");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().rules().empty());
}

TEST(RulesEngineYaml, ParseInvalidPublicKeyLength) {
    const char* yaml = R"(
rules:
  - friend: tooshort
    allow:
      - host: localhost
)";

    auto result = RulesEngine::from_string(yaml);
    EXPECT_FALSE(result.has_value());
}

TEST(RulesEngineYaml, ParseSequenceFormat) {
    const char* yaml = R"(
- friend: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  allow:
    - host: localhost
)";

    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().rules().size(), 1u);
}

// ============================================================================
// Serialization (to_yaml)
// ============================================================================

TEST(RulesEngineSerialization, ToYamlRoundTrip) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80, 443}});
    rule.deny.push_back(TargetSpec{"*.internal", {}});

    RulesEngine engine(std::vector<FriendRule>{rule});

    std::string yaml = engine.to_yaml();

    // Re-parse
    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& loaded = result.value();
    ASSERT_EQ(loaded.rules().size(), 1u);
    EXPECT_EQ(loaded.rules()[0].friend_pk, kTestPk1);
    EXPECT_EQ(loaded.rules()[0].allow.size(), 1u);
    EXPECT_EQ(loaded.rules()[0].deny.size(), 1u);
}

// ============================================================================
// RulesError error_code integration
// ============================================================================

TEST(RulesError, ErrorCodeCategory) {
    auto ec = make_error_code(RulesError::FileNotFound);
    EXPECT_EQ(std::string(ec.category().name()), "rules");
    EXPECT_FALSE(ec.message().empty());
}

TEST(RulesError, AllCodesHaveMessages) {
    std::vector<RulesError> errors = {
        RulesError::FileNotFound,       RulesError::ParseError,       RulesError::InvalidPublicKey,
        RulesError::InvalidHostPattern, RulesError::InvalidIpPattern, RulesError::InvalidPort,
    };

    for (const auto& err : errors) {
        auto ec = make_error_code(err);
        EXPECT_FALSE(ec.message().empty())
            << "Error code " << static_cast<int>(err) << " has no message";
    }
}

TEST(RulesError, IsErrorCodeEnum) {
    // Verify the is_error_code_enum specialization works
    std::error_code ec = RulesError::ParseError;
    EXPECT_EQ(std::string(ec.category().name()), "rules");
}

// ============================================================================
// File I/O
// ============================================================================

TEST(RulesEngineFile, FromNonexistentFile) {
    auto result = RulesEngine::from_file("/nonexistent/path/rules.yaml");
    EXPECT_FALSE(result.has_value());
}

TEST(RulesEngineFile, SaveAndLoad) {
    FriendRule rule;
    rule.friend_pk = kTestPk1;
    rule.allow.push_back(TargetSpec{"localhost", {80}});

    RulesEngine engine(std::vector<FriendRule>{rule});

    const auto unique_suffix =
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
        std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    auto tmp = std::filesystem::temp_directory_path() /
               ("test_rules_engine_save_" + unique_suffix + ".yaml");
    auto save_result = engine.save(tmp);
    ASSERT_TRUE(save_result.has_value()) << save_result.error();

    auto load_result = RulesEngine::from_file(tmp);
    ASSERT_TRUE(load_result.has_value()) << load_result.error();

    const auto& loaded = load_result.value();
    ASSERT_EQ(loaded.rules().size(), 1u);
    EXPECT_EQ(loaded.rules()[0].friend_pk, kTestPk1);

    std::filesystem::remove(tmp);
}
