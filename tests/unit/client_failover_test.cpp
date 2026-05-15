#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include "toxtunnel/app/known_servers.hpp"
#include "toxtunnel/app/tunnel_client.hpp"
#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/config.hpp"

namespace {

using namespace toxtunnel;
using namespace toxtunnel::app;
using clock_t_ = std::chrono::steady_clock;

constexpr const char* kPrimary =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
constexpr const char* kFallback1 =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
constexpr const char* kFallback2 =
    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

// Generate a checksum-valid 76-char hex Tox ID parameterised by a single
// "seed" pair (byte0, byte1). The remaining 34 bytes (public_key tail + nospam)
// are zero, so cs = (seed_lo, seed_hi). Use this to fabricate distinct valid
// Tox IDs for tests that go through `Config::validate()`.
std::string make_valid_tox_id_hex(uint8_t seed_lo, uint8_t seed_hi) {
    std::array<uint8_t, toxtunnel::tox::kToxIdBytes> bytes{};
    bytes[0] = seed_lo;
    bytes[1] = seed_hi;
    // Checksum is XOR of (public_key + nospam) bytes in 2-wide stride.
    bytes[36] = seed_lo;
    bytes[37] = seed_hi;
    return toxtunnel::tox::bytes_to_hex(bytes.data(), bytes.size());
}

// Helper: build a vector of endpoints with the given (online, offline_since_secs,
// online_since_secs) tuples. Offsets are interpreted relative to `now`.
struct EndpointSpec {
    std::string tox_id;
    bool online;
    int offline_since_secs_ago;  // 0 means "unset"
    int online_since_secs_ago;   // 0 means "unset"
};

std::vector<ClientServerEndpoint> make_endpoints(const std::vector<EndpointSpec>& specs,
                                                 clock_t_::time_point now) {
    std::vector<ClientServerEndpoint> out;
    out.reserve(specs.size());
    uint32_t friend_no = 100;
    for (const auto& s : specs) {
        ClientServerEndpoint ep;
        ep.tox_id_hex = s.tox_id;
        ep.friend_number = friend_no++;
        ep.online = s.online;
        if (s.offline_since_secs_ago > 0) {
            ep.offline_since = now - std::chrono::seconds(s.offline_since_secs_ago);
        }
        if (s.online_since_secs_ago > 0) {
            ep.online_since = now - std::chrono::seconds(s.online_since_secs_ago);
        }
        out.push_back(std::move(ep));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

TEST(ClientFailoverConfigTest, SingleStringServerIdYieldsOneElementList) {
    const std::string yaml = std::string("mode: client\nclient:\n  server_id: ") + kPrimary + "\n";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    ASSERT_TRUE(cfg.client.has_value());
    EXPECT_EQ(cfg.client->server_id, kPrimary);
    EXPECT_TRUE(cfg.client->fallback_server_ids.empty());

    const auto all = cfg.client->all_server_ids();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0], kPrimary);
}

TEST(ClientFailoverConfigTest, ListServerIdSplitsIntoPrimaryAndFallbacks) {
    const std::string yaml = std::string("mode: client\nclient:\n  server_id:\n    - ") + kPrimary +
                             "\n    - " + kFallback1 + "\n    - " + kFallback2 + "\n";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    ASSERT_TRUE(cfg.client.has_value());
    EXPECT_EQ(cfg.client->server_id, kPrimary);
    ASSERT_EQ(cfg.client->fallback_server_ids.size(), 2u);
    EXPECT_EQ(cfg.client->fallback_server_ids[0], kFallback1);
    EXPECT_EQ(cfg.client->fallback_server_ids[1], kFallback2);

    const auto all = cfg.client->all_server_ids();
    ASSERT_EQ(all.size(), 3u);
    EXPECT_EQ(all[0], kPrimary);
    EXPECT_EQ(all[1], kFallback1);
    EXPECT_EQ(all[2], kFallback2);
}

TEST(ClientFailoverConfigTest, FailoverBlockParsedWithDefaults) {
    const std::string yaml = std::string("mode: client\nclient:\n  server_id: ") + kPrimary + "\n";
    auto cfg = Config::from_string(yaml).value();
    // Defaults come from FailoverConfig struct.
    EXPECT_EQ(cfg.client->failover.timeout_seconds, 60u);
    EXPECT_EQ(cfg.client->failover.prefer_primary_grace_seconds, 30u);
}

TEST(ClientFailoverConfigTest, FailoverBlockOverrides) {
    const std::string yaml = std::string("mode: client\nclient:\n  server_id: ") + kPrimary +
                             "\n  failover:\n    timeout_seconds: 15\n"
                             "    prefer_primary_grace_seconds: 5\n";
    auto cfg = Config::from_string(yaml).value();
    EXPECT_EQ(cfg.client->failover.timeout_seconds, 15u);
    EXPECT_EQ(cfg.client->failover.prefer_primary_grace_seconds, 5u);
}

TEST(ClientFailoverConfigTest, AliasResolutionMixedWithToxIds) {
    // Build a known-servers store on disk with an alias for the fallback Tox ID.
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto dir =
        std::filesystem::temp_directory_path() / ("toxtunnel_failover_alias_test_" + suffix);
    std::filesystem::create_directories(dir);

    {
        KnownServersStore store(dir);
        KnownServer e1;
        e1.tox_id = kPrimary;
        e1.alias = "primary";
        ASSERT_TRUE(store.upsert(e1));
        KnownServer e2;
        e2.tox_id = kFallback1;
        e2.alias = "backup";
        ASSERT_TRUE(store.upsert(e2));
        auto save = store.save();
        ASSERT_TRUE(save.has_value()) << save.error();
    }

    // Re-open and resolve aliases (mirrors what cli/main.cpp does after merge).
    KnownServersStore lookup(dir);
    ASSERT_FALSE(lookup.last_load_error().has_value());

    EXPECT_EQ(lookup.resolve_tox_id("primary"), kPrimary);
    EXPECT_EQ(lookup.resolve_tox_id("backup"), kFallback1);
    // Bare Tox IDs pass through.
    EXPECT_EQ(lookup.resolve_tox_id(kFallback2), kFallback2);
    // Unknown aliases pass through unchanged so callers surface a clear error.
    EXPECT_EQ(lookup.resolve_tox_id("missing"), "missing");

    std::filesystem::remove_all(dir);
}

TEST(ClientFailoverConfigTest, ValidateRejectsDuplicateFallbacks) {
    const auto primary = make_valid_tox_id_hex(0x01, 0x02);
    const auto fb = make_valid_tox_id_hex(0x03, 0x04);
    Config cfg = Config::default_client();
    ASSERT_TRUE(cfg.client.has_value());
    cfg.client->server_id = primary;
    cfg.client->fallback_server_ids = {fb, fb};
    auto v = cfg.validate();
    EXPECT_FALSE(v.has_value());
}

TEST(ClientFailoverConfigTest, ValidateRejectsFallbackEqualPrimary) {
    const auto primary = make_valid_tox_id_hex(0x01, 0x02);
    Config cfg = Config::default_client();
    ASSERT_TRUE(cfg.client.has_value());
    cfg.client->server_id = primary;
    cfg.client->fallback_server_ids = {primary};
    auto v = cfg.validate();
    EXPECT_FALSE(v.has_value());
}

TEST(ClientFailoverConfigTest, ValidateAcceptsListedFallbacks) {
    const auto primary = make_valid_tox_id_hex(0x01, 0x02);
    const auto fb1 = make_valid_tox_id_hex(0x03, 0x04);
    const auto fb2 = make_valid_tox_id_hex(0x05, 0x06);
    Config cfg = Config::default_client();
    ASSERT_TRUE(cfg.client.has_value());
    cfg.client->server_id = primary;
    cfg.client->fallback_server_ids = {fb1, fb2};
    auto v = cfg.validate();
    EXPECT_TRUE(v.has_value()) << v.error();
}

TEST(ClientFailoverConfigTest, ValidateRejectsZeroTimeoutWithFallbacks) {
    const auto primary = make_valid_tox_id_hex(0x01, 0x02);
    const auto fb = make_valid_tox_id_hex(0x03, 0x04);
    Config cfg = Config::default_client();
    ASSERT_TRUE(cfg.client.has_value());
    cfg.client->server_id = primary;
    cfg.client->fallback_server_ids = {fb};
    cfg.client->failover.timeout_seconds = 0;
    auto v = cfg.validate();
    EXPECT_FALSE(v.has_value());
}

// ---------------------------------------------------------------------------
// Failover state machine (pure decide_failover_switch)
// ---------------------------------------------------------------------------

TEST(ClientFailoverDecisionTest, NoSwitchWhenSingleEndpoint) {
    const auto now = clock_t_::now();
    auto eps = make_endpoints({{kPrimary, false, 9999, 0}}, now);
    FailoverConfig fo{1, 1};
    EXPECT_FALSE(decide_failover_switch(eps, 0, fo, now).has_value());
}

TEST(ClientFailoverDecisionTest, NoSwitchWhenActiveOffline_ButShortDuration) {
    const auto now = clock_t_::now();
    // Primary just went offline 5s ago; threshold is 60s.
    auto eps = make_endpoints({{kPrimary, false, 5, 0}, {kFallback1, true, 0, 30}}, now);
    FailoverConfig fo{60, 30};
    EXPECT_FALSE(decide_failover_switch(eps, 0, fo, now).has_value());
}

TEST(ClientFailoverDecisionTest, SwitchAfterTimeoutToOnlineFallback) {
    const auto now = clock_t_::now();
    auto eps = make_endpoints({{kPrimary, false, 70, 0}, {kFallback1, true, 0, 60}}, now);
    FailoverConfig fo{60, 30};
    auto result = decide_failover_switch(eps, 0, fo, now);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1u);
}

TEST(ClientFailoverDecisionTest, NoSwitchIfNoFallbackOnline) {
    const auto now = clock_t_::now();
    // Both offline for long enough, but no candidate is online.
    auto eps = make_endpoints({{kPrimary, false, 70, 0}, {kFallback1, false, 70, 0}}, now);
    FailoverConfig fo{60, 30};
    EXPECT_FALSE(decide_failover_switch(eps, 0, fo, now).has_value());
}

TEST(ClientFailoverDecisionTest, PrefersLowerIndexFallback) {
    const auto now = clock_t_::now();
    // Active is index 2; both fallback candidates online — pick index 0
    // (primary) once it's available, not index 1.
    auto eps = make_endpoints(
        {{kPrimary, true, 0, 120}, {kFallback1, true, 0, 120}, {kFallback2, false, 70, 0}}, now);
    FailoverConfig fo{60, 30};
    auto result = decide_failover_switch(eps, 2, fo, now);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0u);
}

TEST(ClientFailoverDecisionTest, SwitchBackToPrimaryAfterGrace) {
    const auto now = clock_t_::now();
    // Active is on fallback (index 1), primary back online 31s ago,
    // grace is 30s — switch back.
    auto eps = make_endpoints({{kPrimary, true, 0, 31}, {kFallback1, true, 0, 200}}, now);
    FailoverConfig fo{60, 30};
    auto result = decide_failover_switch(eps, 1, fo, now);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0u);
}

TEST(ClientFailoverDecisionTest, NoSwitchBackBeforeGrace) {
    const auto now = clock_t_::now();
    // Primary online for only 10s; grace is 30s — stay on fallback.
    auto eps = make_endpoints({{kPrimary, true, 0, 10}, {kFallback1, true, 0, 200}}, now);
    FailoverConfig fo{60, 30};
    EXPECT_FALSE(decide_failover_switch(eps, 1, fo, now).has_value());
}

TEST(ClientFailoverDecisionTest, NoSwitchBackIfPrimaryOffline) {
    const auto now = clock_t_::now();
    // Primary offline, fallback online — no preferred-primary switchback,
    // and active fallback is online so no failover-out either.
    auto eps = make_endpoints({{kPrimary, false, 5, 0}, {kFallback1, true, 0, 200}}, now);
    FailoverConfig fo{60, 30};
    EXPECT_FALSE(decide_failover_switch(eps, 1, fo, now).has_value());
}

TEST(ClientFailoverDecisionTest, SequentialFailoverThenSwitchback) {
    // Walk through a scenario: primary offline -> failover -> primary back -> switchback.
    const FailoverConfig fo{60, 30};

    // T0: primary just went offline, fallback online from older session.
    auto t0 = clock_t_::now();
    auto eps = make_endpoints({{kPrimary, false, 5, 0}, {kFallback1, true, 0, 120}}, t0);
    EXPECT_FALSE(decide_failover_switch(eps, 0, fo, t0).has_value());

    // T1: 65s later, primary still offline -> failover to fallback.
    auto t1 = t0 + std::chrono::seconds(65);
    // The endpoints' timestamps are absolute, so the active.offline_since stays
    // at (t0 - 5s) i.e. ~70s ago by t1. Recompute by re-seeding offline_since
    // appropriately:
    auto eps_t1 = make_endpoints({{kPrimary, false, 70, 0}, {kFallback1, true, 0, 185}}, t1);
    auto r1 = decide_failover_switch(eps_t1, 0, fo, t1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 1u);

    // T2: now active is index 1. Primary comes back online and stays for 31s.
    auto t2 = t1 + std::chrono::seconds(50);
    auto eps_t2 = make_endpoints({{kPrimary, true, 0, 31}, {kFallback1, true, 0, 235}}, t2);
    auto r2 = decide_failover_switch(eps_t2, 1, fo, t2);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 0u);
}

}  // namespace
