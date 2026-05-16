// Per-friend rate-limiter unit tests.
//
// Pins the design-doc contract:
//
//   1. `Off` mode never denies.
//   2. `Enforce` mode denies when the open bucket is empty.
//   3. `Report` mode counts rejections in the metrics but still returns
//      true so the caller proceeds (shadow mode).
//   4. Default spec applies when no per-friend override is installed; the
//      override wins when present.
//   5. RulesEngine parses top-level `rate_limit_defaults:` and per-friend
//      `rate_limit:` blocks.

#include "toxtunnel/app/rate_limiter.hpp"

#include <gtest/gtest.h>

#include <thread>

#include "toxtunnel/app/rules_engine.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::test {
namespace {

constexpr char kFriend1[] = "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFF1234";
constexpr char kFriend2[] = "1122334455667788112233445566778811223344556677881122334455667788";

// =============================================================================
// 1. Off mode is a no-op.
// =============================================================================

TEST(RateLimiterTest, OffModeNeverDenies) {
    RateLimiter rl;
    RateLimitSpec spec;
    spec.mode = RateLimitMode::Off;
    spec.open_per_sec = 1;
    spec.open_burst = 1;
    rl.set_default_spec(spec);

    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1));
    }
}

// =============================================================================
// 2. Enforce mode denies once burst is exhausted.
// =============================================================================

TEST(RateLimiterTest, EnforceModeDeniesAfterBurstExhausted) {
    util::MetricsRegistry::instance().reset();
    RateLimiter rl;
    RateLimitSpec spec;
    spec.mode = RateLimitMode::Enforce;
    spec.open_per_sec = 1;  // very slow refill; burst is what we test
    spec.open_burst = 5;
    rl.set_default_spec(spec);

    // First 5 succeed.
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1));
    }
    // 6th fails.
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
    EXPECT_GE(util::MetricsRegistry::instance().rate_limit_open_rejected(), 1u);
}

// =============================================================================
// 3. Report mode counts rejections but always allows.
// =============================================================================

TEST(RateLimiterTest, ReportModeAlwaysAllowsButCounts) {
    util::MetricsRegistry::instance().reset();
    RateLimiter rl;
    RateLimitSpec spec;
    spec.mode = RateLimitMode::Report;
    spec.open_per_sec = 1;
    spec.open_burst = 2;
    rl.set_default_spec(spec);

    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1));
    }
    // The 3rd...10th calls counted as rejections (8 of them).
    EXPECT_GE(util::MetricsRegistry::instance().rate_limit_open_rejected(), 5u);
}

// =============================================================================
// 4. Per-friend override wins over default.
// =============================================================================

TEST(RateLimiterTest, PerFriendSpecWinsOverDefault) {
    RateLimiter rl;

    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;
    defaults.open_burst = 1;
    rl.set_default_spec(defaults);

    RateLimitSpec override_spec;
    override_spec.mode = RateLimitMode::Enforce;
    override_spec.open_per_sec = 1;
    override_spec.open_burst = 100;  // much higher than default
    rl.set_friend_spec(kFriend1, override_spec);

    // friend1: override → allowed for many calls.
    for (int i = 0; i < 50; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1));
    }
    // friend2: falls back to default → only 1 call.
    EXPECT_TRUE(rl.try_consume_open(kFriend2));
    EXPECT_FALSE(rl.try_consume_open(kFriend2));
}

// =============================================================================
// 5. Bytes bucket behaves analogously.
// =============================================================================

TEST(RateLimiterTest, BytesBucketDeniesWhenExhausted) {
    util::MetricsRegistry::instance().reset();
    RateLimiter rl;
    RateLimitSpec spec;
    spec.mode = RateLimitMode::Enforce;
    spec.bytes_per_sec = 100;
    spec.bytes_burst = 1024;
    rl.set_default_spec(spec);

    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 500));
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 500));
    // Exactly at burst (1000 < 1024); next 100 bytes still fits.
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 24));
    // Now exhausted.
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 100));
    EXPECT_GE(util::MetricsRegistry::instance().rate_limit_bytes_throttled(), 1u);
}

// =============================================================================
// 6. parse_rate_limit_mode round-trips known values.
// =============================================================================

TEST(RateLimiterTest, ParseModeRoundTrip) {
    RateLimitMode m = RateLimitMode::Off;
    EXPECT_TRUE(parse_rate_limit_mode("enforce", m));
    EXPECT_EQ(m, RateLimitMode::Enforce);
    EXPECT_TRUE(parse_rate_limit_mode("report", m));
    EXPECT_EQ(m, RateLimitMode::Report);
    EXPECT_TRUE(parse_rate_limit_mode("off", m));
    EXPECT_EQ(m, RateLimitMode::Off);
    EXPECT_FALSE(parse_rate_limit_mode("nope", m));
}

// =============================================================================
// 7. RulesEngine parses top-level rate_limit_defaults + per-friend block.
// =============================================================================

TEST(RulesEngineRateLimitTest, ParsesDefaultsAndPerFriendOverride) {
    const std::string yaml = R"(
rate_limit_defaults:
  mode: enforce
  open_per_sec: 10
  open_burst: 50
  bytes_per_sec: 1048576
  bytes_burst: 4194304
  max_concurrent_tunnels: 100

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      mode: enforce
      bytes_per_sec: 104857600
      max_concurrent_tunnels: 200
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    auto result = RulesEngine::from_string(yaml);
    ASSERT_TRUE(result) << result.error();
    const auto& engine = result.value();

    EXPECT_EQ(engine.rate_limit_defaults().mode, RateLimitMode::Enforce);
    EXPECT_EQ(engine.rate_limit_defaults().open_per_sec, 10u);
    EXPECT_EQ(engine.rate_limit_defaults().open_burst, 50u);
    EXPECT_EQ(engine.rate_limit_defaults().bytes_per_sec, 1048576u);

    ASSERT_EQ(engine.rules().size(), 1u);
    const auto& rl = engine.rules().front().rate_limit;
    EXPECT_EQ(rl.mode, RateLimitMode::Enforce);
    EXPECT_EQ(rl.bytes_per_sec, 104857600u);
    EXPECT_EQ(rl.max_concurrent_tunnels, 200u);
}

}  // namespace
}  // namespace toxtunnel::test
