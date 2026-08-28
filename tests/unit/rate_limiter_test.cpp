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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "toxtunnel/app/rules_engine.hpp"
#include "toxtunnel/app/tunnel_server.hpp"
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
    // At or above kMinActiveByteBurst, so the burst floor does not move it.
    spec.bytes_burst = 100'000;
    rl.set_default_spec(spec);

    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 50'000));
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 49'000));
    // Still 1000 in the bucket, so a 1000-byte request is the last one that
    // fits (refill is 100 B/s, far too slow to matter inside a test).
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 1'000));
    // Now exhausted.
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 100));
    EXPECT_GE(util::MetricsRegistry::instance().rate_limit_bytes_throttled(), 1u);
}

// =============================================================================
// 6. parse_rate_limit_mode round-trips known values.
// =============================================================================

// H-3 / 2026-05-20 finding: rules reload calls clear_all_friend_specs()
// to drop stale per-friend buckets. Without this, a friend removed from
// the new rules would silently retain its old (possibly tightening) spec
// and continue to be limited under stale parameters.
TEST(RateLimiterTest, ClearAllFriendSpecsDropsOverridesAndBuckets) {
    RateLimiter rl;

    // Tight default; loose per-friend override exhausts friend1's bucket.
    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;
    defaults.open_burst = 1;
    rl.set_default_spec(defaults);

    RateLimitSpec loose;
    loose.mode = RateLimitMode::Enforce;
    loose.open_per_sec = 100;
    loose.open_burst = 100;
    rl.set_friend_spec(kFriend1, loose);

    // Drain the loose bucket so its open_tokens are near 0.
    for (int i = 0; i < 100; ++i) {
        (void)rl.try_consume_open(kFriend1);
    }

    // Reload: clear and re-install only the default. friend1 should now
    // be governed by the (tight) default spec, not its old loose state.
    rl.clear_all_friend_specs();
    rl.set_default_spec(defaults);

    EXPECT_EQ(rl.effective_spec(kFriend1).mode, defaults.mode);
    EXPECT_EQ(rl.effective_spec(kFriend1).open_burst, defaults.open_burst);
    // Burst of 1 -> first open allowed, second denied.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
}

// A rules reload is `clear_all_friend_specs()` + `set_default_spec()` +
// re-install of each per-friend block (the exact sequence
// TunnelServer::sync_rate_limiter() runs). `set_default_spec` on its own
// preserves accumulated tokens, and the header used to advertise that as the
// reload behaviour — it is not: the leading clear destroys every bucket, so
// after a SIGHUP each friend has a full burst again and its rejection count
// restarts at 0. This test pins the semantics that actually ship so the
// header comment and the code cannot drift apart again.
TEST(RateLimiterTest, RulesReloadRefillsBucketsAndZeroesRejectionCounts) {
    RateLimiter rl;

    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;  // slow refill: the burst is what we observe
    defaults.open_burst = 2;
    defaults.defaults_present = true;
    rl.set_default_spec(defaults);

    RateLimitOverride ov;
    ov.max_concurrent_tunnels = 3u;
    rl.set_friend_spec(kFriend1, ov);

    // Drain the burst and push the friend into rejection.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
    EXPECT_GE(rl.state(kFriend1).open_rejected, 1u);

    // Reload with an identical ruleset.
    rl.clear_all_friend_specs();
    rl.set_default_spec(defaults);
    rl.set_friend_spec(kFriend1, ov);

    // Per-friend bookkeeping is gone, not carried over.
    EXPECT_EQ(rl.state(kFriend1).open_rejected, 0u);
    // ...and the burst is available again immediately, mid-flood.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
}

// The in-place preservation that `set_default_spec` *does* provide: moving the
// defaults without a surrounding clear keeps accumulated tokens (clamped to
// any shrunken burst) rather than handing out a fresh burst.
TEST(RateLimiterTest, SetDefaultSpecAloneKeepsAccumulatedTokens) {
    RateLimiter rl;

    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;
    defaults.open_burst = 2;
    defaults.defaults_present = true;
    rl.set_default_spec(defaults);

    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));

    // Same defaults pushed again (no clear): the drained bucket stays drained.
    rl.set_default_spec(defaults);
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
    EXPECT_GE(rl.state(kFriend1).open_rejected, 2u);

    // Widening the burst does not retroactively grant the missing tokens
    // either — refill is what fills a bucket, not a spec change.
    RateLimitSpec wider = defaults;
    wider.open_burst = 100;
    rl.set_default_spec(wider);
    EXPECT_LE(rl.state(kFriend1).open_tokens, 1);
}

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
    ASSERT_TRUE(rl.mode.has_value());
    EXPECT_EQ(*rl.mode, RateLimitMode::Enforce);
    ASSERT_TRUE(rl.bytes_per_sec.has_value());
    EXPECT_EQ(*rl.bytes_per_sec, 104857600u);
    ASSERT_TRUE(rl.max_concurrent_tunnels.has_value());
    EXPECT_EQ(*rl.max_concurrent_tunnels, 200u);
    // Fields the block did not name stay disengaged so they can inherit.
    EXPECT_FALSE(rl.open_per_sec.has_value());
    EXPECT_FALSE(rl.open_burst.has_value());
}

// =============================================================================
// 8. Per-friend overrides merge field-by-field onto the defaults.
//
// The original bug: a per-friend `rate_limit:` block replaced the whole
// default spec, so writing a single tightening field (max_concurrent_tunnels)
// zeroed open_per_sec/open_burst and switched that friend's OPEN limiting
// *off* entirely. Every test below pins one half of the merge contract.
// =============================================================================

// Builds the exact rules file from the bug report: defaults enforce an OPEN
// rate, one friend tightens only `max_concurrent_tunnels`.
constexpr char kMergeYaml[] = R"(
rate_limit_defaults:
  mode: enforce
  open_per_sec: 2
  open_burst: 3

rules:
  - friend: "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFF1234"
    rate_limit:
      max_concurrent_tunnels: 2
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";

TEST(RateLimiterMergeTest, UnwrittenFieldsInheritDefaults) {
    auto parsed = RulesEngine::from_string(kMergeYaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();
    ASSERT_EQ(engine.rules().size(), 1u);

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);

    const auto eff = rl.effective_spec(kFriend1);
    // The one written field wins...
    EXPECT_EQ(eff.max_concurrent_tunnels, 2u);
    // ...and everything else still comes from the defaults. Before the fix
    // these were 0/0/Off, i.e. "no limiting at all for this friend".
    EXPECT_EQ(eff.mode, RateLimitMode::Enforce);
    EXPECT_EQ(eff.open_per_sec, 2u);
    EXPECT_EQ(eff.open_burst, 3u);
}

TEST(RateLimiterMergeTest, InheritedOpenLimitStillEnforced) {
    auto parsed = RulesEngine::from_string(kMergeYaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);

    // Burst of 3 inherited from the defaults: three OPENs pass, the fourth is
    // rejected. Pre-fix this friend could open unboundedly.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
}

TEST(RateLimiterMergeTest, ExplicitZeroDisablesThatLimitOnly) {
    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;
    defaults.open_burst = 1;
    defaults.max_concurrent_tunnels = 50;

    RateLimiter rl;
    rl.set_default_spec(defaults);

    // Explicit 0 = "exempt this friend from the OPEN rate", which must be
    // distinguishable from simply not writing the field.
    RateLimitOverride exempt;
    exempt.open_per_sec = 0u;
    rl.set_friend_spec(kFriend1, exempt);

    const auto eff = rl.effective_spec(kFriend1);
    EXPECT_EQ(eff.open_per_sec, 0u);
    EXPECT_EQ(eff.open_burst, 1u);               // untouched by the override
    EXPECT_EQ(eff.max_concurrent_tunnels, 50u);  // untouched by the override
    EXPECT_EQ(eff.mode, RateLimitMode::Enforce);
    for (int i = 0; i < 20; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1)) << "iteration " << i;
    }

    // The contrast case: a friend that writes an unrelated field keeps the
    // default OPEN rate and runs out after one token.
    RateLimitOverride unrelated;
    unrelated.max_concurrent_tunnels = 7u;
    rl.set_friend_spec(kFriend2, unrelated);
    EXPECT_EQ(rl.effective_spec(kFriend2).open_per_sec, 1u);
    EXPECT_TRUE(rl.try_consume_open(kFriend2));
    EXPECT_FALSE(rl.try_consume_open(kFriend2));
}

TEST(RateLimiterMergeTest, ModeIsInheritedWhenNotWritten) {
    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Report;
    defaults.open_per_sec = 1;
    defaults.open_burst = 1;

    RateLimiter rl;
    rl.set_default_spec(defaults);

    RateLimitOverride ov;
    ov.open_burst = 2u;
    rl.set_friend_spec(kFriend1, ov);

    EXPECT_EQ(rl.effective_spec(kFriend1).mode, RateLimitMode::Report);
    // Report never denies, so the over-budget call still returns true.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));

    // ...and an explicitly written mode still overrides the default.
    RateLimitOverride enforcing;
    enforcing.mode = RateLimitMode::Enforce;
    rl.set_friend_spec(kFriend2, enforcing);
    EXPECT_EQ(rl.effective_spec(kFriend2).mode, RateLimitMode::Enforce);
    EXPECT_TRUE(rl.try_consume_open(kFriend2));
    EXPECT_FALSE(rl.try_consume_open(kFriend2));
}

// =============================================================================
// 8b. An explicit `rate_limit_defaults: {mode: off}` must survive the merge.
//
// Release-blocking bug: the merge decided "there are no defaults to inherit"
// from `RateLimitSpec::empty()`, which is true for a defaults block that says
// nothing but `mode: off` (Off + all counters 0). Any friend with a
// `rate_limit:` block that omitted `mode` was therefore flipped to `Enforce` —
// an operator's explicit *disable* switch silently re-enabled enforcement.
// These tests go through `RulesEngine::from_string()` so they cover the real
// parse → merge path, not just the helper.
// =============================================================================

TEST(RateLimiterMergeTest, ExplicitOffDefaultsAreInheritedByPerFriendBlock) {
    const std::string yaml = R"(
rate_limit_defaults:
  mode: off

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      max_concurrent_tunnels: 2
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();
    ASSERT_EQ(engine.rules().size(), 1u);

    // The defaults are value-indistinguishable from "no block at all" — only
    // the provenance bit separates them. If this pair of expectations ever
    // flips, the bug is back.
    EXPECT_TRUE(engine.rate_limit_defaults().empty());
    EXPECT_TRUE(engine.rate_limit_defaults().defaults_present);
    EXPECT_EQ(engine.rate_limit_defaults().mode, RateLimitMode::Off);
    EXPECT_FALSE(engine.rules().front().rate_limit.mode.has_value());

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);

    const auto eff = rl.effective_spec(kFriend1);
    EXPECT_EQ(eff.mode, RateLimitMode::Off) << "explicit `mode: off` must not be flipped on";
    // The friend's own tightening still lands — `max_concurrent_tunnels` is
    // applied by TunnelServer::apply_tunnel_cap() regardless of mode, so
    // "limiting off" does not mean "unbounded tunnels".
    EXPECT_EQ(eff.max_concurrent_tunnels, 2u);
}

TEST(RateLimiterMergeTest, ExplicitOffDefaultsWithBudgetsStillNeverDeny) {
    // Same shape, but the defaults also carry OPEN budgets. `mode: off` is
    // what decides; the numbers are inherited but inert.
    const std::string yaml = R"(
rate_limit_defaults:
  mode: off
  open_per_sec: 1
  open_burst: 1

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      max_concurrent_tunnels: 2
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);

    EXPECT_EQ(rl.effective_spec(kFriend1).mode, RateLimitMode::Off);
    // Burst of 1 would deny from the second call under Enforce.
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(rl.try_consume_open(kFriend1)) << "iteration " << i;
    }
}

TEST(RateLimiterMergeTest, ExplicitOffDefaultsApplyToFriendsWithoutAnyBlock) {
    const std::string yaml = R"(
rate_limit_defaults:
  mode: off
  open_per_sec: 1
  open_burst: 1

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();

    RateLimiter rl;
    rl.set_default_spec(parsed.value().rate_limit_defaults());
    // No per-friend entry at all: the plain defaults govern.
    EXPECT_EQ(rl.effective_spec(kFriend1).mode, RateLimitMode::Off);
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
}

// The provenance bit must not weaken the inheritance of a *non*-off default:
// a present block that names a mode is still inherited verbatim.
TEST(RateLimiterMergeTest, PresentDefaultsInheritReportMode) {
    const std::string yaml = R"(
rate_limit_defaults:
  mode: report
  open_per_sec: 1
  open_burst: 1

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      max_concurrent_tunnels: 2
)";
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);
    EXPECT_EQ(rl.effective_spec(kFriend1).mode, RateLimitMode::Report);
}

// With no `rate_limit_defaults:` there is no mode to inherit; a friend-only
// block must still take effect rather than parsing as an inert mode: off.
TEST(RateLimiterMergeTest, FriendOnlyBlockDefaultsToEnforce) {
    const std::string yaml = R"(
rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      open_per_sec: 1
      open_burst: 1
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();
    ASSERT_EQ(engine.rules().size(), 1u);
    EXPECT_FALSE(engine.rules().front().rate_limit.mode.has_value());
    // No block was written, so the fallback below is legitimate — this is the
    // half of the pair that `ExplicitOffDefaultsAreInheritedByPerFriendBlock`
    // must stay distinguishable from.
    EXPECT_FALSE(engine.rate_limit_defaults().defaults_present);

    RateLimiter rl;
    rl.set_default_spec(engine.rate_limit_defaults());  // empty
    rl.set_friend_spec(engine.rules().front().friend_pk, engine.rules().front().rate_limit);

    EXPECT_EQ(rl.effective_spec(kFriend1).mode, RateLimitMode::Enforce);
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
}

// The merge is recomputed when the defaults move, so the order in which
// TunnelServer::sync_rate_limiter() pushes defaults and overrides cannot
// leave a friend resolved against a stale baseline.
TEST(RateLimiterMergeTest, DefaultsChangeRemergesLiveOverrides) {
    RateLimiter rl;

    RateLimitOverride ov;
    ov.max_concurrent_tunnels = 4u;
    rl.set_friend_spec(kFriend1, ov);

    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 5;
    defaults.open_burst = 9;
    rl.set_default_spec(defaults);

    const auto eff = rl.effective_spec(kFriend1);
    EXPECT_EQ(eff.max_concurrent_tunnels, 4u);
    EXPECT_EQ(eff.open_burst, 9u);
    EXPECT_EQ(eff.mode, RateLimitMode::Enforce);
}

// An empty override is not a way to disable limiting — it simply inherits.
TEST(RateLimiterMergeTest, EmptyOverrideInheritsDefaults) {
    RateLimitSpec defaults;
    defaults.mode = RateLimitMode::Enforce;
    defaults.open_per_sec = 1;
    defaults.open_burst = 1;

    RateLimiter rl;
    rl.set_default_spec(defaults);
    rl.set_friend_spec(kFriend1, RateLimitOverride{});

    EXPECT_EQ(rl.effective_spec(kFriend1), defaults);
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));
}

// =============================================================================
// 9. Byte limits parse, and the exposition describes what enforcement does.
// =============================================================================

TEST(RateLimiterByteLimitTest, ConfiguredByteLimitsAreAcceptedNotRejected) {
    const std::string yaml = R"(
rate_limit_defaults:
  mode: enforce
  bytes_per_sec: 20480
  bytes_burst: 40960

rules:
  - friend: ")" + std::string(kFriend1) +
                             R"("
    rate_limit:
      bytes_per_sec: 104857600
    allow:
      - host: "127.0.0.1"
        ports: [22]
)";
    // Byte limits must not be a fatal parse error: shipped docs advertised
    // them, so upgrading a daemon whose rules file uses them has to keep
    // working (a warning is logged instead).
    auto parsed = RulesEngine::from_string(yaml);
    ASSERT_TRUE(parsed) << parsed.error();
    const auto& engine = parsed.value();
    EXPECT_TRUE(engine.rate_limit_defaults().has_byte_limits());
    ASSERT_EQ(engine.rules().size(), 1u);
    EXPECT_TRUE(engine.rules().front().rate_limit.has_byte_limits());
}

// The HELP text used to say the counter was structurally pinned at 0. It is
// not any more, and an exposition that still says so would send an operator
// looking for a bug when the throttle fires. Pin the corrected wording.
TEST(RateLimiterByteLimitTest, MetricsHelpTextDescribesRealThrottling) {
    const std::string rendered = util::MetricsRegistry::instance().render();
    const auto pos = rendered.find("# HELP toxtunnel_rate_limit_bytes_throttled_total");
    ASSERT_NE(pos, std::string::npos);
    const auto eol = rendered.find('\n', pos);
    const std::string help_line = rendered.substr(pos, eol - pos);
    EXPECT_EQ(help_line.find("Always 0"), std::string::npos) << help_line;
    EXPECT_EQ(help_line.find("not wired"), std::string::npos) << help_line;
    EXPECT_NE(help_line.find("bytes_per_sec"), std::string::npos) << help_line;
}

TEST(RateLimiterByteLimitTest, ExplicitZeroByteLimitIsNotFlaggedAsConfigured) {
    RateLimitOverride ov;
    ov.bytes_per_sec = 0u;
    ov.bytes_burst = 0u;
    // Written-but-zero is an opt-out, not a request for a feature that does
    // not exist, so it must not trigger the "not implemented" warning.
    EXPECT_FALSE(ov.has_byte_limits());
    EXPECT_FALSE(ov.empty());
}

// =============================================================================
// replace_all() — atomic rules-generation swap.
//
// The reload path used to be `clear_all_friend_specs()` + `set_default_spec()`
// + N x `set_friend_spec()`, each taking `mu_` on its own. A TUNNEL_OPEN
// arriving in one of those gaps was judged against a generation that no rules
// file ever described. These tests pin (a) that the gap really was observable,
// (b) that `replace_all` closes it, and (c) that closing it did not quietly
// change the documented "a reload refills every bucket" semantics.
// =============================================================================

namespace {

/// Defaults deliberately tight enough that falling back to them is instantly
/// visible: one token, then denial.
RateLimitSpec tight_defaults() {
    RateLimitSpec spec;
    spec.defaults_present = true;
    spec.mode = RateLimitMode::Enforce;
    spec.open_per_sec = 1;
    spec.open_burst = 1;
    return spec;
}

/// A per-friend override so generous that a friend carrying it can never be
/// denied within a test's lifetime.
RateLimitOverride generous_override() {
    RateLimitOverride ov;
    ov.mode = RateLimitMode::Enforce;
    ov.open_per_sec = 1000000u;
    ov.open_burst = 1000000u;
    return ov;
}

}  // namespace

// The bug, reproduced deterministically and without threads: the intermediate
// state is reachable from a single thread simply by stepping the old sequence,
// because each call published its own result. Between the clear and the
// re-install, a friend whose rules grant it a million OPENs/s is governed by
// the one-token defaults and gets denied.
TEST(RateLimiterReplaceAllTest, StepwiseReloadExposesAnIntermediateState) {
    RateLimiter rl;
    rl.replace_all(tight_defaults(), {{kFriend1, generous_override()}});

    // Under the real (whole) generation the friend is not limited.
    for (int i = 0; i < 10; ++i) {
        ASSERT_TRUE(rl.try_consume_open(kFriend1)) << "iteration " << i;
    }

    // Now step the old three-call sequence and stop after the first step.
    rl.clear_all_friend_specs();
    // The friend's override is gone but the new one is not installed yet, so
    // it now falls back to the defaults: one token, then denial.
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1))
        << "the stepwise reload must be able to deny a friend the rules never limited; "
           "if this passes, the test no longer reproduces the race replace_all fixes";
}

// Same rules, applied atomically, hammered by a concurrent consumer: no
// TUNNEL_OPEN may ever observe the tight defaults, because the friend's
// override is installed under the same lock hold that dropped the old one.
TEST(RateLimiterReplaceAllTest, ConcurrentOpensNeverObserveAPartialGeneration) {
    RateLimiter rl;
    const std::vector<RateLimiter::FriendOverride> overrides{{kFriend1, generous_override()}};
    rl.replace_all(tight_defaults(), overrides);

    // Both sides run a FIXED number of iterations rather than "reader spins
    // until the writer says stop". With the stop-flag shape the reader's sample
    // size depended entirely on scheduling: on macOS the writer finished all
    // 5000 reloads before the reader got a slice, so the run recorded a single
    // open and the sanity floor — the assertion that keeps "no denials" from
    // passing vacuously — failed even though the invariant held. A bounded
    // reader makes the test's power the same on every platform.
    constexpr int kReloads = 5000;
    constexpr int kOpens = 5000;

    std::atomic<int> denials{0};
    std::atomic<long> opens{0};

    std::thread consumer([&] {
        for (int i = 0; i < kOpens; ++i) {
            if (!rl.try_consume_open(kFriend1)) {
                denials.fetch_add(1, std::memory_order_relaxed);
            }
            opens.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Many reloads: the window the stepwise version leaves open is short, so
    // the test's power comes from hitting it repeatedly.
    for (int i = 0; i < kReloads; ++i) {
        rl.replace_all(tight_defaults(), overrides);
    }
    consumer.join();

    // Sanity: the consumer must actually have run, or "no denials" is vacuous.
    EXPECT_EQ(opens.load(), kOpens);
    EXPECT_EQ(denials.load(), 0);
}

// The reload semantics documented on `clear_all_friend_specs()` and in
// docs/CONFIGURATION.md: buckets are destroyed, so tokens come back full and
// rejection counters restart. `replace_all` must NOT have quietly upgraded this
// to token preservation — operators (and the docs) depend on the reset.
TEST(RateLimiterReplaceAllTest, ReloadStillResetsTokensAndRejectionCounters) {
    RateLimiter rl;
    RateLimitOverride ov;
    ov.mode = RateLimitMode::Enforce;
    ov.open_per_sec = 1;  // slow enough that no refill lands during the test
    ov.open_burst = 2;
    const std::vector<RateLimiter::FriendOverride> overrides{{kFriend1, ov}};

    rl.replace_all(RateLimitSpec{}, overrides);
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
    EXPECT_FALSE(rl.try_consume_open(kFriend1));

    auto drained = rl.state(kFriend1);
    EXPECT_EQ(drained.open_tokens, 0);
    EXPECT_EQ(drained.open_rejected, 1u);

    // Reloading the very same rules refills the bucket and zeroes the counter.
    rl.replace_all(RateLimitSpec{}, overrides);
    auto reloaded = rl.state(kFriend1);
    EXPECT_EQ(reloaded.open_tokens, 2);
    EXPECT_EQ(reloaded.open_rejected, 0u);
    EXPECT_TRUE(rl.try_consume_open(kFriend1));
}

// A friend dropped from the new rules must not keep its old bucket — the reason
// the reload had to clear in the first place.
TEST(RateLimiterReplaceAllTest, DropsFriendsAbsentFromTheNewGeneration) {
    RateLimiter rl;
    rl.replace_all(tight_defaults(), {{kFriend1, generous_override()}});
    EXPECT_EQ(rl.effective_spec(kFriend1).open_burst, 1000000u);

    // New generation names only kFriend2.
    rl.replace_all(tight_defaults(), {{kFriend2, generous_override()}});
    EXPECT_EQ(rl.effective_spec(kFriend1).open_burst, tight_defaults().open_burst);
    EXPECT_EQ(rl.effective_spec(kFriend2).open_burst, 1000000u);
}

// `replace_all` is the whole three-call sequence, so it must also publish the
// new defaults to friends that carry no override at all.
TEST(RateLimiterReplaceAllTest, PublishesNewDefaultsToFriendsWithoutOverrides) {
    RateLimiter rl;
    rl.replace_all(tight_defaults(), {});
    EXPECT_TRUE(rl.try_consume_open(kFriend2));
    EXPECT_FALSE(rl.try_consume_open(kFriend2));

    RateLimitSpec off;
    off.defaults_present = true;
    off.mode = RateLimitMode::Off;
    rl.replace_all(off, {});
    EXPECT_TRUE(rl.try_consume_open(kFriend2));
    EXPECT_EQ(rl.effective_spec(kFriend2).mode, RateLimitMode::Off);
}

// Rules carry sparse blocks; an empty one means "inherit the defaults" and must
// not materialise a bucket, exactly as `set_friend_spec` treats it.
TEST(RateLimiterReplaceAllTest, EmptyOverridesAreSkipped) {
    RateLimiter rl;
    rl.replace_all(tight_defaults(), {{kFriend1, RateLimitOverride{}}});
    EXPECT_EQ(rl.effective_spec(kFriend1), tight_defaults());
}

// =============================================================================
// 10. Byte-budget ENFORCEMENT.
//
// `bytes_per_sec` / `bytes_burst` used to parse, validate, refill and do
// nothing: no production code path consulted the byte buckets, so a configured
// byte limit shaped no traffic and
// `toxtunnel_rate_limit_bytes_throttled_total` was structurally pinned at 0.
// These tests cover the wiring that made it real, and are written so they FAIL
// against the un-wired implementation — a byte-limit test that passes on inert
// code proves nothing.
//
// Everything here drives an injected clock. Enforcement is a *rate*, and a rate
// asserted against wall time is a flake waiting for a loaded CI box; the
// Windows ARM runner's ~15.6 ms timer granularity would make any sleep-based
// version of these tests useless.
// =============================================================================

namespace {

/// Fake monotonic clock, in nanoseconds.
class FakeClock {
   public:
    /// Starts non-zero: 0 is the limiter's "this bucket has never refilled"
    /// sentinel, so a clock that began there would swallow the first interval.
    [[nodiscard]] std::int64_t now() const noexcept { return now_ns_; }

    void advance(std::chrono::nanoseconds delta) noexcept { now_ns_ += delta.count(); }

   private:
    std::int64_t now_ns_{1'000'000'000LL};
};

/// A limiter driven by `clock`, with a single default byte budget.
RateLimitSpec byte_spec(RateLimitMode mode, std::uint64_t per_sec, std::uint64_t burst) {
    RateLimitSpec spec;
    spec.defaults_present = true;
    spec.mode = mode;
    spec.bytes_per_sec = per_sec;
    spec.bytes_burst = burst;
    return spec;
}

/// A packet body of `n` bytes, tagged with `marker` so an ordering assertion
/// can tell two same-sized packets apart.
std::vector<std::uint8_t> packet_of(std::size_t n, std::uint8_t marker) {
    std::vector<std::uint8_t> p(n, marker);
    return p;
}

std::uint64_t throttle_metric() {
    return util::MetricsRegistry::instance().rate_limit_bytes_throttled();
}

}  // namespace

// --- Bucket-level semantics -------------------------------------------------

TEST(ByteEnforcementTest, OffModeMetersNothing) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Off, 1'000, 100'000));

    const auto before = throttle_metric();
    for (int i = 0; i < 500; ++i) {
        EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 4'096)) << "iteration " << i;
    }
    EXPECT_EQ(throttle_metric(), before) << "mode: off must not even account";
}

TEST(ByteEnforcementTest, ReportModeCountsButNeverRefuses) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Report, 1'000, 100'000));

    const auto before = throttle_metric();
    std::chrono::nanoseconds wait{1};
    // 200 x 4 KiB = 800 KiB against a 100 KB burst and a 1 KB/s refill: most of
    // this is far over budget, and every single call must still be allowed.
    for (int i = 0; i < 200; ++i) {
        EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 4'096, wait)) << "iteration " << i;
        EXPECT_EQ(wait, std::chrono::nanoseconds::zero())
            << "report never defers, so it must never ask the caller to wait";
    }
    EXPECT_GT(throttle_metric(), before) << "report must still move the counter";
    EXPECT_GT(rl.state(kFriend1).bytes_throttled, 0u);
    // Count-only: the bucket is clamped at the floor, never driven into debt.
    EXPECT_GE(rl.state(kFriend1).bytes_tokens, 0);
}

TEST(ByteEnforcementTest, EnforceAllowsTheBurstThenRefuses) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    // The burst is spendable up front, with no time passing at all.
    std::size_t admitted = 0;
    std::chrono::nanoseconds wait{};
    while (rl.try_consume_bytes(kFriend1, 1'000, wait)) {
        admitted += 1'000;
        ASSERT_LE(admitted, 200'000u) << "burst must be finite";
    }
    EXPECT_EQ(admitted, 100'000u);
    // ...and the refusal tells the caller when to come back rather than
    // leaving it to poll.
    EXPECT_GT(wait, std::chrono::nanoseconds::zero());
    EXPECT_LE(wait, std::chrono::seconds(1)) << "1000 bytes at 1000 B/s is one second";
    // Never into debt.
    EXPECT_GE(rl.state(kFriend1).bytes_tokens, 0);
}

TEST(ByteEnforcementTest, BucketRefillsAtTheConfiguredRate) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 10'000, 100'000));

    // Drain.
    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 100'000));
    ASSERT_FALSE(rl.try_consume_bytes(kFriend1, 1));

    clock.advance(std::chrono::seconds(1));
    // Exactly one second of budget, no more.
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 10'000));
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1));

    // And it saturates at the burst rather than accruing without bound.
    clock.advance(std::chrono::seconds(3600));
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 100'000));
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1));
}

// Discriminating test for the refill cursor. The pre-existing implementation
// stamped one shared cursor to `now` on every call and floored the token gain,
// so any caller polling faster than one whole token per call threw the
// remainder away and accrued NOTHING, forever. Harmless while the only consumer
// was TUNNEL_OPEN (opens are rare); fatal the moment a 1362-byte data frame
// asks every few hundred microseconds.
TEST(ByteEnforcementTest, SubTokenIntervalsAccrueInsteadOfBeingDiscarded) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 100'000));  // drain

    // One simulated second, sampled every 100 us: each step is worth 0.1 of a
    // token, i.e. always floors to zero on its own.
    int admitted = 0;
    for (int i = 0; i < 10'000; ++i) {
        clock.advance(std::chrono::microseconds(100));
        if (rl.try_consume_bytes(kFriend1, 1)) {
            ++admitted;
        }
    }
    // 1000 B/s for one second, exactly. The old cursor yields 0.
    EXPECT_EQ(admitted, 1'000);
}

TEST(ByteEnforcementTest, EachFriendGetsItsOwnBucket) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    // Drain friend1 completely.
    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 100'000));
    ASSERT_FALSE(rl.try_consume_bytes(kFriend1, 1'000));

    // friend2 is untouched by that: same spec, its own tokens.
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(rl.try_consume_bytes(kFriend2, 1'000)) << "iteration " << i;
    }
    EXPECT_FALSE(rl.try_consume_bytes(kFriend2, 1'000));
    // ...and draining friend2 did not resurrect friend1.
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1'000));
}

// --- Budget normalisation ---------------------------------------------------

TEST(ByteEnforcementTest, EngagedBurstIsRaisedToFitOneMaximumFrame) {
    RateLimiter rl;
    // A burst below one max-size TUNNEL_DATA payload would make such a frame
    // permanently unservable — the throttle would defer it on every retry and
    // the tunnel would hang with no error. The floor makes progress
    // unconditional.
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 1'024));
    EXPECT_EQ(rl.effective_spec(kFriend1).bytes_burst, kMinActiveByteBurst);

    // Any frame the wire can carry therefore fits once the bucket is full.
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 65'535));
}

TEST(ByteEnforcementTest, ZeroBurstStaysAnOptOut) {
    RateLimiter rl;
    // `bytes_burst: 0` is the operator switching byte limiting off. The floor
    // must not switch it back on.
    RateLimitSpec spec = byte_spec(RateLimitMode::Enforce, 1'000, 0);
    rl.set_default_spec(spec);
    EXPECT_EQ(rl.effective_spec(kFriend1).bytes_burst, 0u);
    EXPECT_FALSE(rl.effective_spec(kFriend1).byte_limiting_engaged());
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 1'000'000)) << "iteration " << i;
    }
}

TEST(ByteEnforcementTest, AbsurdBudgetsAreClampedRatherThanOverflowing) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    // The refill maths multiplies a budget by 1e9 in int64. Without the clamp
    // this wraps negative and starves the friend permanently — the exact
    // failure mode the OPEN bucket's saturation short-circuit was added for.
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1ULL << 62, 1ULL << 62));
    const auto eff = rl.effective_spec(kFriend1);
    EXPECT_EQ(eff.bytes_per_sec, kMaxByteBudget);
    EXPECT_EQ(eff.bytes_burst, kMaxByteBudget);

    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, kMaxByteBudget));
    ASSERT_FALSE(rl.try_consume_bytes(kFriend1, 1));
    clock.advance(std::chrono::seconds(1));
    // Refill still moves forward instead of wrapping to a negative gain.
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 1'000'000));
}

// The remainder must be kept only while the bucket has room for it. A full
// bucket that keeps banking sub-token credit while it overflows would hand out
// the next token early, so the enforced rate would drift above the configured
// one — slowly, and only under exactly the traffic pattern that makes the
// limiter matter.
TEST(ByteEnforcementTest, SaturatedBucketDoesNotBankCreditItCannotHold) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    // 1000 B/s: one token per millisecond.
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    // Prime the refill cursor. Without this first touch the probe below exits
    // through the "never refilled yet" branch and never reaches the saturation
    // test at all — the test would pass against the bug.
    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 0));

    // Sit at capacity for 0.9 of a token's worth of time, and touch the bucket
    // there so a refill runs. A zero-byte request is the probe: it drives the
    // refill without consuming, so the bucket really is still full — a probe
    // that consumed would leave room and miss the branch entirely.
    clock.advance(std::chrono::microseconds(900));
    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 0));
    ASSERT_EQ(rl.state(kFriend1).bytes_tokens, 100'000);

    // Drain it completely, with no time passing.
    ASSERT_TRUE(rl.try_consume_bytes(kFriend1, 100'000));
    ASSERT_EQ(rl.state(kFriend1).bytes_tokens, 0);

    // 100 us later, a tenth of a token is owed — nothing. If the full bucket
    // had banked the earlier 900 us, this would total a millisecond and pay out
    // a token that was never earned by the drained bucket.
    clock.advance(std::chrono::microseconds(100));
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1))
        << "a token arrived early: credit was banked while the bucket was full";

    // ...and the accrual is otherwise intact: a further 900 us completes it.
    clock.advance(std::chrono::microseconds(900));
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 1));
}

TEST(ByteEnforcementTest, HugeRequestCannotCreditTheBucket) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    // Clamping `bytes` after casting size_t -> int64 can land on a negative
    // `need`, which sails past the shortfall test and then *adds* to the bucket
    // on the subtraction. Clamping unsigned-first is what prevents it.
    const std::size_t huge = static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max()) + 1;
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, huge));
    EXPECT_LE(rl.state(kFriend1).bytes_tokens, 0);
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1));
}

TEST(ByteEnforcementTest, RequestLargerThanCapacityIsServedNotLivelocked) {
    RateLimiter rl;
    FakeClock clock;
    rl.set_clock([&clock] { return clock.now(); });
    rl.set_default_spec(byte_spec(RateLimitMode::Enforce, 100'000, 100'000));

    // A bucket cannot hold more than its capacity, so charging at capacity is
    // the only answer that ever makes progress. Refusing forever would be a
    // livelock wearing a rate limit's clothes.
    EXPECT_TRUE(rl.try_consume_bytes(kFriend1, 500'000));
    EXPECT_FALSE(rl.try_consume_bytes(kFriend1, 1));
}

// --- The inbound gate: ordering, loss-freedom, sustained rate ---------------

namespace {

using app::detail::InboundByteThrottle;
using Admission = InboundByteThrottle::Admission;

/// Drive one throttle the way TunnelServer does: offer packets, replay whatever
/// the budget releases, and advance the clock when it says to wait.
struct ThrottleHarness {
    RateLimiter limiter;
    FakeClock clock;
    InboundByteThrottle throttle{limiter, kFriend1};
    /// Packets in the order they were released for dispatch.
    std::vector<std::vector<std::uint8_t>> dispatched;

    explicit ThrottleHarness(const RateLimitSpec& spec) {
        limiter.set_clock([this] { return clock.now(); });
        // The throttle's own clock drives the deferral-age rail; it must be the
        // same fake one, or the rail would be measured against wall time while
        // the budget is measured against simulated time.
        throttle.set_clock([this] { return clock.now(); });
        limiter.set_default_spec(spec);
        throttle.set_active(limiter.effective_spec(kFriend1).byte_limiting_engaged());
    }

    /// How long each offered packet says it may safely wait. Tests that care
    /// about the deadline rail set this; the rest leave it effectively
    /// unlimited so the budget is the only thing under test.
    std::chrono::nanoseconds max_wait{std::chrono::hours(1)};

    Admission offer(const std::vector<std::uint8_t>& packet, tunnel::FrameType type,
                    std::size_t data_bytes) {
        const auto outcome =
            throttle.admit(std::span<const std::uint8_t>(packet), type, data_bytes, max_wait);
        if (outcome == Admission::Dispatch) {
            dispatched.push_back(packet);
        }
        return outcome;
    }

    Admission offer_data(const std::vector<std::uint8_t>& packet) {
        return offer(packet, tunnel::FrameType::TUNNEL_DATA, packet.size());
    }

    /// Replay everything the budget currently allows.
    std::size_t drain() {
        std::size_t n = 0;
        std::vector<std::uint8_t> out;
        while (throttle.next_ready(out)) {
            dispatched.push_back(std::move(out));
            ++n;
        }
        return n;
    }

    /// Drain, and if anything is still parked, jump the clock to the moment the
    /// limiter said the head would be servable. Returns false once empty.
    bool drain_and_wait() {
        drain();
        if (throttle.empty()) {
            return false;
        }
        clock.advance(throttle.retry_after());
        return true;
    }
};

}  // namespace

TEST(InboundByteThrottleTest, InactiveThrottleDispatchesEverythingUntouched) {
    // No byte budget configured — the v0.3.0 default. Nothing is metered and
    // nothing is queued, so the data path costs exactly what it used to.
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 0, 0)};
    ASSERT_FALSE(h.throttle.active());

    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(h.offer_data(packet_of(1'400, static_cast<std::uint8_t>(i))),
                  Admission::Dispatch);
    }
    EXPECT_TRUE(h.throttle.empty());
    EXPECT_EQ(h.dispatched.size(), 100u);
}

TEST(InboundByteThrottleTest, ReportModeNeverParksButDoesCount) {
    ThrottleHarness h{byte_spec(RateLimitMode::Report, 1'000, 100'000)};
    ASSERT_TRUE(h.throttle.active()) << "report must still meter, or the counter cannot move";

    const auto before = throttle_metric();
    // 200 KiB against a 100 KB burst: comfortably over budget.
    for (int i = 0; i < 150; ++i) {
        ASSERT_EQ(h.offer_data(packet_of(1'400, static_cast<std::uint8_t>(i))), Admission::Dispatch)
            << "iteration " << i << ": report must never defer a frame";
    }
    EXPECT_TRUE(h.throttle.empty());
    EXPECT_EQ(h.dispatched.size(), 150u);
    EXPECT_GT(throttle_metric(), before);
}

// The central no-data-loss property: under enforcement the receiver gets every
// byte the sender sent, in the order it was sent, just later.
TEST(InboundByteThrottleTest, EnforcementDelaysEveryByteAndLosesNone) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10'000, 100'000)};
    ASSERT_TRUE(h.throttle.active());

    constexpr int kFrames = 400;  // 400 x 1400 B = 560 KB, 5.6x the burst
    std::vector<std::vector<std::uint8_t>> sent;
    sent.reserve(kFrames);
    for (int i = 0; i < kFrames; ++i) {
        sent.push_back(packet_of(1'400, static_cast<std::uint8_t>(i)));
        const auto outcome = h.offer_data(sent.back());
        // Nothing here should reach a rail: 560 KB is far under the memory
        // bound, and the drain below advances only simulated time.
        ASSERT_NE(outcome, Admission::Release) << "iteration " << i;
    }
    // Most of it is necessarily parked; the throttle would be doing nothing
    // otherwise.
    ASSERT_GT(h.throttle.backlog_frames(), 0u);

    // Let simulated time run until the backlog clears. Bounded so a livelock
    // fails the test instead of hanging it.
    for (int guard = 0; guard < 10'000 && h.drain_and_wait(); ++guard) {
    }
    ASSERT_TRUE(h.throttle.empty()) << "backlog never drained";

    // Every frame, exactly once, in order.
    ASSERT_EQ(h.dispatched.size(), sent.size());
    for (std::size_t i = 0; i < sent.size(); ++i) {
        EXPECT_EQ(h.dispatched[i], sent[i]) << "frame " << i << " lost, duplicated or reordered";
    }
}

// The rate the throttle actually holds: burst up front, then bytes_per_sec.
TEST(InboundByteThrottleTest, SustainedRateTracksTheConfiguredBudget) {
    constexpr std::uint64_t kRate = 10'000;    // bytes/sec
    constexpr std::uint64_t kBurst = 100'000;  // bytes
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, kRate, kBurst)};

    // A sender with an unlimited supply, offering a frame every millisecond of
    // simulated time for 10 simulated seconds.
    constexpr int kMillis = 10'000;
    constexpr std::size_t kFrameBytes = 1'400;
    for (int ms = 0; ms < kMillis; ++ms) {
        const auto packet = packet_of(kFrameBytes, static_cast<std::uint8_t>(ms));
        // Keep the backlog well clear of the memory rail: this test is about
        // the rate the budget holds, and a rail release would (correctly)
        // exceed it. The rails have their own tests.
        if (h.throttle.backlog_bytes() < InboundByteThrottle::kDefaultMaxBacklogBytes / 2) {
            (void)h.offer_data(packet);
        }
        h.drain();
        h.clock.advance(std::chrono::milliseconds(1));
    }

    const std::size_t delivered = h.dispatched.size() * kFrameBytes;
    // Ceiling: the burst, plus the rate for the elapsed 10 s. Frames are
    // granular, so allow one frame of slop either way.
    const std::size_t ceiling = kBurst + kRate * 10 + kFrameBytes;
    const std::size_t floor_bytes = kBurst + kRate * 10 - 2 * kFrameBytes;
    EXPECT_LE(delivered, ceiling) << "throttle let more through than the budget allows";
    EXPECT_GE(delivered, floor_bytes) << "throttle is stingier than the budget promises";
}

TEST(InboundByteThrottleTest, StreamFramesQueueBehindDeferredData) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};

    // Exhaust the burst so the next DATA frame is definitely parked.
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    const auto parked_data = packet_of(1'400, 0xBB);
    ASSERT_EQ(h.offer_data(parked_data), Admission::Parked);

    // A TUNNEL_CLOSE that overtook that DATA would tear the tunnel down and
    // strand the bytes behind it — silent truncation of a lossless stream.
    const auto close_packet = packet_of(8, 0xCC);
    EXPECT_EQ(h.offer(close_packet, tunnel::FrameType::TUNNEL_CLOSE, 0), Admission::Parked);
    EXPECT_EQ(h.throttle.backlog_frames(), 2u);

    for (int guard = 0; guard < 10'000 && h.drain_and_wait(); ++guard) {
    }
    ASSERT_EQ(h.dispatched.size(), 3u);
    EXPECT_EQ(h.dispatched[1], parked_data);
    EXPECT_EQ(h.dispatched[2], close_packet) << "CLOSE must not overtake the data it follows";
}

TEST(InboundByteThrottleTest, LivenessAndWindowFramesBypassTheBacklog) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);

    // Holding PING/PONG behind a throttled stream would let the keepalive
    // declare a healthy peer dead and tear down every tunnel it has — losing
    // vastly more than the throttle saved. TUNNEL_ACK is credit for the
    // opposite direction and has no ordering relationship with inbound DATA.
    EXPECT_EQ(h.offer(packet_of(8, 0x01), tunnel::FrameType::PING, 0), Admission::Dispatch);
    EXPECT_EQ(h.offer(packet_of(8, 0x02), tunnel::FrameType::PONG, 0), Admission::Dispatch);
    EXPECT_EQ(h.offer(packet_of(8, 0x03), tunnel::FrameType::TUNNEL_ACK, 0), Admission::Dispatch);
    EXPECT_EQ(h.offer(packet_of(8, 0x04), tunnel::FrameType::INFO_REQUEST, 0), Admission::Dispatch);
    EXPECT_EQ(h.throttle.backlog_frames(), 1u) << "only the DATA frame should be parked";
}

// The memory rail fails OPEN: it releases the backlog in order rather than
// dropping bytes or closing the friend. A friend with a large
// max_concurrent_tunnels can reach this rail with entirely compliant traffic,
// so treating it as proof of misbehaviour would disconnect innocent peers.
TEST(InboundByteThrottleTest, BacklogRailReleasesInOrderInsteadOfDiscarding) {
    RateLimiter limiter;
    FakeClock clock;
    limiter.set_clock([&clock] { return clock.now(); });
    limiter.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));
    // Deliberately tiny rail so the test does not have to build 32 MiB.
    InboundByteThrottle throttle{limiter, kFriend1, /*max_backlog_bytes=*/10'000};
    throttle.set_active(true);
    throttle.set_clock([&clock] { return clock.now(); });

    ASSERT_EQ(throttle.admit(std::span<const std::uint8_t>(packet_of(100'000, 0xAA)),
                             tunnel::FrameType::TUNNEL_DATA, 100'000),
              Admission::Dispatch);

    std::vector<std::vector<std::uint8_t>> offered;
    Admission last = Admission::Dispatch;
    for (int i = 0; i < 100; ++i) {
        offered.push_back(packet_of(1'400, static_cast<std::uint8_t>(i)));
        last = throttle.admit(std::span<const std::uint8_t>(offered.back()),
                              tunnel::FrameType::TUNNEL_DATA, offered.back().size());
        if (last != Admission::Parked) {
            break;
        }
    }
    ASSERT_EQ(last, Admission::Release) << "the rail must tell the caller to drain now";
    EXPECT_GT(offered.size(), 1u);
    EXPECT_TRUE(throttle.releasing());

    // Draining now ignores the budget until the queue is empty — every offered
    // packet comes back, in order, with nothing dropped.
    std::vector<std::vector<std::uint8_t>> released;
    std::vector<std::uint8_t> out;
    while (throttle.next_ready(out)) {
        released.push_back(std::move(out));
    }
    ASSERT_EQ(released.size(), offered.size());
    for (std::size_t i = 0; i < offered.size(); ++i) {
        EXPECT_EQ(released[i], offered[i]) << "packet " << i;
    }
    EXPECT_TRUE(throttle.empty());
    EXPECT_FALSE(throttle.releasing()) << "the release latch clears once the backlog drains";
}

// The deferral-age rail, and why it is a correctness bound rather than a
// nicety: the idle reaper and the half-close linger cap judge a tunnel by when
// it last saw TUNNEL_DATA. A parked frame has NOT reached its tunnel, so a long
// enough deferral makes an actively-receiving tunnel look idle — the reaper
// closes it, releases its id, and the replay then delivers bytes to a tunnel
// that no longer exists (or to a recycled id). Releasing first is what keeps
// the no-loss guarantee true.
TEST(InboundByteThrottleTest, ReleaseDeadlineFiresBeforeTheReaperCouldAct) {
    // 10 B/s: a 1400-byte frame needs 140 s of budget, comfortably past the
    // 60 s deadline below, so the deadline is unambiguously what releases it.
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10, 100'000)};
    h.max_wait = std::chrono::seconds(60);

    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    const auto parked = packet_of(1'400, 0xBB);
    ASSERT_EQ(h.offer_data(parked), Admission::Parked);

    // Just under the deadline: still governed by the budget (590 bytes accrued
    // of the 1400 needed), still waiting.
    h.clock.advance(std::chrono::seconds(59));
    EXPECT_EQ(h.drain(), 0u);
    EXPECT_FALSE(h.throttle.empty());

    // Past it: released regardless of the budget, which is still ~800 bytes
    // short of servicing the frame.
    h.clock.advance(std::chrono::seconds(2));
    EXPECT_EQ(h.drain(), 1u);
    ASSERT_EQ(h.dispatched.size(), 2u);
    EXPECT_EQ(h.dispatched[1], parked) << "the aged frame must be delivered, not dropped";
}

// The deadline is per frame, not per queue, and the queue honours the EARLIEST
// one. This is the case a head-based age check gets wrong: a frame arriving
// LATER can belong to a tunnel that was already nearly idle, so it becomes
// reapable sooner than everything queued ahead of it.
TEST(InboundByteThrottleTest, EarliestDeadlineGovernsTheWholeBacklog) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10, 100'000)};

    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);

    // First frame: a busy tunnel, can afford a long wait.
    h.max_wait = std::chrono::seconds(600);
    const auto patient = packet_of(1'400, 0xB1);
    ASSERT_EQ(h.offer_data(patient), Admission::Parked);

    // Second frame: its tunnel is seconds from being reaped.
    h.max_wait = std::chrono::seconds(5);
    const auto urgent = packet_of(1'400, 0xB2);
    ASSERT_EQ(h.offer_data(urgent), Admission::Parked);

    h.clock.advance(std::chrono::seconds(4));
    EXPECT_EQ(h.drain(), 0u) << "nothing is due yet";

    // The later frame's tighter deadline releases the whole backlog, in order.
    h.clock.advance(std::chrono::seconds(2));
    EXPECT_EQ(h.drain(), 2u);
    ASSERT_EQ(h.dispatched.size(), 3u);
    EXPECT_EQ(h.dispatched[1], patient);
    EXPECT_EQ(h.dispatched[2], urgent);
}

// A tunnel already at its reaper deadline gets a zero budget. Such a frame must
// come back as Release, not Parked: Parked hands it to the retry timer, which
// is scheduled from the refill rate and would happily sleep while the reaper
// closes the tunnel underneath it.
TEST(InboundByteThrottleTest, ZeroBudgetReleasesImmediatelyRatherThanParking) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);

    h.max_wait = std::chrono::nanoseconds::zero();
    const auto at_risk = packet_of(1'400, 0xBB);
    EXPECT_EQ(h.offer_data(at_risk), Admission::Release)
        << "an at-risk tunnel's frame must not be left to the rate-based retry timer";
    EXPECT_TRUE(h.throttle.deadline_release_pending()) << "and the release must be reportable";
    EXPECT_EQ(h.drain(), 1u);
    ASSERT_EQ(h.dispatched.size(), 2u);
    EXPECT_EQ(h.dispatched[1], at_risk);
    EXPECT_TRUE(h.throttle.take_deadline_release_notice());
    EXPECT_FALSE(h.throttle.take_deadline_release_notice()) << "the notice is consumed once";
}

// The retry timer must never sleep past the release deadline: `retry_after()`
// only knows when the budget will be ready. This is the bound the server takes
// the min against.
TEST(InboundByteThrottleTest, TimeUntilReleaseBoundsTheRetryTimer) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10, 100'000)};
    EXPECT_EQ(h.throttle.time_until_release(), std::chrono::nanoseconds::max())
        << "no deadline while the queue is empty";

    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    h.max_wait = std::chrono::milliseconds(200);
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);

    // The budget alone would have the caller wait ~140 s (1400 bytes at 10 B/s);
    // the deadline caps that at 200 ms.
    EXPECT_GT(h.throttle.retry_after(), std::chrono::seconds(100));
    EXPECT_LE(h.throttle.time_until_release(), std::chrono::milliseconds(200));

    h.clock.advance(std::chrono::milliseconds(150));
    EXPECT_EQ(h.throttle.time_until_release(), std::chrono::milliseconds(50));
    h.clock.advance(std::chrono::milliseconds(100));
    EXPECT_EQ(h.throttle.time_until_release(), std::chrono::nanoseconds::zero());
    EXPECT_EQ(h.drain(), 1u);
}

// The throttle metric must measure traffic, not the retry cadence: a frame
// parked for a second is re-offered on every timer tick, and counting each of
// those would let one frame contribute hundreds.
TEST(InboundByteThrottleTest, RetriesDoNotInflateTheThrottleCounter) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);

    const auto before = throttle_metric();
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);
    const auto after_first_judgement = throttle_metric();
    EXPECT_EQ(after_first_judgement, before + 1) << "one frame, one increment";

    // Poll it many times without advancing far enough to service it.
    for (int i = 0; i < 50; ++i) {
        EXPECT_EQ(h.drain(), 0u);
        h.clock.advance(std::chrono::milliseconds(1));
    }
    EXPECT_EQ(throttle_metric(), after_first_judgement)
        << "retries of an already-counted frame must be silent";
}

// ...but every frame the budget delays must be counted once. A frame queued
// behind an existing backlog never reaches the bucket — the head is what is
// short — so counting only the frames that personally found it empty would
// report a long congestion episode as a single frame.
TEST(InboundByteThrottleTest, EveryDeferredFrameIsCountedExactlyOnce) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);

    const auto before = throttle_metric();
    constexpr int kDeferred = 25;
    for (int i = 0; i < kDeferred; ++i) {
        ASSERT_EQ(h.offer_data(packet_of(1'400, static_cast<std::uint8_t>(i))), Admission::Parked)
            << "iteration " << i;
    }
    EXPECT_EQ(throttle_metric(), before + kDeferred);

    // Draining them adds nothing further: the replay is silent.
    for (int guard = 0; guard < 10'000 && h.drain_and_wait(); ++guard) {
    }
    ASSERT_TRUE(h.throttle.empty());
    EXPECT_EQ(throttle_metric(), before + kDeferred);
}

// Control frames queued behind deferred data carry no metered payload, so they
// must not inflate a *bytes* counter.
TEST(InboundByteThrottleTest, QueuedControlFramesDoNotCountAsThrottledBytes) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);

    const auto before = throttle_metric();
    EXPECT_EQ(h.offer(packet_of(8, 0xCC), tunnel::FrameType::TUNNEL_CLOSE, 0), Admission::Parked);
    EXPECT_EQ(throttle_metric(), before);
}

TEST(InboundByteThrottleTest, ThrottledFriendDoesNotAffectAnother) {
    RateLimiter limiter;
    FakeClock clock;
    limiter.set_clock([&clock] { return clock.now(); });
    limiter.set_default_spec(byte_spec(RateLimitMode::Enforce, 1'000, 100'000));

    InboundByteThrottle noisy{limiter, kFriend1};
    InboundByteThrottle quiet{limiter, kFriend2};
    noisy.set_active(true);
    quiet.set_active(true);

    // Drain friend1's budget and push it into deferral.
    ASSERT_EQ(noisy.admit(std::span<const std::uint8_t>(packet_of(100'000, 0xAA)),
                          tunnel::FrameType::TUNNEL_DATA, 100'000),
              Admission::Dispatch);
    const auto noisy_packet = packet_of(1'400, 0xBB);
    ASSERT_EQ(noisy.admit(std::span<const std::uint8_t>(noisy_packet),
                          tunnel::FrameType::TUNNEL_DATA, noisy_packet.size()),
              Admission::Parked);

    // friend2 has its own bucket and must be entirely unaffected.
    for (int i = 0; i < 50; ++i) {
        const auto packet = packet_of(1'400, static_cast<std::uint8_t>(i));
        EXPECT_EQ(quiet.admit(std::span<const std::uint8_t>(packet), tunnel::FrameType::TUNNEL_DATA,
                              packet.size()),
                  Admission::Dispatch)
            << "iteration " << i;
    }
    EXPECT_TRUE(quiet.empty());
    EXPECT_EQ(noisy.backlog_frames(), 1u);
}

TEST(InboundByteThrottleTest, RetryHintIsUsableAsATimerDelay) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 10'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);

    // Never zero (that would busy-loop the server's retry timer) and never
    // longer than the time the shortfall actually needs.
    const auto wait = h.throttle.retry_after();
    EXPECT_GT(wait, std::chrono::nanoseconds::zero());
    EXPECT_LE(wait, std::chrono::milliseconds(140)) << "1400 B at 10 kB/s is 140 ms";

    // Waiting exactly that long is enough — the drain must make progress, not
    // ask again.
    h.clock.advance(wait);
    EXPECT_EQ(h.drain(), 1u);
}

// A budget removed by a hot reload must not strand what is already parked:
// dispatching new frames past a non-empty backlog would reorder the stream.
TEST(InboundByteThrottleTest, DeactivationStillDrainsInOrder) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    const auto first = packet_of(1'400, 0xB1);
    const auto second = packet_of(1'400, 0xB2);
    ASSERT_EQ(h.offer_data(first), Admission::Parked);
    ASSERT_EQ(h.offer_data(second), Admission::Parked);

    h.throttle.set_active(false);
    // Still queued (order), but now released without waiting (no budget).
    const auto third = packet_of(1'400, 0xB3);
    EXPECT_EQ(h.offer_data(third), Admission::Parked);
    EXPECT_EQ(h.drain(), 3u);

    ASSERT_EQ(h.dispatched.size(), 4u);
    EXPECT_EQ(h.dispatched[1], first);
    EXPECT_EQ(h.dispatched[2], second);
    EXPECT_EQ(h.dispatched[3], third);
}

TEST(InboundByteThrottleTest, ClearDropsTheBacklog) {
    ThrottleHarness h{byte_spec(RateLimitMode::Enforce, 1'000, 100'000)};
    ASSERT_EQ(h.offer_data(packet_of(100'000, 0xAA)), Admission::Dispatch);
    ASSERT_EQ(h.offer_data(packet_of(1'400, 0xBB)), Admission::Parked);

    // What teardown does when the friend goes away. These bytes were never
    // acknowledged, so the peer still counts them as in flight and resume's
    // offset reconciliation reports the gap rather than hiding it.
    h.throttle.clear();
    EXPECT_TRUE(h.throttle.empty());
    EXPECT_EQ(h.throttle.backlog_bytes(), 0u);
}

}  // namespace
}  // namespace toxtunnel::test
