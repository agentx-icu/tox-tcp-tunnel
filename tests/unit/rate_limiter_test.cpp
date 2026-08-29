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
#include <string>
#include <thread>
#include <utility>
#include <vector>

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
// 9. Byte limits are parsed but inert — pin the honesty contract so nobody
//    reads a green test suite as proof that byte throttling works.
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

// The Prometheus HELP text is the last place that still described byte
// throttling as a working feature. An operator who alerts on this counter is
// alerting on a number that cannot move, so the exposition has to say so.
TEST(RateLimiterByteLimitTest, MetricsHelpTextAdmitsByteLimitsAreInert) {
    const std::string rendered = util::MetricsRegistry::instance().render();
    const auto pos = rendered.find("# HELP toxtunnel_rate_limit_bytes_throttled_total");
    ASSERT_NE(pos, std::string::npos);
    const auto eol = rendered.find('\n', pos);
    const std::string help_line = rendered.substr(pos, eol - pos);
    EXPECT_NE(help_line.find("Always 0"), std::string::npos) << help_line;
    EXPECT_NE(help_line.find("not wired"), std::string::npos) << help_line;
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

}  // namespace
}  // namespace toxtunnel::test
