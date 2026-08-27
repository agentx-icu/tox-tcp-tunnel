#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <set>
#include <thread>
#include <vector>

#include "toxtunnel/util/logger.hpp"

// ---------------------------------------------------------------------------
// util::LogThrottle — rate limiter behind Logger::*_throttled
// ---------------------------------------------------------------------------

using toxtunnel::util::KeyedLogThrottle;
using toxtunnel::util::log_key;
using toxtunnel::util::LogThrottle;

namespace {

constexpr std::int64_t kNsPerMs = 1000000;

constexpr std::int64_t ms_to_ns(std::int64_t ms) noexcept {
    return ms * kNsPerMs;
}

}  // namespace

TEST(LogThrottleTest, FirstCallIsAlwaysAdmitted) {
    LogThrottle throttle{std::chrono::milliseconds(1000)};
    LogThrottle::Decision decision;

    EXPECT_TRUE(throttle.allow(decision));
    EXPECT_EQ(decision.suppressed, 0u);
    EXPECT_EQ(decision.window_ms, 0u);
}

TEST(LogThrottleTest, SuppressesWithinInterval) {
    LogThrottle throttle{std::chrono::milliseconds(1000)};
    LogThrottle::Decision decision;

    ASSERT_TRUE(throttle.allow(decision));
    for (int i = 0; i < 500; ++i) {
        EXPECT_FALSE(throttle.allow(decision));
    }
    EXPECT_EQ(throttle.pending_suppressed(), 500u);
    EXPECT_EQ(throttle.total(), 501u);
}

TEST(LogThrottleTest, AdmitsAgainAfterIntervalAndReportsTally) {
    // Short interval so the test does not sleep for a noticeable time.
    LogThrottle throttle{std::chrono::milliseconds(20)};
    LogThrottle::Decision decision;

    ASSERT_TRUE(throttle.allow(decision));
    for (int i = 0; i < 10; ++i) {
        ASSERT_FALSE(throttle.allow(decision));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(40));

    ASSERT_TRUE(throttle.allow(decision));
    EXPECT_EQ(decision.suppressed, 10u);
    // The window spans at least the sleep we performed.
    EXPECT_GE(decision.window_ms, 20u);
    // The tally resets once reported.
    EXPECT_EQ(throttle.pending_suppressed(), 0u);
}

TEST(LogThrottleTest, ZeroIntervalAdmitsEverything) {
    LogThrottle throttle{std::chrono::milliseconds(0)};
    LogThrottle::Decision decision;

    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(throttle.allow(decision));
    }
    EXPECT_EQ(throttle.pending_suppressed(), 0u);
    EXPECT_EQ(throttle.total(), 100u);
}

TEST(LogThrottleTest, TakeSuppressedDrainsTally) {
    LogThrottle throttle{std::chrono::milliseconds(1000)};
    LogThrottle::Decision decision;

    ASSERT_TRUE(throttle.allow(decision));
    ASSERT_FALSE(throttle.allow(decision));
    ASSERT_FALSE(throttle.allow(decision));

    EXPECT_EQ(throttle.take_suppressed(), 2u);
    EXPECT_EQ(throttle.pending_suppressed(), 0u);
}

// The throttle is consulted from the Tox thread and from tunnel data paths
// concurrently, so the "one admission per interval" guarantee must hold under
// races and no event may be lost from the accounting.
TEST(LogThrottleTest, ConcurrentCallersAdmitExactlyOneAndLoseNothing) {
    constexpr int kThreads = 8;
    constexpr int kCallsPerThread = 5000;

    LogThrottle throttle{std::chrono::seconds(60)};
    std::atomic<int> admitted{0};
    std::atomic<std::uint64_t> reported_suppressed{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            LogThrottle::Decision decision;
            for (int i = 0; i < kCallsPerThread; ++i) {
                if (throttle.allow(decision)) {
                    admitted.fetch_add(1, std::memory_order_relaxed);
                    reported_suppressed.fetch_add(decision.suppressed, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    // The interval is far longer than the test, so exactly one call wins.
    EXPECT_EQ(admitted.load(), 1);
    EXPECT_EQ(throttle.total(), static_cast<std::uint64_t>(kThreads) * kCallsPerThread);
    // Every call is accounted for: admitted + reported + still-pending.
    EXPECT_EQ(reported_suppressed.load() + throttle.pending_suppressed() + 1u, throttle.total());
}

// Smoke test of the Logger facade wrapper: the throttled entry points must be
// callable with the usual fmt arguments and must not blow up when the level
// filters them out.
TEST(LogThrottleTest, LoggerFacadeAcceptsThrottledCalls) {
    using toxtunnel::util::Logger;

    static LogThrottle throttle{std::chrono::milliseconds(50)};
    for (int i = 0; i < 200; ++i) {
        Logger::debug_throttled(throttle, "throttled debug {} {}", i, "payload");
        Logger::warn_throttled(throttle, "throttled warn {}", i);
    }
    // 400 calls, at most a couple admitted within the 50 ms window.
    EXPECT_EQ(throttle.total(), 400u);
    EXPECT_GT(throttle.pending_suppressed(), 300u);
}

// ---------------------------------------------------------------------------
// Regression: rewound emission timestamps (window_ms underflow)
// ---------------------------------------------------------------------------
//
// A CAS winner can be descheduled between claiming its slot and publishing its
// timestamp; a *later* window's winner then publishes first. When the stalled
// winner resumes it holds an `emit_ns` that is older than what is already
// recorded. The subtraction `emit_ns - last` is negative there, and widening it
// to std::uint64_t used to print `[+N suppressed in 18446744073709551615ms]`.
//
// That interleaving cannot be produced through `allow()`, because `allow()`
// only admits a caller once `next_emit_ns_` (always one interval *ahead* of
// `last_emit_ns_`) has elapsed — a winner reached through the public API can
// never carry a timestamp older than the recorded one. The publish step is
// therefore driven directly through `record_emission_for_test`, which is the
// exact code `allow()` runs after winning.

TEST(LogThrottleTest, LateWinnerPublishingOlderTimestampDoesNotUnderflowWindow) {
    LogThrottle throttle{std::chrono::milliseconds(1000)};
    const std::int64_t base = ms_to_ns(1000000);

    // First emission: no previous window to measure against.
    EXPECT_EQ(throttle.record_emission_for_test(base), 0u);
    // A winner five seconds later publishes normally.
    EXPECT_EQ(throttle.record_emission_for_test(base + ms_to_ns(5000)), 5000u);

    // Now the stalled winner from one second in resumes and publishes. Its
    // window is meaningless, so it must saturate to zero rather than wrap.
    EXPECT_EQ(throttle.record_emission_for_test(base + ms_to_ns(1000)), 0u);
}

TEST(LogThrottleTest, EmissionTimestampNeverMovesBackwards) {
    LogThrottle throttle{std::chrono::milliseconds(1000)};
    const std::int64_t base = ms_to_ns(1000000);

    throttle.record_emission_for_test(base);
    throttle.record_emission_for_test(base + ms_to_ns(5000));
    ASSERT_EQ(throttle.last_emit_ns_for_test(), base + ms_to_ns(5000));

    // The stalled winner must not rewind the anchor...
    throttle.record_emission_for_test(base + ms_to_ns(1000));
    EXPECT_EQ(throttle.last_emit_ns_for_test(), base + ms_to_ns(5000));

    // ...so the *next* genuine window is still measured from the newest
    // emission (3 s), not from the rewound one (would have read 7 s).
    EXPECT_EQ(throttle.record_emission_for_test(base + ms_to_ns(8000)), 3000u);
}

// Same hazard, exercised concurrently: many threads publish timestamps out of
// order, mimicking winners that were stalled by varying amounts. No window may
// come back absurd and the anchor must end on the newest timestamp.
TEST(LogThrottleTest, ConcurrentOutOfOrderPublishesStayMonotonicAndSane) {
    constexpr int kThreads = 8;
    constexpr int kStepsPerThread = 2000;
    const std::int64_t base = ms_to_ns(1000000);
    const std::int64_t newest = base + ms_to_ns(kStepsPerThread - 1);

    LogThrottle throttle{std::chrono::milliseconds(1000)};
    std::atomic<std::uint64_t> max_window{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        // Half the threads walk time forwards, half backwards, so every thread
        // is at some point the "stalled winner" relative to another.
        const bool forward = (t % 2) == 0;
        threads.emplace_back([&, forward] {
            for (int i = 0; i < kStepsPerThread; ++i) {
                const int step = forward ? i : (kStepsPerThread - 1 - i);
                const std::uint64_t window =
                    throttle.record_emission_for_test(base + ms_to_ns(step));
                std::uint64_t previous = max_window.load(std::memory_order_relaxed);
                while (window > previous && !max_window.compare_exchange_weak(
                                                previous, window, std::memory_order_relaxed)) {
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    // The whole simulated span is kStepsPerThread ms; anything larger means a
    // subtraction wrapped.
    EXPECT_LE(max_window.load(), static_cast<std::uint64_t>(kStepsPerThread));
    EXPECT_EQ(throttle.last_emit_ns_for_test(), newest);
}

// ---------------------------------------------------------------------------
// Regression: stale clock reading must not admit two lines back to back
// ---------------------------------------------------------------------------
//
// A caller can be descheduled between sampling the clock and claiming the
// emission slot. Deriving the next deadline from the stale sample would put it
// in the past, admitting the very next call as well. `allow()` re-reads the
// clock after the gate, which `allow_with_stale_now_for_test` lets us verify by
// injecting the stale sample the scheduler would otherwise have to produce.

TEST(LogThrottleTest, StaleClockSampleStillArmsTheFullInterval) {
    constexpr std::int64_t kIntervalMs = 5000;
    LogThrottle throttle{std::chrono::milliseconds(kIntervalMs)};
    LogThrottle::Decision decision;

    // Pretend the caller sampled the clock ten intervals ago and only now
    // reaches the claim.
    const std::int64_t stale = LogThrottle::now_ns() - ms_to_ns(10 * kIntervalMs);
    ASSERT_TRUE(throttle.allow_with_stale_now_for_test(stale, decision));

    // The deadline must be an interval past *now*, not past the stale sample
    // (which would already be ~45 s in the past).
    EXPECT_GT(throttle.next_emit_ns_for_test(), LogThrottle::now_ns());
    // The recorded emission instant likewise reflects reality, not the sample.
    EXPECT_GT(throttle.last_emit_ns_for_test(), stale + ms_to_ns(kIntervalMs));

    // The observable consequence: no immediate second line.
    EXPECT_FALSE(throttle.allow(decision));
    EXPECT_EQ(throttle.pending_suppressed(), 1u);
}

// Concurrency across real window boundaries: the earlier concurrent test used a
// 60 s interval and so never crossed one. Here the interval is short enough
// that many windows elapse while eight threads hammer the site.
TEST(LogThrottleTest, ConcurrentCallersCrossWindowsWithoutAbsurdWindows) {
    constexpr int kThreads = 8;
    constexpr auto kInterval = std::chrono::milliseconds(2);
    constexpr auto kDuration = std::chrono::milliseconds(300);

    LogThrottle throttle{kInterval};
    std::atomic<int> admitted{0};
    std::atomic<std::uint64_t> max_window{0};
    std::atomic<bool> stop{false};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            LogThrottle::Decision decision;
            int spins = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                if (throttle.allow(decision)) {
                    admitted.fetch_add(1, std::memory_order_relaxed);
                    std::uint64_t previous = max_window.load(std::memory_order_relaxed);
                    while (decision.window_ms > previous &&
                           !max_window.compare_exchange_weak(previous, decision.window_ms,
                                                             std::memory_order_relaxed)) {
                    }
                }
                // Yield often so threads are genuinely interleaved (and get
                // descheduled at arbitrary points inside allow()).
                if ((++spins & 0x3f) == 0) {
                    std::this_thread::yield();
                }
            }
        });
    }
    std::this_thread::sleep_for(kDuration);
    stop.store(true, std::memory_order_relaxed);
    for (auto& thread : threads) {
        thread.join();
    }

    // Several windows must actually have elapsed, otherwise this test proves
    // nothing about boundary crossings.
    EXPECT_GE(admitted.load(), 2);
    // No window may exceed the test's own wall time by a wide margin; the
    // underflow bug produced ~1.8e19 here.
    EXPECT_LE(max_window.load(), 10u * static_cast<std::uint64_t>(kDuration.count()));
    // And the throttle still bounds the output rate: at most one line per
    // interval over the run, with generous slack for a loaded scheduler.
    EXPECT_LE(admitted.load(), 4 * static_cast<int>(kDuration / kInterval));
}

// ---------------------------------------------------------------------------
// util::KeyedLogThrottle — per-condition buckets
// ---------------------------------------------------------------------------

TEST(KeyedLogThrottleTest, DistinctKeysHaveIndependentBudgets) {
    using Keyed = KeyedLogThrottle<64>;
    // The keys below must not collide for this test to mean anything; if a
    // future hash change makes them share a bucket, pick different ones.
    ASSERT_NE(Keyed::bucket_index(log_key(1, 0)), Keyed::bucket_index(log_key(2, 0)));
    ASSERT_NE(Keyed::bucket_index(log_key(1, 0)), Keyed::bucket_index(log_key(1, 1)));

    Keyed throttle{std::chrono::seconds(60)};
    Keyed::Decision decision;

    ASSERT_TRUE(throttle.allow(log_key(1, 0), decision));
    for (int i = 0; i < 100; ++i) {
        ASSERT_FALSE(throttle.allow(log_key(1, 0), decision));
    }

    // A second peer failing during peer 1's burst is still reported...
    EXPECT_TRUE(throttle.allow(log_key(2, 0), decision));
    // ...and so is a different failure reason on the same peer.
    EXPECT_TRUE(throttle.allow(log_key(1, 1), decision));
}

TEST(KeyedLogThrottleTest, SameKeySharesOneBucket) {
    KeyedLogThrottle<16> throttle{std::chrono::seconds(60)};
    KeyedLogThrottle<16>::Decision decision;

    ASSERT_TRUE(throttle.allow(log_key(7, 3), decision));
    EXPECT_FALSE(throttle.allow(log_key(7, 3), decision));
    // for_key() hands back that same bucket, so the Logger overloads that take
    // a plain LogThrottle& see the identical state.
    EXPECT_EQ(&throttle.for_key(log_key(7, 3)), &throttle.for_key(log_key(7, 3)));
    EXPECT_EQ(throttle.for_key(log_key(7, 3)).pending_suppressed(), 1u);
}

// Composite keys pack the peer id in the high half. A plain `key % Buckets`
// would ignore that half entirely (2^32 is a multiple of any power-of-two
// bucket count) and collapse every peer onto one bucket, which is precisely the
// aggregation this class exists to avoid. Mixing must spread them.
TEST(KeyedLogThrottleTest, CompositeKeysSpreadAcrossBuckets) {
    using Keyed = KeyedLogThrottle<64>;

    std::set<std::size_t> buckets;
    for (std::uint32_t peer = 0; peer < 64; ++peer) {
        buckets.insert(Keyed::bucket_index(log_key(peer, 7)));
    }
    // 64 well-mixed keys into 64 buckets fill ~40 of them; the unmixed
    // modulo fills exactly 1.
    EXPECT_GE(buckets.size(), 20u);
}

// The two production key schemes, pinned as such:
//
//   * tox_adapter's lossless-send failure -> log_key(friend_number, error_code)
//   * tunnel.cpp's backpressure lines     -> log_key(friend_number, site_id)
//
// Both were single process-wide throttles before, which meant one loud pair
// consumed the whole budget and every other pair's onset was folded into its
// `[+N suppressed]` tally. This checks the property the migration bought: a
// sustained burst on one key leaves every other key's first line admitted.
TEST(KeyedLogThrottleTest, ProductionKeySchemesDoNotShareBudgets) {
    // A minute-long interval means nothing here can be admitted twice by the
    // clock; every admission below is a genuinely independent bucket.
    KeyedLogThrottle<64> throttle{std::chrono::seconds(60)};
    KeyedLogThrottle<64>::Decision decision;

    // Friend 3 floods with TOX_ERR_..._SENDQ (code 5).
    ASSERT_TRUE(throttle.allow(log_key(3, 5), decision));
    for (int i = 0; i < 1000; ++i) {
        ASSERT_FALSE(throttle.allow(log_key(3, 5), decision));
    }

    // Mid-flood, each of these is a distinct condition an operator needs to
    // see: the same friend's escalation to a different error code, a second
    // friend failing, and (tunnel.cpp) each backpressure site per friend.
    auto expect_still_reported = [&](std::uint32_t high, std::uint32_t low, const char* what) {
        // Skip a key that genuinely collided with the flooding one: a collision
        // degrades to the old shared budget by design, so asserting through it
        // would be asserting the hash function, not this class's contract.
        if (KeyedLogThrottle<64>::bucket_index(log_key(high, low)) ==
            KeyedLogThrottle<64>::bucket_index(log_key(3, 5))) {
            return;
        }
        EXPECT_TRUE(throttle.allow(log_key(high, low), decision)) << what;
    };
    expect_still_reported(3, 6, "same friend, different error code");
    expect_still_reported(4, 5, "second friend, same error code");
    expect_still_reported(3, 0, "friend 3, backpressure site 0");
    expect_still_reported(3, 1, "friend 3, backpressure site 1");
    expect_still_reported(4, 0, "friend 4, backpressure site 0");

    // And the flooding key's own tally is untouched by all of the above.
    EXPECT_EQ(throttle.for_key(log_key(3, 5)).pending_suppressed(), 1000u);
}

TEST(KeyedLogThrottleTest, LoggerFacadeAcceptsBucketedThrottles) {
    using toxtunnel::util::Logger;

    static KeyedLogThrottle<32> throttle{std::chrono::milliseconds(50)};
    for (std::uint32_t peer = 0; peer < 4; ++peer) {
        for (int i = 0; i < 50; ++i) {
            Logger::warn_throttled(throttle.for_key(log_key(peer, 0)),
                                   "send failed on peer {} attempt {}", peer, i);
        }
    }
    // Each peer keeps its own tally rather than one shared one.
    for (std::uint32_t peer = 0; peer < 4; ++peer) {
        EXPECT_EQ(throttle.for_key(log_key(peer, 0)).total(), 50u);
    }
}
