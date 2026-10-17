// Adaptive write coalescer + BDP flow control unit tests.
//
// 1. WriteCoalescer policy selection: fixed mode pins Batch; adaptive mode
//    transitions Batch → Bypass when avg_write_size ≥ MTU after the hysteresis
//    window; Batch → Drain when avg_write_gap exceeds 4× the hold delay.
//
// 2. EWMA values track the design-doc formula (α = 1/8).
//
// 3. BdpFlowControl: fixed mode pins the configured window; bdp mode computes
//    `bdp = rtt × bps`, clamps to [min, max], and exposes the result via
//    target_window_bytes()/ack_threshold_bytes().
//
// 4. parse_coalesce_mode / parse_flow_control_mode round-trip the legal
//    string values and reject unknown ones.

#include "toxtunnel/tunnel/write_coalescer.hpp"

#include <gtest/gtest.h>

#include <algorithm>

#include "toxtunnel/tunnel/bdp_flow_control.hpp"

namespace toxtunnel::test {
namespace {

using tunnel::BdpFlowControl;
using tunnel::CoalesceMode;
using tunnel::CoalescePolicy;
using tunnel::FlowControlMode;
using tunnel::WriteCoalescer;

// =============================================================================
// 1. WriteCoalescer fixed/pinned modes.
// =============================================================================

TEST(WriteCoalescerTest, FixedModeAlwaysReturnsBatch) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Fixed);
    wc.configure(/*mtu=*/1362, /*max_delay_us=*/200);

    for (int i = 0; i < 32; ++i) {
        wc.observe(/*write_size=*/2000, /*gap_us=*/0);
        EXPECT_EQ(wc.decide().policy, CoalescePolicy::Batch);
    }
}

TEST(WriteCoalescerTest, BypassModeAlwaysReturnsBypass) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Bypass);
    wc.configure(1362, 200);
    EXPECT_EQ(wc.decide().policy, CoalescePolicy::Bypass);
}

TEST(WriteCoalescerTest, DrainModeAlwaysReturnsDrain) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Drain);
    wc.configure(1362, 200);
    EXPECT_EQ(wc.decide().policy, CoalescePolicy::Drain);
}

// =============================================================================
// 2. Adaptive mode: large writes → Bypass after hysteresis.
// =============================================================================

TEST(WriteCoalescerTest, AdaptivePromotesToBypassOnLargeWrites) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Adaptive);
    wc.configure(/*mtu=*/1362, /*max_delay_us=*/200);

    // Seed the EWMA above MTU.
    for (int i = 0; i < 32; ++i) {
        wc.observe(/*write_size=*/4096, /*gap_us=*/100);
    }
    // After enough hysteresis ticks, the policy must promote.
    bool saw_bypass = false;
    for (int i = 0; i < 8; ++i) {
        auto d = wc.decide();
        if (d.policy == CoalescePolicy::Bypass) {
            saw_bypass = true;
            break;
        }
    }
    EXPECT_TRUE(saw_bypass);
}

TEST(WriteCoalescerTest, AdaptivePromotesToDrainOnSparseWrites) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Adaptive);
    wc.configure(/*mtu=*/1362, /*max_delay_us=*/200);

    // Small writes spaced 10 ms apart (gap_us=10000) >> 4×200=800 µs threshold.
    for (int i = 0; i < 32; ++i) {
        wc.observe(/*write_size=*/64, /*gap_us=*/10000);
    }

    bool saw_drain = false;
    for (int i = 0; i < 8; ++i) {
        auto d = wc.decide();
        if (d.policy == CoalescePolicy::Drain) {
            saw_drain = true;
            break;
        }
    }
    EXPECT_TRUE(saw_drain);
}

TEST(WriteCoalescerTest, AdaptiveStaysBatchForCloselySpacedSmallWrites) {
    WriteCoalescer wc;
    wc.set_mode(CoalesceMode::Adaptive);
    wc.configure(/*mtu=*/1362, /*max_delay_us=*/200);

    // Small writes spaced 100 µs apart: well below the 4×200 µs threshold.
    for (int i = 0; i < 32; ++i) {
        wc.observe(/*write_size=*/256, /*gap_us=*/100);
    }
    for (int i = 0; i < 8; ++i) {
        auto d = wc.decide();
        EXPECT_EQ(d.policy, CoalescePolicy::Batch);
    }
}

// =============================================================================
// 3. EWMA accessors.
// =============================================================================

TEST(WriteCoalescerTest, EwmaTracksWriteSizeAndGap) {
    WriteCoalescer wc;
    wc.configure(1362, 200);

    // First observation seeds the EWMA outright.
    wc.observe(1000, 100);
    EXPECT_EQ(wc.avg_write_size(), 1000u);
    EXPECT_EQ(wc.avg_write_gap_us(), 100);

    // Second observation: new = old + (sample - old) >> 3
    // size:  1000 + (2000 - 1000) >> 3 = 1000 + 125 = 1125
    // gap:   100  + (300 - 100) >> 3   = 100  + 25  = 125
    wc.observe(2000, 300);
    EXPECT_EQ(wc.avg_write_size(), 1125u);
    EXPECT_EQ(wc.avg_write_gap_us(), 125);
}

// =============================================================================
// 4. parse_coalesce_mode / parse_flow_control_mode.
// =============================================================================

TEST(ParseTest, CoalesceModeRoundTrip) {
    CoalesceMode m = CoalesceMode::Fixed;
    EXPECT_TRUE(tunnel::parse_coalesce_mode("adaptive", m));
    EXPECT_EQ(m, CoalesceMode::Adaptive);
    EXPECT_TRUE(tunnel::parse_coalesce_mode("bypass", m));
    EXPECT_EQ(m, CoalesceMode::Bypass);
    EXPECT_TRUE(tunnel::parse_coalesce_mode("drain", m));
    EXPECT_EQ(m, CoalesceMode::Drain);
    EXPECT_TRUE(tunnel::parse_coalesce_mode("fixed", m));
    EXPECT_EQ(m, CoalesceMode::Fixed);
    EXPECT_FALSE(tunnel::parse_coalesce_mode("nope", m));
}

TEST(ParseTest, FlowControlModeRoundTrip) {
    FlowControlMode m = FlowControlMode::Fixed;
    EXPECT_TRUE(tunnel::parse_flow_control_mode("bdp", m));
    EXPECT_EQ(m, FlowControlMode::Bdp);
    EXPECT_TRUE(tunnel::parse_flow_control_mode("fixed", m));
    EXPECT_EQ(m, FlowControlMode::Fixed);
    EXPECT_FALSE(tunnel::parse_flow_control_mode("auto", m));
}

// =============================================================================
// 5. BdpFlowControl: fixed mode pins the configured window.
// =============================================================================

TEST(BdpFlowControlTest, FixedModePinsConfiguredWindow) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Fixed;
    cfg.fixed_window_bytes = 131072;  // 128 KiB
    BdpFlowControl bdp(cfg);
    EXPECT_EQ(bdp.target_window_bytes(), 131072);

    // RTT/bandwidth observations don't change the window in fixed mode.
    bdp.observe_rtt_us(50000);                    // 50 ms
    bdp.observe_bandwidth_bps(10 * 1024 * 1024);  // 10 MiB/s
    EXPECT_EQ(bdp.target_window_bytes(), 131072);
}

TEST(BdpFlowControlTest, BdpModeComputesWindowFromRttAndBandwidth) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 65536;
    cfg.max_window_bytes = 4 * 1024 * 1024;
    cfg.safety_factor_x100 = 100;  // no headroom for an easy check
    cfg.fixed_window_bytes = 65536;
    BdpFlowControl bdp(cfg);

    // RTT = 100 ms, bandwidth = 10 MiB/s.
    // bdp = (10 * 1048576) * 100000 / 1_000_000 = 104857.6 -> ~104857 bytes.
    // Clamped to min (65536) at lower bound and max at upper bound; 104857 is
    // between min and max, so target = 104857.
    bdp.observe_rtt_us(100000);
    bdp.observe_bandwidth_bps(10 * 1024 * 1024);
    EXPECT_GE(bdp.target_window_bytes(), 65536);
    EXPECT_LE(bdp.target_window_bytes(), 4 * 1024 * 1024);
    // Window should now reflect a non-fixed value (different from the seed
    // 65536 after EWMA + computation).
    EXPECT_NE(bdp.target_window_bytes(), 65536);
}

TEST(BdpFlowControlTest, BdpModeClampsToMinWindow) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 65536;
    cfg.max_window_bytes = 4 * 1024 * 1024;
    cfg.safety_factor_x100 = 100;
    cfg.fixed_window_bytes = 100 * 1024 * 1024;  // huge seed
    BdpFlowControl bdp(cfg);

    // Very small product → would be tiny BDP, clamped at min.
    bdp.observe_rtt_us(1);  // 1 µs
    bdp.observe_bandwidth_bps(1024);
    EXPECT_GE(bdp.target_window_bytes(), 65536);
}

TEST(BdpFlowControlTest, AckThresholdScalesWithWindow) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Fixed;
    cfg.fixed_window_bytes = 1024 * 1024;  // 1 MiB
    BdpFlowControl bdp(cfg);
    // ACK threshold = window / 16 = 64 KiB.
    EXPECT_EQ(bdp.ack_threshold_bytes(), 65536);
}

// S21 / 2026-05-20 follow-up: peer-controlled ACK timing + byte counts
// can pump the EWMA estimates toward huge values. The bdp = bps * rtt
// computation must not wrap around int64. Feed obviously-out-of-band
// samples and assert the window stays inside [min, max] and finite.
TEST(BdpFlowControlTest, BdpModeSurvivesAdversarialSamplesWithoutOverflow) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.fixed_window_bytes = 256 * 1024;  // seed = 256 KiB
    cfg.min_window_bytes = 64 * 1024;
    cfg.max_window_bytes = 4 * 1024 * 1024;
    cfg.safety_factor_x100 = 200;  // 2.0x
    BdpFlowControl bdp(cfg);

    // Hostile sample 1: very large bandwidth — close to int64_t / 1e9.
    // Pumped repeatedly so the EWMA settles near it.
    for (int i = 0; i < 50; ++i) {
        bdp.observe_bandwidth_bps(static_cast<std::int64_t>(4'000'000'000'000'000LL));  // 4e15 B/s
    }
    // Hostile sample 2: huge RTT (e.g. 10 seconds = 1e7 us).
    for (int i = 0; i < 50; ++i) {
        bdp.observe_rtt_us(10'000'000);
    }

    const auto win = bdp.target_window_bytes();
    EXPECT_GE(win, cfg.min_window_bytes) << "window underflowed below floor";
    EXPECT_LE(win, cfg.max_window_bytes) << "window overflowed past ceiling";

    const auto thr = bdp.ack_threshold_bytes();
    EXPECT_GT(thr, 0) << "ack threshold should never go negative";
    EXPECT_LE(thr, win) << "ack threshold should not exceed the window";
}

// v0.5.0: the seed is a starting point, not a floor. On a slow path the
// window must shrink, or a bulk tunnel parks the whole seed in toxcore's
// per-friend queue (observed: 256 KiB at 7 KB/s, OPEN_ACKs waiting > 30 s).
TEST(BdpFlowControlTest, BdpModeShrinksBelowTheSeedOnASlowPath) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 32 * 1024;
    cfg.fixed_window_bytes = 256 * 1024;
    cfg.safety_factor_x100 = 150;
    BdpFlowControl bdp(cfg);
    EXPECT_EQ(bdp.target_window_bytes(), 256 * 1024);  // seed

    bdp.observe_rtt_us(300'000);      // 300 ms
    bdp.observe_bandwidth_bps(7000);  // 7 KB/s -> BDP ~2 KiB
    EXPECT_EQ(bdp.target_window_bytes(), 32 * 1024) << "clamped to the floor, below the seed";
}

TEST(BdpFlowControlTest, FloorNeverGoesBelowTwoAckThresholds) {
    // A receiver ACKs every 16 KiB; a smaller window would stall for good.
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 4096;
    cfg.fixed_window_bytes = 8192;
    BdpFlowControl bdp(cfg);
    EXPECT_EQ(bdp.config().min_window_bytes, BdpFlowControl::kAckSafeFloorBytes);
    EXPECT_EQ(bdp.target_window_bytes(), BdpFlowControl::kAckSafeFloorBytes);
    bdp.observe_rtt_us(1000);
    bdp.observe_bandwidth_bps(1000);
    EXPECT_EQ(bdp.target_window_bytes(), BdpFlowControl::kAckSafeFloorBytes);
}

TEST(BdpFlowControlTest, TargetUsesMinRttNotTheQueueInflatedAverage) {
    // A full window inflates every RTT sample with its own queue. Using those
    // samples would keep the window large forever; the minimum is the path.
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 32 * 1024;
    cfg.max_window_bytes = 64 * 1024 * 1024;
    cfg.fixed_window_bytes = 256 * 1024;
    cfg.safety_factor_x100 = 100;
    BdpFlowControl bdp(cfg);
    const std::int64_t t0 = 1'000'000'000;
    bdp.observe_bandwidth_bps(1'000'000);  // 1 MB/s
    bdp.observe_rtt_us_at(100'000, t0);    // 100 ms path
    for (int i = 1; i <= 20; ++i) {
        bdp.observe_rtt_us_at(2'000'000, t0 + i * 100'000'000LL);  // 2 s with queue
    }
    EXPECT_EQ(bdp.min_rtt_us(), 100'000);
    EXPECT_GT(bdp.rtt_us(), 1'000'000) << "the smoothed RTT still reports the queue";
    // 1 MB/s x (100 ms + the 50 ms queue budget) = 150 KB, not 1 MB/s x ~2 s.
    EXPECT_EQ(bdp.target_window_bytes(), 150'000);
}

// Review regression: under a saturating transfer every sample carries the
// sender's own standing queue. If those samples were allowed to refill the
// minimum once the clean one aged out, the target would ratchet x1.5 per
// bucket up to max_window_bytes. Untrusted samples never touch the minimum,
// and after kMinRttProbeAfterNs without a trusted sample the window drops to
// the floor until a clean sample re-measures the path.
TEST(BdpFlowControlTest, AStandingQueueCannotRatchetTheWindowUp) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 32 * 1024;
    cfg.max_window_bytes = 4 * 1024 * 1024;
    cfg.fixed_window_bytes = 256 * 1024;
    cfg.safety_factor_x100 = 150;
    BdpFlowControl bdp(cfg);
    const std::int64_t t0 = 1'000'000'000;
    bdp.observe_bandwidth_bps(100'000);                        // 100 KB/s
    bdp.observe_rtt_sample_at(200'000, t0, /*trusted=*/true);  // 200 ms path
    const auto steady = bdp.target_window_bytes();

    std::int64_t peak = 0;
    for (int i = 1; i <= 210; ++i) {  // 21 s of samples behind a ~2.5 s queue
        bdp.observe_rtt_sample_at(2'500'000, t0 + i * 100'000'000LL, /*trusted=*/false);
        peak = std::max(peak, bdp.target_window_bytes());
    }
    EXPECT_EQ(bdp.min_rtt_us(), 200'000) << "queued samples must not become the minimum";
    EXPECT_LE(peak, steady) << "the window grew from its own queue";
    EXPECT_TRUE(bdp.probing_min_rtt());
    EXPECT_EQ(bdp.target_window_bytes(), 32 * 1024) << "probe holds the floor";

    // A clean sample ends the probe and re-measures the path: the 200 ms
    // minimum aged out with its buckets, so 210 ms is the new minimum.
    bdp.observe_rtt_sample_at(210'000, t0 + 22'000'000'000LL, /*trusted=*/true);
    EXPECT_FALSE(bdp.probing_min_rtt());
    EXPECT_EQ(bdp.min_rtt_us(), 210'000);
    EXPECT_EQ(bdp.target_window_bytes(), 39'000);  // 100 KB/s x (210 + 50) ms x 1.5
}

// Trust is relative to the configured floor: with the pre-v0.5.0 64 KiB
// minimum a probe drains to 64 KiB, and samples sent at that level must count
// as clean or the probe would never end.
TEST(BdpFlowControlTest, TrustFollowsTheConfiguredFloor) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.min_window_bytes = 64 * 1024;
    BdpFlowControl bdp(cfg);
    EXPECT_TRUE(bdp.is_trusted_inflight(64 * 1024));
    EXPECT_TRUE(bdp.is_trusted_inflight(64 * 1024 + BdpFlowControl::kTrustedSlackBytes));
    EXPECT_FALSE(bdp.is_trusted_inflight(80 * 1024));
}

TEST(BdpFlowControlTest, WithoutATrustedMinimumTheWindowNeverGrowsPastTheSeed) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    cfg.fixed_window_bytes = 256 * 1024;
    BdpFlowControl bdp(cfg);
    const std::int64_t t0 = 1'000'000'000;
    bdp.observe_bandwidth_bps(1'000'000);
    for (int i = 0; i < 50; ++i) {  // queued samples only, from the start
        bdp.observe_rtt_samples_at(3'000'000, /*trusted_rtt_us=*/0, t0 + i * 10'000'000LL);
    }
    EXPECT_EQ(bdp.min_rtt_us(), 0);
    EXPECT_LE(bdp.target_window_bytes(), 256 * 1024);
}

TEST(BdpFlowControlTest, MinRttForgetsAMinimumOlderThanTwoBuckets) {
    BdpFlowControl::Config cfg;
    cfg.mode = FlowControlMode::Bdp;
    BdpFlowControl bdp(cfg);
    const std::int64_t t0 = 1'000'000'000;
    const std::int64_t bucket = BdpFlowControl::kMinRttBucketNs;
    bdp.observe_rtt_us_at(50'000, t0);
    bdp.observe_rtt_us_at(80'000, t0 + bucket + 1);  // next bucket: 50 ms still counts
    EXPECT_EQ(bdp.min_rtt_us(), 50'000);
    bdp.observe_rtt_us_at(90'000, t0 + 2 * bucket + 2);  // 50 ms bucket now two back
    EXPECT_EQ(bdp.min_rtt_us(), 80'000);
    bdp.observe_rtt_us_at(120'000, t0 + 5 * bucket);  // long silence: nothing carried over
    EXPECT_EQ(bdp.min_rtt_us(), 120'000);
}

}  // namespace
}  // namespace toxtunnel::test
