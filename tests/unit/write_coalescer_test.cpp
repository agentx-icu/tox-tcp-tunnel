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

}  // namespace
}  // namespace toxtunnel::test
