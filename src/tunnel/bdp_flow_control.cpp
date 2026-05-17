#include "toxtunnel/tunnel/bdp_flow_control.hpp"

#include <algorithm>

namespace toxtunnel::tunnel {

bool parse_flow_control_mode(std::string_view s, FlowControlMode& out) noexcept {
    if (s == "fixed") {
        out = FlowControlMode::Fixed;
        return true;
    }
    if (s == "bdp") {
        out = FlowControlMode::Bdp;
        return true;
    }
    return false;
}

namespace {

/// EWMA update with α = 1/8, integer math. Returns the new value.
[[nodiscard]] std::int64_t ewma_update(std::int64_t prev, std::int64_t sample) noexcept {
    if (prev == 0) {
        return sample;
    }
    const auto delta = sample - prev;
    return prev + (delta >> 3);
}

}  // namespace

void BdpFlowControl::observe_rtt_us(std::int64_t rtt_us) noexcept {
    if (rtt_us <= 0) {
        return;
    }
    const auto prev = rtt_us_.load(std::memory_order_relaxed);
    rtt_us_.store(ewma_update(prev, rtt_us), std::memory_order_relaxed);
    recompute_window_locked();
}

void BdpFlowControl::observe_bandwidth_bps(std::int64_t bps) noexcept {
    if (bps <= 0) {
        return;
    }
    const auto prev = bandwidth_bps_.load(std::memory_order_relaxed);
    bandwidth_bps_.store(ewma_update(prev, bps), std::memory_order_relaxed);
    recompute_window_locked();
}

void BdpFlowControl::recompute_window_locked() noexcept {
    if (cfg_.mode == FlowControlMode::Fixed) {
        target_window_bytes_.store(cfg_.fixed_window_bytes, std::memory_order_relaxed);
        ack_threshold_bytes_.store(std::max<std::int64_t>(cfg_.fixed_window_bytes / 16, 1024),
                                   std::memory_order_relaxed);
        return;
    }

    const auto rtt = rtt_us_.load(std::memory_order_relaxed);
    const auto bps = bandwidth_bps_.load(std::memory_order_relaxed);
    if (rtt <= 0 || bps <= 0) {
        // Not enough samples; leave the window at its seed value.
        return;
    }

    // bdp_bytes = bandwidth (bytes/sec) * rtt (us) / 1_000_000.
    // Worked in int64_t to avoid overflow on a 10 Gbps × 100 ms link.
    const std::int64_t bdp = (bps * rtt) / 1'000'000;
    const std::int64_t target = (bdp * cfg_.safety_factor_x100) / 100;
    // Never shrink below the configured seed (fixed_window_bytes). On a
    // high-RTT / low-throughput path (e.g. Tox public TCP relay), the BDP
    // estimate is small — but a single SSH/scp write can be larger than the
    // BDP, and shrinking below the seed would starve those writes at the
    // admission gate even though the link can actually carry that much
    // in-flight. Treat the seed as a floor; only grow from it.
    const std::int64_t floor_bytes =
        std::max<std::int64_t>(cfg_.min_window_bytes, cfg_.fixed_window_bytes);
    const std::int64_t clamped =
        std::clamp<std::int64_t>(target, floor_bytes, cfg_.max_window_bytes);
    target_window_bytes_.store(clamped, std::memory_order_relaxed);
    ack_threshold_bytes_.store(std::max<std::int64_t>(clamped / 16, 1024),
                               std::memory_order_relaxed);
}

}  // namespace toxtunnel::tunnel
