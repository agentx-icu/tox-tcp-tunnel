#include "toxtunnel/tunnel/bdp_flow_control.hpp"

#include <algorithm>
#include <chrono>

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
    observe_rtt_us_at(rtt_us, std::chrono::steady_clock::now().time_since_epoch().count());
}

void BdpFlowControl::observe_rtt_us_at(std::int64_t rtt_us, std::int64_t now_ns) noexcept {
    observe_rtt_samples_at(rtt_us, rtt_us, now_ns);
}

void BdpFlowControl::observe_rtt_samples_at(std::int64_t rtt_us, std::int64_t trusted_rtt_us,
                                            std::int64_t now_ns) noexcept {
    if (rtt_us <= 0) {
        return;
    }
    const auto prev = rtt_us_.load(std::memory_order_relaxed);
    rtt_us_.store(ewma_update(prev, rtt_us), std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(min_rtt_mutex_);
        if (last_trusted_ns_ == 0) {
            last_trusted_ns_ = now_ns;  // the probe clock starts with the first sample
        }
        const bool trusted = trusted_rtt_us > 0;
        if (trusted) {
            rtt_us = trusted_rtt_us;
            if (bucket_start_ns_ == 0 || now_ns - bucket_start_ns_ >= kMinRttBucketNs) {
                // Rotate. A gap of two buckets or more leaves nothing current to
                // carry over.
                const bool adjacent =
                    bucket_start_ns_ != 0 && now_ns - bucket_start_ns_ < 2 * kMinRttBucketNs;
                prev_bucket_min_us_ = adjacent ? cur_bucket_min_us_ : 0;
                cur_bucket_min_us_ = 0;
                bucket_start_ns_ = now_ns;
            }
            if (cur_bucket_min_us_ == 0 || rtt_us < cur_bucket_min_us_) {
                cur_bucket_min_us_ = rtt_us;
            }
            std::int64_t m = cur_bucket_min_us_;
            if (prev_bucket_min_us_ != 0 && prev_bucket_min_us_ < m) {
                m = prev_bucket_min_us_;
            }
            min_rtt_us_.store(m, std::memory_order_relaxed);
            last_trusted_ns_ = now_ns;
            probing_.store(false, std::memory_order_relaxed);
        } else if (now_ns - last_trusted_ns_ >= kMinRttProbeAfterNs) {
            // The minimum is stale and every recent sample carried a queue.
            // Keep the old minimum (never refill it from queued samples) and
            // drain to the floor until a trusted sample re-measures the path.
            probing_.store(true, std::memory_order_relaxed);
        }
    }
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

    // Min-RTT probe: hold the floor until a trusted sample arrives.
    if (probing_.load(std::memory_order_relaxed)) {
        target_window_bytes_.store(cfg_.min_window_bytes, std::memory_order_relaxed);
        ack_threshold_bytes_.store(std::max<std::int64_t>(cfg_.min_window_bytes / 16, 1024),
                                   std::memory_order_relaxed);
        return;
    }

    // Propagation delay, not the queue: the windowed minimum. Falls back to
    // the smoothed RTT only before the filter has a sample.
    auto rtt = min_rtt_us_.load(std::memory_order_relaxed);
    const bool have_min = rtt > 0;
    if (!have_min) {
        rtt = rtt_us_.load(std::memory_order_relaxed);
    }
    const auto bps = bandwidth_bps_.load(std::memory_order_relaxed);
    if (rtt <= 0 || bps <= 0) {
        // Not enough samples; leave the window at its seed value.
        return;
    }

    // bdp_bytes = bandwidth (bytes/sec) * rtt (us) / 1_000_000.
    // S21 (2026-05-20) protected against peer-controlled overflow of
    // `bps * rtt`. The original fix used __int128 — portable on GCC
    // and Clang but not on MSVC, which has no __int128 of any spelling.
    // CI-pedantic-fix follow-up (2026-05-21): replace with input
    // saturation. We cap both factors so the product is provably
    // < INT64_MAX without needing wide-integer arithmetic, then run
    // the multiplication in plain int64. Caps are loose enough that
    // honest links are unaffected — 1 Gbps × 1000 s RTT bounds the
    // product at 1e18, comfortably below INT64_MAX (~9.2e18) with
    // headroom for the * safety_factor step below.
    constexpr std::int64_t kBpsCap = 1'000'000'000;    // 1 Gbps
    constexpr std::int64_t kRttCapUs = 1'000'000'000;  // 1000 seconds
    const std::int64_t bps_capped = std::min(bps, kBpsCap);
    // min RTT plus the queue/jitter budget (see kQueueBudgetUs).
    const std::int64_t rtt_capped = std::min(rtt, kRttCapUs - kQueueBudgetUs) + kQueueBudgetUs;
    const std::int64_t bdp = (bps_capped * rtt_capped) / 1'000'000;
    const std::int64_t target = (bdp * cfg_.safety_factor_x100) / 100;
    // The seed (fixed_window_bytes) is only where the window starts; it is
    // NOT a floor. It used to be one, so on a slow path the window could never
    // fall below 256 KiB and every one of those bytes queued in toxcore's
    // single ordered stream for the friend -- 30+ s in front of each OPEN_ACK,
    // PONG and every other tunnel's data at 7 KB/s. A large write is not
    // starved by a small window: admission takes it in window-sized pieces.
    // The floor is min_window_bytes, itself never below kAckSafeFloorBytes.
    std::int64_t clamped =
        std::clamp<std::int64_t>(target, cfg_.min_window_bytes, cfg_.max_window_bytes);
    // Until a trusted sample exists the RTT is the smoothed one, queue
    // included: let it shrink the window but never grow it past the seed.
    if (!have_min) {
        clamped = std::min(clamped, cfg_.fixed_window_bytes);
    }
    target_window_bytes_.store(clamped, std::memory_order_relaxed);
    ack_threshold_bytes_.store(std::max<std::int64_t>(clamped / 16, 1024),
                               std::memory_order_relaxed);
}

}  // namespace toxtunnel::tunnel
