#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string_view>

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// FlowControlMode
// ---------------------------------------------------------------------------

/// Operator-selected flow-control strategy. `Fixed` is the v0.3.0 default
/// (256 KiB window / 16 KiB ACK); `Bdp` tracks RTT and bandwidth and sizes
/// the window to keep the link pipe full without overcommitting memory.
enum class FlowControlMode : std::uint8_t {
    Fixed = 0,
    Bdp = 1,
};

[[nodiscard]] constexpr std::string_view to_string(FlowControlMode m) noexcept {
    return m == FlowControlMode::Bdp ? "bdp" : "fixed";
}

/// Parse a YAML string-typed flow-control mode. Returns true on success.
[[nodiscard]] bool parse_flow_control_mode(std::string_view s, FlowControlMode& out) noexcept;

// ---------------------------------------------------------------------------
// BdpFlowControl
// ---------------------------------------------------------------------------

/// Per-tunnel send-window state. Supports two operating modes:
///
/// - `FlowControlMode::Fixed`: the window is pinned at construction (matches
///   v0.3.0 semantics). RTT/bandwidth EWMA is still tracked so operators can
///   compare what `Bdp` *would* have chosen, but the value is never applied.
/// - `FlowControlMode::Bdp`: the window is recomputed as
///   EWMA(bytes_per_second) x (windowed min RTT + kQueueBudgetUs) x safety
///   whenever an RTT or bandwidth sample arrives, clamped between
///   `min_window_bytes` (never below kAckSafeFloorBytes) and
///   `max_window_bytes`. The seed (`fixed_window_bytes`) is only the start.
///
/// All math is in `int64_t` with saturated inputs so `bdp * safety_factor`
/// cannot overflow. The outputs are atomics read lock-free on the data path;
/// only the min-RTT filter takes a (leaf) mutex, on the ACK path.
class BdpFlowControl {
   public:
    /// Configuration mirroring the YAML `flow_control:` block.
    /// Hard floor for any window, whatever `min_window_bytes` says: twice
    /// the receiver's ACK threshold (TunnelImpl::kDefaultAckThreshold,
    /// 16 KiB, in every version so far). A receiver only ACKs once that many
    /// bytes have arrived, so a sender window below one threshold stalls for
    /// good and one below two degrades to stop-and-wait.
    static constexpr std::int64_t kAckSafeFloorBytes = 2 * 16 * 1024;

    struct Config {
        FlowControlMode mode = FlowControlMode::Fixed;
        std::int64_t min_window_bytes = kAckSafeFloorBytes;  // 32 KiB
        std::int64_t max_window_bytes = 4 * 1024 * 1024;     // 4 MiB
        std::int64_t safety_factor_x100 = 150;               // 1.5×
        std::int64_t fixed_window_bytes = 262144;            // 256 KiB
    };

    BdpFlowControl() : BdpFlowControl(Config{}) {}

    explicit BdpFlowControl(const Config& cfg) { configure(cfg); }

    /// Apply @p cfg and re-seed the window at `fixed_window_bytes`, so the
    /// first push sees that budget in either mode (the seed is only a
    /// starting point in bdp mode, not a floor).
    void configure(const Config& cfg) noexcept {
        cfg_.mode = cfg.mode;
        cfg_.min_window_bytes = std::max<std::int64_t>(cfg.min_window_bytes, kAckSafeFloorBytes);
        cfg_.max_window_bytes = std::max<std::int64_t>(cfg.max_window_bytes, cfg_.min_window_bytes);
        // [1x, 10x]: the upper bound keeps bdp * safety inside int64 (bdp is
        // capped at ~1e12 bytes) and nothing useful lies beyond it.
        cfg_.safety_factor_x100 = std::clamp<std::int64_t>(cfg.safety_factor_x100, 100, 1000);
        cfg_.fixed_window_bytes = std::clamp<std::int64_t>(
            cfg.fixed_window_bytes, cfg_.min_window_bytes, cfg_.max_window_bytes);
        target_window_bytes_.store(cfg_.fixed_window_bytes, std::memory_order_relaxed);
        ack_threshold_bytes_.store(std::max<std::int64_t>(cfg_.fixed_window_bytes / 16, 1024),
                                   std::memory_order_relaxed);
    }

    [[nodiscard]] FlowControlMode mode() const noexcept { return cfg_.mode; }
    [[nodiscard]] const Config& config() const noexcept { return cfg_; }

    /// Record an RTT sample (microseconds): updates the smoothed RTT (EWMA)
    /// and the windowed minimum. The BDP target uses the minimum -- the
    /// propagation delay without the queue. Treated as trusted; see
    /// observe_rtt_sample_at() for samples that may carry a queue.
    void observe_rtt_us(std::int64_t rtt_us) noexcept;
    /// Same, at an explicit steady_clock time (tests).
    void observe_rtt_us_at(std::int64_t rtt_us, std::int64_t now_ns) noexcept;

    /// Record an RTT sample and say whether it can be trusted for the minimum:
    /// a sample sent with a standing queue in flight measures that queue, not
    /// the path. Only trusted samples (little in flight when the bytes were
    /// sent) feed the min-RTT filter; every sample feeds the smoothed RTT.
    /// When no trusted sample has arrived for kMinRttProbeAfterNs the window
    /// drops to the floor (a probe, as in BBR's ProbeRTT) until one does, so a
    /// saturating transfer cannot keep re-learning its own queue as the
    /// minimum and ratchet the window up. observe_rtt_us*() are trusted.
    void observe_rtt_sample_at(std::int64_t rtt_us, std::int64_t now_ns, bool trusted) noexcept {
        observe_rtt_samples_at(rtt_us, trusted ? rtt_us : 0, now_ns);
    }

    /// One ACK's worth of samples: @p rtt_us (the newest sample it covered)
    /// feeds the smoothed RTT; @p trusted_rtt_us (the newest *trusted* one it
    /// covered, 0 if none) feeds the minimum. Kept apart so a large ACK that
    /// covers both clean and queued samples does not discard the clean one.
    void observe_rtt_samples_at(std::int64_t rtt_us, std::int64_t trusted_rtt_us,
                                std::int64_t now_ns) noexcept;

    /// Whether a sample sent with @p inflight bytes outstanding measured the
    /// path rather than our own queue: no more than the floor window (what a
    /// probe drains to) plus a few frames of slack.
    [[nodiscard]] bool is_trusted_inflight(std::uint64_t inflight) const noexcept {
        return inflight <= static_cast<std::uint64_t>(cfg_.min_window_bytes) + kTrustedSlackBytes;
    }
    static constexpr std::uint64_t kTrustedSlackBytes = 4096;

    /// True while a min-RTT probe holds the window at the floor.
    [[nodiscard]] bool probing_min_rtt() const noexcept {
        return probing_.load(std::memory_order_relaxed);
    }
    static constexpr std::int64_t kMinRttProbeAfterNs = 10'000'000'000;

    /// Record a "delivered bytes per second" sample. Typically computed from
    /// cumulative ACKed bytes / observation interval.
    void observe_bandwidth_bps(std::int64_t bps) noexcept;

    /// Current target window in bytes. The tunnel's `send_window_size` is
    /// clamped at this value.
    [[nodiscard]] std::int64_t target_window_bytes() const noexcept {
        return target_window_bytes_.load(std::memory_order_relaxed);
    }

    /// ACK threshold derived from the target window (≈ window / 16).
    [[nodiscard]] std::int64_t ack_threshold_bytes() const noexcept {
        return ack_threshold_bytes_.load(std::memory_order_relaxed);
    }

    /// EWMA accessors (microseconds and bytes/sec). Updated on each observe().
    [[nodiscard]] std::int64_t rtt_us() const noexcept {
        return rtt_us_.load(std::memory_order_relaxed);
    }
    /// Minimum RTT over the last one to two kMinRttBucketNs buckets (0 = no
    /// sample yet).
    [[nodiscard]] std::int64_t min_rtt_us() const noexcept {
        return min_rtt_us_.load(std::memory_order_relaxed);
    }

    /// The min-RTT filter covers two consecutive buckets of this length, i.e.
    /// between one and two of them: long enough to ride out a burst of queued
    /// samples, short enough to follow a path change.
    static constexpr std::int64_t kMinRttBucketNs = 5'000'000'000;

    /// Delay the window may add on top of the minimum RTT: target =
    /// bandwidth x (min_rtt + kQueueBudgetUs) x safety. Without it the window
    /// collapses on fast paths: there the RTT is dominated by jitter (each side
    /// iterates toxcore every <= 5 ms), the minimum is a lucky sample several
    /// times below the typical RTT, and a window-limited bandwidth sample
    /// (window / typical RTT) times that minimum shrinks the window every
    /// round -- measured 2.9 MB/s on a LAN loopback pair against 11 MB/s
    /// before. With the budget the window keeps growing while the RTT stays
    /// under ~1.5 x (min_rtt + budget). The price is bounded: a saturated
    /// path settles where RTT ~= 1.5 x (min_rtt + budget), i.e. it queues at
    /// most ~(min_rtt / 2 + 75 ms) of data (and never more than the 4 MiB
    /// max window); on paths slower than ~440 KB/s the 32 KiB floor is the
    /// bound instead (32 KiB / C). The pre-v0.5.0 256 KiB floor queued 36 s
    /// at 7 KB/s. The bound relies on min_rtt being the path's, which is why
    /// only trusted samples feed it (see observe_rtt_sample_at).
    static constexpr std::int64_t kQueueBudgetUs = 50'000;
    [[nodiscard]] std::int64_t bandwidth_bps() const noexcept {
        return bandwidth_bps_.load(std::memory_order_relaxed);
    }

   private:
    void recompute_window_locked() noexcept;

    Config cfg_;

    // EWMA state. α = 1/8.
    std::atomic<std::int64_t> rtt_us_{0};
    std::atomic<std::int64_t> bandwidth_bps_{0};

    // Windowed min RTT: the minimum of the current and the previous bucket.
    // Guarded by min_rtt_mutex_ (a leaf; ACK path only, never per byte).
    std::mutex min_rtt_mutex_;
    std::int64_t bucket_start_ns_{0};
    std::int64_t cur_bucket_min_us_{0};
    std::int64_t prev_bucket_min_us_{0};
    std::int64_t last_trusted_ns_{0};
    std::atomic<std::int64_t> min_rtt_us_{0};
    std::atomic<bool> probing_{false};

    // Outputs (atomics so data-path readers don't lock).
    std::atomic<std::int64_t> target_window_bytes_{262144};
    std::atomic<std::int64_t> ack_threshold_bytes_{16384};
};

}  // namespace toxtunnel::tunnel
