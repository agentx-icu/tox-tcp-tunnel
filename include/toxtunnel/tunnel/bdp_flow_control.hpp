#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
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
/// - `FlowControlMode::Bdp`: the window is recomputed from EWMA(RTT) and
///   EWMA(bytes_per_second) when an RTT or bandwidth sample updates. Clamped
///   between `min_window_bytes` and `max_window_bytes`.
///
/// All math is in `int64_t` to keep `bdp * safety_factor` from overflowing on
/// high-bandwidth localhost links. State is lock-free atomics; callers read
/// `target_window_bytes()` and `ack_threshold_bytes()` on the data path.
class BdpFlowControl {
   public:
    /// Configuration mirroring the YAML `flow_control:` block.
    struct Config {
        FlowControlMode mode = FlowControlMode::Fixed;
        std::int64_t min_window_bytes = 65536;            // 64 KiB
        std::int64_t max_window_bytes = 4 * 1024 * 1024;  // 4 MiB
        std::int64_t safety_factor_x100 = 150;            // 1.5×
        std::int64_t fixed_window_bytes = 262144;         // 256 KiB
    };

    BdpFlowControl() : BdpFlowControl(Config{}) {}

    explicit BdpFlowControl(const Config& cfg) {
        configure(cfg);
        // Seed the window at the fixed value so the very first push sees a
        // sane budget regardless of which mode we are in.
        target_window_bytes_.store(cfg.fixed_window_bytes, std::memory_order_relaxed);
        ack_threshold_bytes_.store(std::max<std::int64_t>(cfg.fixed_window_bytes / 16, 1024),
                                   std::memory_order_relaxed);
    }

    void configure(const Config& cfg) noexcept {
        cfg_.mode = cfg.mode;
        cfg_.min_window_bytes = std::max<std::int64_t>(cfg.min_window_bytes, 1024);
        cfg_.max_window_bytes = std::max<std::int64_t>(cfg.max_window_bytes, cfg_.min_window_bytes);
        cfg_.safety_factor_x100 = std::max<std::int64_t>(cfg.safety_factor_x100, 100);
        cfg_.fixed_window_bytes = std::clamp<std::int64_t>(
            cfg.fixed_window_bytes, cfg_.min_window_bytes, cfg_.max_window_bytes);
    }

    [[nodiscard]] FlowControlMode mode() const noexcept { return cfg_.mode; }
    [[nodiscard]] const Config& config() const noexcept { return cfg_; }

    /// Record an RTT sample (microseconds). Drives the EWMA used by the BDP
    /// mode to recompute the window.
    void observe_rtt_us(std::int64_t rtt_us) noexcept;

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
    [[nodiscard]] std::int64_t bandwidth_bps() const noexcept {
        return bandwidth_bps_.load(std::memory_order_relaxed);
    }

   private:
    void recompute_window_locked() noexcept;

    Config cfg_;

    // EWMA state. α = 1/8.
    std::atomic<std::int64_t> rtt_us_{0};
    std::atomic<std::int64_t> bandwidth_bps_{0};

    // Outputs (atomics so data-path readers don't lock).
    std::atomic<std::int64_t> target_window_bytes_{262144};
    std::atomic<std::int64_t> ack_threshold_bytes_{16384};
};

}  // namespace toxtunnel::tunnel
