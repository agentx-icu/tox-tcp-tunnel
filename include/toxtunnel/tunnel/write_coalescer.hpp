#pragma once

#include <atomic>
#include <cstdint>
#include <string_view>

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// CoalescePolicy — per-tunnel write coalescer decision.
// ---------------------------------------------------------------------------

/// The three runtime behaviours selectable by `WriteCoalescer`.
///
/// - `Bypass` — every push emits one frame; no hold, no merge. Best for bulk
///   transfers where each write is already MTU-sized.
/// - `Drain` — emit immediately on overflow; no hold timer. Good for bursty
///   bulk where writes are sub-MTU but arrive faster than the hold window.
/// - `Batch` — hold up to `coalesce_max_delay_us` and merge into one frame.
///   The v0.3.0 default behaviour; best for trickle workloads.
enum class CoalescePolicy : std::uint8_t {
    Bypass = 0,
    Drain = 1,
    Batch = 2,
};

[[nodiscard]] constexpr std::string_view to_string(CoalescePolicy p) noexcept {
    switch (p) {
        case CoalescePolicy::Bypass:
            return "bypass";
        case CoalescePolicy::Drain:
            return "drain";
        case CoalescePolicy::Batch:
            return "batch";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// CoalesceMode — operator-selectable static configuration.
// ---------------------------------------------------------------------------

/// Top-level switch operators set via `tunnel.coalesce_mode`. Determines
/// whether `WriteCoalescer` runs the adaptive state machine or pins one
/// behaviour for the lifetime of the tunnel.
enum class CoalesceMode : std::uint8_t {
    /// v0.3.0 behaviour: always `Batch` (current default in v0.4.0).
    Fixed = 0,
    /// Run the state machine and select per-push.
    Adaptive = 1,
    /// Always `Bypass`.
    Bypass = 2,
    /// Always `Drain`.
    Drain = 3,
};

[[nodiscard]] constexpr std::string_view to_string(CoalesceMode m) noexcept {
    switch (m) {
        case CoalesceMode::Fixed:
            return "fixed";
        case CoalesceMode::Adaptive:
            return "adaptive";
        case CoalesceMode::Bypass:
            return "bypass";
        case CoalesceMode::Drain:
            return "drain";
    }
    return "unknown";
}

/// Parse a YAML string-typed coalesce mode. Returns true on success.
[[nodiscard]] bool parse_coalesce_mode(std::string_view s, CoalesceMode& out) noexcept;

// ---------------------------------------------------------------------------
// WriteCoalescer — EWMA + policy state machine.
// ---------------------------------------------------------------------------

/// Per-tunnel coalescer state. Holds an exponentially-weighted moving average
/// of write size and inter-arrival gap, plus the currently active policy.
/// Updated on every `TunnelImpl::send_data_to_tox` call.
///
/// EWMA implementation matches the design doc: α = 1/8 (TCP RTT convention),
/// pure integer math, no floating point on the hot path.
///
/// Thread safety: state is plain atomics; updates are lock-free. The active
/// policy is read on every push so concurrent updates are inherently safe.
class WriteCoalescer {
   public:
    WriteCoalescer() = default;

    /// Configure the operator-facing mode. Determines whether the state
    /// machine runs adaptive selection or pins one policy.
    void set_mode(CoalesceMode mode) noexcept { mode_.store(mode, std::memory_order_relaxed); }

    [[nodiscard]] CoalesceMode mode() const noexcept {
        return mode_.load(std::memory_order_relaxed);
    }

    /// Set the per-frame MTU + max hold delay. The state machine compares
    /// `avg_write_size` against `mtu_bytes` and `avg_write_gap_us` against
    /// `4 * max_delay_us` to pick policies.
    void configure(std::uint32_t mtu_bytes, std::uint32_t max_delay_us) noexcept {
        mtu_bytes_ = mtu_bytes ? mtu_bytes : 1;
        max_delay_us_ = max_delay_us;
    }

    /// Update the EWMA state with a new write observation.
    ///
    /// @param write_size      Size of the just-pushed write in bytes.
    /// @param gap_us          Microseconds since the previous push. Zero on
    ///                        the first call.
    void observe(std::size_t write_size, std::int64_t gap_us) noexcept;

    /// Run the state machine and return the policy to use for this push.
    /// Includes hysteresis: a transition is committed only after the
    /// candidate policy holds for `kHysteresisSamples` consecutive observations.
    /// On a transition, the second return value is true.
    struct Decision {
        CoalescePolicy policy{CoalescePolicy::Batch};
        CoalescePolicy previous{CoalescePolicy::Batch};
        bool transitioned{false};
    };
    Decision decide() noexcept;

    /// Read-only EWMA values for metrics / inspect.
    [[nodiscard]] std::uint64_t avg_write_size() const noexcept {
        return avg_write_size_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::int64_t avg_write_gap_us() const noexcept {
        return avg_write_gap_us_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] CoalescePolicy active_policy() const noexcept {
        return policy_.load(std::memory_order_relaxed);
    }

    /// Number of consecutive observations required before a candidate policy
    /// is promoted to active. Public for tests.
    static constexpr int kHysteresisSamples = 4;

   private:
    std::atomic<CoalesceMode> mode_{CoalesceMode::Fixed};
    std::uint32_t mtu_bytes_{1362};
    std::uint32_t max_delay_us_{200};

    // EWMA state. Stored as atomics so background readers (inspect, metrics)
    // see a consistent value without taking a lock. α = 1/8: integer shift.
    std::atomic<std::uint64_t> avg_write_size_{0};
    std::atomic<std::int64_t> avg_write_gap_us_{0};

    // Hysteresis tracking.
    // `candidate_` and `candidate_streak_` are read/written in `decide()`,
    // which is called from `send_data_to_tox()` on any tunnel-data path
    // before the coalesce mutex is taken — so concurrent inbound TCP reads
    // race here. Use atomics to keep updates well-defined; the small loss
    // of "strict" hysteresis under contention is acceptable because
    // hysteresis itself is statistical.
    std::atomic<CoalescePolicy> policy_{CoalescePolicy::Batch};
    std::atomic<CoalescePolicy> candidate_{CoalescePolicy::Batch};
    std::atomic<int> candidate_streak_{0};
};

}  // namespace toxtunnel::tunnel
