#include "toxtunnel/tunnel/write_coalescer.hpp"

#include <algorithm>

namespace toxtunnel::tunnel {

bool parse_coalesce_mode(std::string_view s, CoalesceMode& out) noexcept {
    if (s == "fixed") {
        out = CoalesceMode::Fixed;
        return true;
    }
    if (s == "adaptive") {
        out = CoalesceMode::Adaptive;
        return true;
    }
    if (s == "bypass") {
        out = CoalesceMode::Bypass;
        return true;
    }
    if (s == "drain") {
        out = CoalesceMode::Drain;
        return true;
    }
    return false;
}

void WriteCoalescer::observe(std::size_t write_size, std::int64_t gap_us) noexcept {
    // EWMA with α = 1/8 implemented as `new = old + (sample - old) >> 3`.
    // Match the TCP RTT convention so any future RTT-based scaler can reuse
    // the same constants.
    auto prev_size = avg_write_size_.load(std::memory_order_relaxed);
    if (prev_size == 0) {
        avg_write_size_.store(static_cast<std::uint64_t>(write_size), std::memory_order_relaxed);
    } else {
        std::int64_t delta =
            static_cast<std::int64_t>(write_size) - static_cast<std::int64_t>(prev_size);
        avg_write_size_.store(
            static_cast<std::uint64_t>(static_cast<std::int64_t>(prev_size) + (delta >> 3)),
            std::memory_order_relaxed);
    }

    if (gap_us > 0) {
        auto prev_gap = avg_write_gap_us_.load(std::memory_order_relaxed);
        if (prev_gap == 0) {
            avg_write_gap_us_.store(gap_us, std::memory_order_relaxed);
        } else {
            std::int64_t delta = gap_us - prev_gap;
            avg_write_gap_us_.store(prev_gap + (delta >> 3), std::memory_order_relaxed);
        }
    }
}

WriteCoalescer::Decision WriteCoalescer::decide() noexcept {
    Decision d;
    d.previous = policy_.load(std::memory_order_relaxed);

    // Operator-pinned modes ignore the state machine entirely.
    switch (mode_.load(std::memory_order_relaxed)) {
        case CoalesceMode::Fixed:
            d.policy = CoalescePolicy::Batch;
            policy_.store(d.policy, std::memory_order_relaxed);
            return d;
        case CoalesceMode::Bypass:
            d.policy = CoalescePolicy::Bypass;
            policy_.store(d.policy, std::memory_order_relaxed);
            return d;
        case CoalesceMode::Drain:
            d.policy = CoalescePolicy::Drain;
            policy_.store(d.policy, std::memory_order_relaxed);
            return d;
        case CoalesceMode::Adaptive:
            break;
    }

    // Adaptive: state machine from the design doc.
    //
    //   avg_write_size >= MTU?
    //     YES  → Bypass
    //     NO   → avg_write_gap > 4 * max_delay?
    //              YES → Drain (no point holding; each write stands alone)
    //              NO  → Batch (default; payloads are small and arrive quickly)
    const auto size = avg_write_size_.load(std::memory_order_relaxed);
    const auto gap = avg_write_gap_us_.load(std::memory_order_relaxed);

    CoalescePolicy candidate;
    if (size >= mtu_bytes_) {
        candidate = CoalescePolicy::Bypass;
    } else if (gap > static_cast<std::int64_t>(4) * static_cast<std::int64_t>(max_delay_us_)) {
        candidate = CoalescePolicy::Drain;
    } else {
        candidate = CoalescePolicy::Batch;
    }

    // Hysteresis: require kHysteresisSamples observations in a row before
    // committing the transition. This avoids flapping on a brief mode change.
    if (candidate == d.previous) {
        candidate_streak_ = 0;
        d.policy = d.previous;
        return d;
    }
    if (candidate != candidate_) {
        candidate_ = candidate;
        candidate_streak_ = 1;
        d.policy = d.previous;
        return d;
    }
    if (++candidate_streak_ < kHysteresisSamples) {
        d.policy = d.previous;
        return d;
    }

    d.policy = candidate;
    d.transitioned = true;
    policy_.store(d.policy, std::memory_order_relaxed);
    candidate_streak_ = 0;
    return d;
}

}  // namespace toxtunnel::tunnel
