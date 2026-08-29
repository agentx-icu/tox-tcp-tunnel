#pragma once

#include <algorithm>
#include <chrono>

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// SENDQ retry cadence
// ---------------------------------------------------------------------------
//
// Schedule for re-attempting a frame that toxcore refused with
// `SendOutcome::SendqFull`, used by every driver that retains its own frame
// instead of parking it in TunnelManager's identity-less retry queue
// (TunnelImpl's TUNNEL_OPEN, TunnelServer's OPEN_ACK).
//
// WHY THIS IS NOT `tunnel.coalesce_max_delay_us`
//
// Reusing the coalesce timer's *object* is fine; reusing its *delay* is not.
// That value is an operator promise about latency ("never hold a byte longer
// than N us"), it defaults to 200 us, and on Windows any sub-tick value is
// deliberately clamped to 0 (see clamp_coalesce_delay_to_platform in
// tunnel.cpp) — which is the effective default there. A zero-delay asio timer
// that re-arms itself from its own handler is a spin: the io_context never goes
// idle and one wedged link burns a core. Even at 200 us it is a ~5 kHz retry
// loop, the exact pathology tunnel.cpp's backpressure_log_throttle exists to
// paper over.
//
// A toxcore send queue drains on toxcore's own schedule — one `tox_iterate`
// cycle, ~50 ms by default — so the useful granularity here is milliseconds.
// Start well under one iterate cycle so a queue that frees early is noticed
// promptly, then back off to roughly one cycle, past which extra attempts
// cannot learn anything new. The positive floor is what makes the schedule
// spin-free *by construction*, independent of any configuration.

/// First retry delay. Comfortably under one tox_iterate cycle.
inline constexpr std::chrono::microseconds kSendqRetryBaseDelay{2'000};

/// Backoff ceiling. Roughly one tox_iterate cycle.
inline constexpr std::chrono::microseconds kSendqRetryMaxDelay{50'000};

/// Delay before retry number @p attempt (0 = the first retry, i.e. the one
/// scheduled after the initial send came back SendqFull).
///
/// Monotonically non-decreasing, capped at kSendqRetryMaxDelay, and — the
/// property the callers depend on — always strictly positive.
[[nodiscard]] constexpr std::chrono::microseconds sendq_retry_delay(unsigned attempt) noexcept {
    auto delay = kSendqRetryBaseDelay;
    for (unsigned i = 0; i < attempt && delay < kSendqRetryMaxDelay; ++i) {
        delay *= 2;
    }
    return std::min(delay, kSendqRetryMaxDelay);
}

}  // namespace toxtunnel::tunnel
