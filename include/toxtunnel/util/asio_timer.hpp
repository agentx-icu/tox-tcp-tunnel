#pragma once

#include <asio.hpp>

namespace toxtunnel::util {

// The one shared non-throwing timer cancel (issue #24 slice 3). This build
// defines ASIO_NO_DEPRECATED, so the non-throwing cancel(error_code&) overload
// is gone; contain the throwing overload here. Every teardown / shutdown /
// terminal cancel must be non-throwing — a throw before close_all would strand
// the rest of teardown, destructors are effectively noexcept, and a claim that
// publishes a terminal state must not lose its notification ownership to a
// throwing cancel. A failed cancel only leaves a handler that the epoch checks
// at every handler entry already reject.
inline void cancel_timer_noexcept(asio::steady_timer& timer) noexcept {
    try {
        timer.cancel();
    } catch (...) {
    }
}

}  // namespace toxtunnel::util
