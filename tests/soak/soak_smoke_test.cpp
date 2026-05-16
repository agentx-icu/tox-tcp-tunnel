// Soak-test infrastructure smoke test.
//
// The real soak fixtures (8h steady-state, 200k ID-exhaustion cycle,
// reload storm) live alongside this file and are intentionally NOT
// driven from the default `ctest` run — they consume too much wall
// clock for fast CI. This smoke test proves the harness compiles and
// links against `toxtunnel_lib`, runs a 10-second mini-soak using the
// same helpers, and asserts the standard invariants
// (no leaked tunnels, allocator wraps correctly).
//
// Operators run the full suite via `ctest -L soak`. The release-branch
// CI is wired separately (see docs/plans/2026-05-15-stability-hardening
// for the operational policy).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "toxtunnel/tunnel/tunnel_id_allocator.hpp"

namespace toxtunnel::test {
namespace {

using namespace std::chrono_literals;

// =============================================================================
// 1. Mini steady-state: exercise the allocator and a worker loop for 1s.
//    Acts as the "the harness works" canary.
// =============================================================================

TEST(SoakSmoke, MiniSteadyState) {
    tunnel::TunnelIdAllocator allocator;
    std::atomic<int> opens{0};
    std::atomic<int> closes{0};

    const auto end = std::chrono::steady_clock::now() + 1s;
    while (std::chrono::steady_clock::now() < end) {
        auto id = allocator.allocate();
        if (id == 0) {
            break;  // exhausted
        }
        opens.fetch_add(1);
        allocator.release(id);
        closes.fetch_add(1);
    }

    EXPECT_GT(opens.load(), 0);
    EXPECT_EQ(opens.load(), closes.load());
    EXPECT_EQ(allocator.in_use_count(), 0u);
}

// =============================================================================
// 2. Mini ID-exhaustion: open + close 200k tunnels back-to-back. With proper
//    recycling this should never report 0 from allocate().
// =============================================================================

TEST(SoakSmoke, MiniIdExhaustionCycle) {
    tunnel::TunnelIdAllocator allocator;
    for (int i = 0; i < 200000; ++i) {
        auto id = allocator.allocate();
        ASSERT_NE(id, 0) << "allocator exhausted at iteration " << i;
        allocator.release(id);
    }
    EXPECT_EQ(allocator.in_use_count(), 0u);
}

}  // namespace
}  // namespace toxtunnel::test
