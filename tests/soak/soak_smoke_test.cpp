// Short, bounded soak-style smoke tests.
//
// These checks are included in the default `ctest` run. The `soak` label also
// allows running just these checks via `ctest -L soak`. They exercise allocator
// reuse and a one-second steady-state loop; they are not a long-duration soak
// suite.

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
