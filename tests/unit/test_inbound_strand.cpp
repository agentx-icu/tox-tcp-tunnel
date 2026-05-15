// Regression test for the inbound-dispatch strand used by TunnelClient and
// TunnelServer.
//
// Background: an earlier perf change off-loaded inbound lossless-packet
// handling from the single Tox iterate thread onto the multi-threaded IO
// pool via raw `asio::post(io_context, ...)`. Two consecutive packets for
// the same friend (e.g. TUNNEL_ACK followed by TUNNEL_DATA) could then be
// picked up by different worker threads and run out of order — a DATA
// frame would land before its tunnel transitioned to Connected and get
// silently dropped, manifesting as a stalled SSH session.
//
// The fix is to post inbound work onto an asio::strand layered over the
// IO pool so that *per-friend frame ordering* is preserved while other
// pool work still runs in parallel.
//
// These tests pin the invariant: under heavy contention, a strand-posted
// sequence is observed in posted order.
#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

namespace {

// Number of tasks the test posts. Large enough that any naive multi-thread
// scheduling will reorder them with overwhelming probability if no strand
// is in use.
constexpr int kPostCount = 1000;

// IO pool size. Mirrors TunnelClient/TunnelServer's "many workers" setup.
constexpr int kThreads = 8;

}  // namespace

TEST(InboundStrandRegression, StrandPreservesArrivalOrder) {
    asio::io_context io_ctx;
    auto work_guard = asio::make_work_guard(io_ctx);

    // Multi-threaded pool — same shape as the real TunnelClient/Server.
    std::vector<std::thread> pool;
    pool.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        pool.emplace_back([&io_ctx] { io_ctx.run(); });
    }

    auto strand = asio::make_strand(io_ctx.get_executor());

    std::vector<int> observed;
    observed.reserve(kPostCount);
    std::mutex observed_mu;
    std::atomic<int> seen{0};

    // Post every task onto the strand. Each one writes its sequence
    // number into a shared vector. The strand guarantees serialised
    // execution, so the vector must end up as [0, 1, 2, ..., N-1].
    for (int i = 0; i < kPostCount; ++i) {
        asio::post(strand, [i, &observed, &observed_mu, &seen] {
            {
                std::lock_guard<std::mutex> lock(observed_mu);
                observed.push_back(i);
            }
            seen.fetch_add(1, std::memory_order_release);
        });
    }

    // Wait for all posts to drain.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (seen.load(std::memory_order_acquire) < kPostCount &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    work_guard.reset();
    io_ctx.stop();
    for (auto& t : pool) {
        t.join();
    }

    ASSERT_EQ(observed.size(), static_cast<std::size_t>(kPostCount));
    for (int i = 0; i < kPostCount; ++i) {
        ASSERT_EQ(observed[i], i) << "out-of-order at position " << i;
    }
}

// Companion: simulate the exact two-packet pattern that triggered the
// production bug. Two posts back-to-back representing TUNNEL_ACK then
// TUNNEL_DATA for the same logical tunnel must run in posted order.
// Repeated under the multi-thread pool to flush out the race.
TEST(InboundStrandRegression, AckBeforeDataPairAlwaysOrdered) {
    constexpr int kPairs = 500;

    asio::io_context io_ctx;
    auto work_guard = asio::make_work_guard(io_ctx);
    std::vector<std::thread> pool;
    pool.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        pool.emplace_back([&io_ctx] { io_ctx.run(); });
    }

    auto strand = asio::make_strand(io_ctx.get_executor());

    // Per-pair state machine: ACK first transitions to Connected, then
    // DATA must observe Connected. If DATA ran first, it would observe
    // Connecting and "drop" — modeled here as an error counter.
    std::atomic<int> dropped_data{0};
    std::atomic<int> delivered_data{0};
    std::atomic<int> done{0};

    for (int p = 0; p < kPairs; ++p) {
        // Each pair gets its own connection state, captured by reference
        // to the strand-posted lambdas. Using shared_ptr so the state
        // outlives stack frames once the loop iteration ends.
        auto connected = std::make_shared<std::atomic<bool>>(false);

        // ACK first: flips state to Connected.
        asio::post(strand, [connected] { connected->store(true, std::memory_order_release); });

        // DATA second: must observe Connected. If not, we modeled a drop.
        asio::post(strand, [connected, &dropped_data, &delivered_data, &done] {
            if (connected->load(std::memory_order_acquire)) {
                delivered_data.fetch_add(1, std::memory_order_relaxed);
            } else {
                dropped_data.fetch_add(1, std::memory_order_relaxed);
            }
            done.fetch_add(1, std::memory_order_release);
        });
    }

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (done.load(std::memory_order_acquire) < kPairs &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    work_guard.reset();
    io_ctx.stop();
    for (auto& t : pool) {
        t.join();
    }

    EXPECT_EQ(dropped_data.load(), 0);
    EXPECT_EQ(delivered_data.load(), kPairs);
}
