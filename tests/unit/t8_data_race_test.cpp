// Concurrent-stress tests for findings R5/R9/R10/R11 (T8 — data races on
// non-atomic shared state). On a normal build these just exercise the code
// paths without assertions; under `-DTOXTUNNEL_ENABLE_TSAN=ON`
// ThreadSanitizer turns any remaining data race into a test failure.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/tunnel/write_coalescer.hpp"
#include "toxtunnel/util/logger.hpp"

namespace {

constexpr int kIterations = 5000;
constexpr auto kSpinDuration = std::chrono::milliseconds(50);

// Spin the given function on N threads until either `kIterations` iterations
// have been completed by each thread or `kSpinDuration` has elapsed.
template <typename Fn>
void hammer(int num_threads, Fn fn) {
    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    std::atomic<bool> stop{false};
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([t, &stop, &fn]() {
            for (int i = 0; i < kIterations && !stop.load(std::memory_order_relaxed); ++i) {
                fn(t, i);
            }
        });
    }
    std::this_thread::sleep_for(kSpinDuration);
    stop.store(true, std::memory_order_relaxed);
    for (auto& th : threads) {
        th.join();
    }
}

}  // namespace

// F-CORE-9 / R5: accepting_ and max_connections_ accessed from any thread.
// Finding-2 (user-reported, 2026-05-21): TcpListener uses
// enable_shared_from_this; the listener MUST live in a shared_ptr or
// any code path that calls shared_from_this() (do_accept,
// set_max_connections's resume tail) throws bad_weak_ptr.
TEST(T8DataRace, TcpListenerAcceptingAndMaxConnections) {
    toxtunnel::core::IoContext ctx(2);
    auto listener =
        std::make_shared<toxtunnel::core::TcpListener>(ctx.get_io_context(), "127.0.0.1", 0);

    hammer(4, [&](int t, int i) {
        if (t == 0) {
            listener->set_max_connections(static_cast<std::size_t>(i % 1000 + 1));
        } else {
            (void)listener->max_connections();
            (void)listener->is_accepting();
            (void)listener->connection_count();
        }
    });
}

// F-CORE-1 / R5: running_ accessed concurrently.
TEST(T8DataRace, IoContextIsRunning) {
    toxtunnel::core::IoContext ctx(2);
    ctx.run();
    hammer(4, [&](int /*t*/, int /*i*/) { (void)ctx.is_running(); });
    ctx.stop();
}

// F-TUN-6 / R9: WriteCoalescer::decide hits candidate_/candidate_streak_.
TEST(T8DataRace, WriteCoalescerDecideAndObserve) {
    toxtunnel::tunnel::WriteCoalescer coalescer;
    coalescer.set_mode(toxtunnel::tunnel::CoalesceMode::Adaptive);
    coalescer.configure(1362, 200);
    hammer(4, [&](int t, int i) {
        coalescer.observe(static_cast<std::uint32_t>((t * 137 + i) % 4096),
                          static_cast<std::int64_t>(i % 1000));
        (void)coalescer.decide();
        (void)coalescer.active_policy();
        (void)coalescer.avg_write_size();
        (void)coalescer.avg_write_gap_us();
    });
}

// F-TUN-10 / R9/R10: TunnelManager::backpressure_threshold_ read in
// has_backpressure() hot path, written in set_backpressure_threshold().
TEST(T8DataRace, TunnelManagerBackpressureThreshold) {
    asio::io_context io;
    toxtunnel::tunnel::TunnelManager mgr(io);
    hammer(4, [&](int t, int i) {
        if (t == 0) {
            mgr.set_backpressure_threshold(static_cast<std::size_t>(i % 65536 + 1));
        } else {
            (void)mgr.backpressure_threshold();
            (void)mgr.has_backpressure();
        }
    });
}

// F-UTIL-4 / R11: Logger::get() previously had a fast-path that read
// `g_logger` (shared_ptr) without taking g_mutex. Pound on it from many
// threads while another thread re-initialises.
TEST(T8DataRace, LoggerGetAndInit) {
    toxtunnel::util::Logger::init("t8-race-test");
    hammer(4, [&](int t, int i) {
        if (t == 0 && (i % 100) == 0) {
            toxtunnel::util::Logger::init("t8-race-test");
        } else {
            auto logger = toxtunnel::util::Logger::get();
            EXPECT_TRUE(static_cast<bool>(logger));
        }
    });
}
