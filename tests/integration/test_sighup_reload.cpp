// Integration test for the SIGHUP reload signal-handling glue used by
// cli/main.cpp.
//
// We don't boot a full TunnelServer here (toxcore init binds ports and
// generates a keypair — far too heavy for a CI unit). Instead we wire up
// the same `asio::signal_set(SIGHUP)` machinery the cli uses, deliver a
// real SIGHUP to ourselves with `kill(getpid(), SIGHUP)`, and assert the
// callback fires. This pins the "kernel -> asio -> reload callback" path
// that the cli relies on.
//
// We also re-arm the signal handler from inside the callback (exactly as
// cli/main.cpp does) and prove a second SIGHUP triggers a second reload,
// which is the contract operators rely on.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#endif

namespace toxtunnel::integration {

#ifndef _WIN32

TEST(SighupReloadTest, SignalSetFiresOnSigHup) {
    asio::io_context ctx;
    asio::signal_set reload(ctx, SIGHUP);
    std::atomic<int> hits{0};

    std::function<void(const asio::error_code&, int)> handler = [&](const asio::error_code& ec,
                                                                    int /*sig*/) {
        if (ec)
            return;
        hits.fetch_add(1, std::memory_order_release);
        reload.async_wait(handler);
    };
    reload.async_wait(handler);

    // Drive ctx on a worker thread so we can deliver the signal from the
    // test thread and observe the callback land.
    std::thread runner([&] { ctx.run(); });

    // First SIGHUP.
    ASSERT_EQ(::kill(::getpid(), SIGHUP), 0);

    // Wait up to 2s for the handler to fire. Anything more than a few ms is
    // a sign that asio's signalfd plumbing is broken on this platform.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (hits.load(std::memory_order_acquire) < 1 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_GE(hits.load(), 1);

    // Second SIGHUP — proves the re-arm in the callback works (the operator
    // contract is "safe to send SIGHUP repeatedly").
    ASSERT_EQ(::kill(::getpid(), SIGHUP), 0);
    const auto deadline2 = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (hits.load(std::memory_order_acquire) < 2 &&
           std::chrono::steady_clock::now() < deadline2) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_GE(hits.load(), 2);

    ctx.stop();
    runner.join();
}

// Regression for the POSIX shutdown hang fixed alongside v0.4.3.
//
// cli/main.cpp's run_server() drives signal_ctx.run() directly on the main
// thread and arms two signal_sets on it: a one-shot SIGINT/SIGTERM handler
// (which calls server.stop()) and a SIGHUP reload handler that re-arms
// itself inside its own callback. Before the fix, run() never returned
// after SIGTERM because reload_signals always had a pending async_wait,
// even though server.stop() had finished cleanly. The daemon logged a
// complete shutdown sequence and then sat in kevent forever — only
// SIGKILL would actually retire the process.
//
// This test stands up the same structure and asserts that delivering a
// real SIGTERM causes signal_ctx.run() to return within a bounded time.
TEST(SighupReloadTest, SigtermUnblocksRunWithReArmingSighupHandler) {
    asio::io_context signal_ctx;
    asio::signal_set term_signals(signal_ctx, SIGTERM);
    asio::signal_set reload_signals(signal_ctx, SIGHUP);
    std::atomic<bool> term_fired{false};

    term_signals.async_wait([&](const asio::error_code& ec, int /*sig*/) {
        if (ec)
            return;
        term_fired.store(true, std::memory_order_release);
        signal_ctx.stop();
    });

    // Same re-arming pattern as cli/main.cpp's reload handler.
    std::function<void(const asio::error_code&, int)> on_reload =
        [&](const asio::error_code& ec, int /*sig*/) {
            if (ec)
                return;
            reload_signals.async_wait(on_reload);
        };
    reload_signals.async_wait(on_reload);

    std::thread killer([] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ::kill(::getpid(), SIGTERM);
    });

    // run() must return within the deadline; before the fix this was infinite.
    const auto start = std::chrono::steady_clock::now();
    signal_ctx.run();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    killer.join();

    EXPECT_TRUE(term_fired.load());
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

#endif  // !_WIN32

}  // namespace toxtunnel::integration
