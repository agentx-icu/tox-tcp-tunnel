#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

using namespace toxtunnel::tunnel;
using namespace std::chrono_literals;

namespace {

// Marks a tunnel as Connected and wires it up enough that close() actually
// emits a TUNNEL_CLOSE through the recorded send callback. The reaper test
// suite intentionally does not need a real TCP/Tox stack.
std::unique_ptr<TunnelImpl> MakeConnectedTunnel(asio::io_context& io_ctx, uint16_t tunnel_id,
                                                std::atomic<int>* close_frames_seen = nullptr) {
    auto tunnel = std::make_unique<TunnelImpl>(io_ctx, tunnel_id, /*friend_number=*/1);
    if (close_frames_seen != nullptr) {
        tunnel->set_on_send_to_tox(
            [close_frames_seen, tunnel_id](std::span<const uint8_t> data) -> bool {
                if (!data.empty() && data[0] == static_cast<uint8_t>(FrameType::TUNNEL_CLOSE)) {
                    close_frames_seen->fetch_add(1);
                }
                (void)tunnel_id;
                return true;
            });
    }
    tunnel->set_state(Tunnel::State::Connected);
    return tunnel;
}

// Pump the io_context until `predicate` returns true or `deadline` elapses.
// Returns the predicate's final value.
template <typename Pred>
bool RunUntil(asio::io_context& io_ctx, Pred pred, std::chrono::milliseconds deadline = 2000ms) {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        if (std::chrono::steady_clock::now() - start > deadline) {
            return false;
        }
        io_ctx.poll();
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

}  // namespace

// ============================================================================
// IdleTunnelTest: per-tunnel activity tracking
// ============================================================================

class IdleTunnelTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
};

TEST_F(IdleTunnelTest, IdleNanosAdvancesOverTime) {
    TunnelImpl tunnel(io_ctx, /*tunnel_id=*/7, /*friend_number=*/1);
    const auto first = tunnel.IdleNanos();
    std::this_thread::sleep_for(20ms);
    const auto second = tunnel.IdleNanos();
    EXPECT_GT(second, first);
    EXPECT_GE(second - first, std::chrono::nanoseconds(15ms).count());
}

TEST_F(IdleTunnelTest, OnDataFrameResetsIdleTimer) {
    auto tunnel = std::make_unique<TunnelImpl>(io_ctx, /*tunnel_id=*/8, /*friend_number=*/1);
    tunnel->set_state(Tunnel::State::Connected);

    std::this_thread::sleep_for(30ms);
    const auto idle_before = tunnel->IdleNanos();
    ASSERT_GT(idle_before, std::chrono::nanoseconds(20ms).count());

    const std::array<uint8_t, 4> payload{1, 2, 3, 4};
    auto frame = ProtocolFrame::make_tunnel_data(8, std::span<const uint8_t>(payload));
    tunnel->handle_frame(frame);

    const auto idle_after = tunnel->IdleNanos();
    EXPECT_LT(idle_after, idle_before);
    EXPECT_LT(idle_after, std::chrono::nanoseconds(10ms).count());
}

TEST_F(IdleTunnelTest, SendDataResetsIdleTimer) {
    auto tunnel = std::make_unique<TunnelImpl>(io_ctx, /*tunnel_id=*/9, /*friend_number=*/1);
    tunnel->set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return true; });
    tunnel->set_state(Tunnel::State::Connected);

    std::this_thread::sleep_for(30ms);
    const auto idle_before = tunnel->IdleNanos();
    ASSERT_GT(idle_before, std::chrono::nanoseconds(20ms).count());

    const std::vector<uint8_t> payload{5, 6, 7, 8};
    ASSERT_TRUE(tunnel->send_data_to_tox(payload));

    const auto idle_after = tunnel->IdleNanos();
    EXPECT_LT(idle_after, idle_before);
}

TEST_F(IdleTunnelTest, PingPongDoesNotResetIdleTimer) {
    auto tunnel = std::make_unique<TunnelImpl>(io_ctx, /*tunnel_id=*/10, /*friend_number=*/1);
    tunnel->set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return true; });
    tunnel->set_state(Tunnel::State::Connected);

    std::this_thread::sleep_for(30ms);
    const auto idle_before = tunnel->IdleNanos();
    ASSERT_GT(idle_before, std::chrono::nanoseconds(20ms).count());

    auto ping = ProtocolFrame::make_ping();
    tunnel->handle_frame(ping);
    auto pong = ProtocolFrame::make_pong();
    tunnel->handle_frame(pong);

    const auto idle_after = tunnel->IdleNanos();
    EXPECT_GE(idle_after, idle_before);
}

TEST_F(IdleTunnelTest, AckDoesNotResetIdleTimer) {
    auto tunnel = std::make_unique<TunnelImpl>(io_ctx, /*tunnel_id=*/11, /*friend_number=*/1);
    tunnel->set_state(Tunnel::State::Connected);

    std::this_thread::sleep_for(30ms);
    const auto idle_before = tunnel->IdleNanos();
    ASSERT_GT(idle_before, std::chrono::nanoseconds(20ms).count());

    auto ack = ProtocolFrame::make_tunnel_ack(11, /*bytes_acked=*/0);
    tunnel->handle_frame(ack);

    const auto idle_after = tunnel->IdleNanos();
    EXPECT_GE(idle_after, idle_before);
}

// ============================================================================
// ReaperTest: TunnelManager reaper behaviour
// ============================================================================

class ReaperTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
    // shared_ptr (not unique_ptr): TunnelManager inherits
    // enable_shared_from_this so the reaper timer callback can capture
    // weak_from_this(). A unique_ptr-owned instance would leave
    // weak_from_this empty and the reaper would silently no-op.
    std::shared_ptr<TunnelManager> manager;

    void SetUp() override {
        manager = std::make_shared<TunnelManager>(io_ctx);
        manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });
    }

    void TearDown() override { manager.reset(); }
};

TEST_F(ReaperTest, ReapsIdleTunnel) {
    std::atomic<int> close_frames{0};
    auto idle = MakeConnectedTunnel(io_ctx, /*tunnel_id=*/100, &close_frames);
    manager->add_tunnel(100, std::move(idle));

    // Configure a 1s idle threshold and a long tick (we drive the pass
    // synchronously via reap_idle_tunnels_once()).
    manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/3600);

    // Sleep past the threshold and run a manual pass.
    std::this_thread::sleep_for(1100ms);
    const std::size_t closed = manager->reap_idle_tunnels_once();

    EXPECT_EQ(closed, 1u);
    EXPECT_FALSE(manager->has_tunnel(100));
    EXPECT_GE(close_frames.load(), 1);
}

TEST_F(ReaperTest, SkipsActiveTunnel) {
    auto active = MakeConnectedTunnel(io_ctx, /*tunnel_id=*/200);
    auto* active_raw = active.get();
    manager->add_tunnel(200, std::move(active));

    manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/3600);

    // Keep bumping activity well within the idle window.
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(100ms);
        const std::array<uint8_t, 2> payload{0xAA, 0xBB};
        auto frame = ProtocolFrame::make_tunnel_data(200, std::span<const uint8_t>(payload));
        active_raw->handle_frame(frame);
    }

    const std::size_t closed = manager->reap_idle_tunnels_once();
    EXPECT_EQ(closed, 0u);
    EXPECT_TRUE(manager->has_tunnel(200));
}

TEST_F(ReaperTest, SkipsConnectingTunnel) {
    auto opening = std::make_unique<TunnelImpl>(io_ctx, /*tunnel_id=*/300, /*friend_number=*/1);
    opening->set_state(Tunnel::State::Connecting);
    manager->add_tunnel(300, std::move(opening));

    std::this_thread::sleep_for(1100ms);

    manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/3600);
    const std::size_t closed = manager->reap_idle_tunnels_once();
    EXPECT_EQ(closed, 0u);
    EXPECT_TRUE(manager->has_tunnel(300));
}

TEST_F(ReaperTest, ZeroTimeoutDisablesReaping) {
    auto idle = MakeConnectedTunnel(io_ctx, /*tunnel_id=*/400);
    manager->add_tunnel(400, std::move(idle));

    std::this_thread::sleep_for(50ms);

    // idle_timeout_seconds == 0 is a no-op; no pass should fire.
    manager->enable_reaper(/*idle_timeout_seconds=*/0, /*tick_seconds=*/1);

    // Wait briefly and confirm nothing was reaped.
    io_ctx.poll();
    std::this_thread::sleep_for(50ms);
    io_ctx.poll();

    EXPECT_TRUE(manager->has_tunnel(400));

    // Calling reap_idle_tunnels_once() directly with a zero timeout must
    // also be a no-op rather than mass-closing.
    const std::size_t closed = manager->reap_idle_tunnels_once();
    EXPECT_EQ(closed, 0u);
    EXPECT_TRUE(manager->has_tunnel(400));
}

TEST_F(ReaperTest, TimerFiresPeriodically) {
    auto idle = MakeConnectedTunnel(io_ctx, /*tunnel_id=*/500);
    manager->add_tunnel(500, std::move(idle));

    // Idle window is 1s, but we'll let the tunnel sit ~1.2s before the tick.
    std::this_thread::sleep_for(1200ms);

    // Tick = 0 is rejected (no-op), use 1s.
    manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/1);

    // Pump the io_context until the timer fires and removes the tunnel,
    // or we time out.
    auto reaped_predicate = [&] { return !manager->has_tunnel(500); };
    const bool reaped = RunUntil(io_ctx, reaped_predicate, 5000ms);
    EXPECT_TRUE(reaped);
}

TEST_F(ReaperTest, DestructorCancelsCleanly) {
    auto local_io = std::make_unique<asio::io_context>();
    auto mgr = std::make_shared<TunnelManager>(*local_io);
    mgr->set_send_handler([](const std::vector<uint8_t>&) { return true; });

    auto t = std::make_shared<TunnelImpl>(*local_io, /*tunnel_id=*/600, /*friend_number=*/1);
    t->set_state(Tunnel::State::Connected);
    mgr->add_tunnel(600, std::move(t));

    mgr->enable_reaper(/*idle_timeout_seconds=*/3600, /*tick_seconds=*/3600);

    // Destroy the manager while the timer is armed. The timer must cancel
    // cleanly without dereferencing freed state when the io_context runs.
    mgr.reset();

    // The cancelled handler still posts a completion with
    // operation_aborted — pump it through so asan/ubsan can flag a UAF.
    local_io->poll();
    // No assertion beyond "didn't crash".
    SUCCEED();
}

TEST_F(ReaperTest, DisableThenEnableRestartsTimer) {
    auto idle = MakeConnectedTunnel(io_ctx, /*tunnel_id=*/700);
    manager->add_tunnel(700, std::move(idle));

    manager->enable_reaper(/*idle_timeout_seconds=*/3600, /*tick_seconds=*/3600);
    manager->disable_reaper();

    // After disable, threshold is 0 and a manual pass is a no-op.
    EXPECT_EQ(manager->reap_idle_tunnels_once(), 0u);
    EXPECT_TRUE(manager->has_tunnel(700));

    std::this_thread::sleep_for(1100ms);
    manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/3600);
    EXPECT_EQ(manager->reap_idle_tunnels_once(), 1u);
    EXPECT_FALSE(manager->has_tunnel(700));
}

// ============================================================================
// KeepaliveTest: application-level PING/PONG liveness (M-02)
// ============================================================================

class KeepaliveTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
    std::shared_ptr<TunnelManager> manager;

    void SetUp() override {
        manager = std::make_shared<TunnelManager>(io_ctx);
        manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });
    }
    void TearDown() override {
        if (manager) {
            manager->disable_keepalive();
        }
        manager.reset();
    }
};

TEST_F(KeepaliveTest, DeclaresPeerDeadWhenNoPong) {
    std::atomic<bool> dead{false};
    manager->set_on_peer_dead([&dead]() { dead.store(true); });
    // Ping every 1s, declare dead after 1s of silence. No PONGs are ever fed.
    manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/1);
    EXPECT_TRUE(RunUntil(
        io_ctx, [&dead] { return dead.load(); }, 5000ms));
}

TEST_F(KeepaliveTest, StaysAliveWhilePongsArrive) {
    std::atomic<bool> dead{false};
    manager->set_on_peer_dead([&dead]() { dead.store(true); });
    manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/2);

    // Feed a PONG every 200ms for ~3s; the peer must never be declared dead.
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < 3000ms) {
        manager->note_pong();
        io_ctx.poll();
        std::this_thread::sleep_for(200ms);
    }
    EXPECT_FALSE(dead.load());
}

TEST_F(KeepaliveTest, SendsPeriodicPingFrames) {
    std::atomic<int> pings{0};
    manager->set_send_handler([&pings](const std::vector<uint8_t>& f) {
        if (!f.empty() && f[0] == static_cast<uint8_t>(FrameType::PING)) {
            pings.fetch_add(1);
        }
        return true;
    });
    // Long timeout so the peer is never declared dead during the test; we just
    // want to observe PINGs being emitted on the interval.
    manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    EXPECT_TRUE(RunUntil(
        io_ctx, [&pings] { return pings.load() >= 2; }, 5000ms));
}
