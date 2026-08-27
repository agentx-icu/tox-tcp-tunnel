#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

using namespace toxtunnel::tunnel;

// ============================================================================
// Helper for creating data spans in tests
// ============================================================================

template <std::size_t N>
std::span<const uint8_t> make_span(const std::array<uint8_t, N>& arr) {
    return std::span<const uint8_t>(arr.data(), N);
}

// ============================================================================
// Concrete Tunnel subclass for testing TunnelManager
// ============================================================================

/// A minimal concrete implementation of the abstract Tunnel class for testing.
/// Provides controllable behavior and records interactions.
class TestTunnel : public Tunnel {
   public:
    TestTunnel(uint16_t tunnel_id, asio::io_context& io_ctx) : Tunnel(tunnel_id, io_ctx) {}

    // -- Tunnel interface implementation --

    [[nodiscard]] State state() const noexcept override { return state_; }

    [[nodiscard]] bool is_active() const override { return state_ == State::Connected; }

    [[nodiscard]] std::size_t buffer_level() const override { return buffer_level_; }

    void handle_frame(const ProtocolFrame& /*frame*/) override { ++frames_handled_; }

    void close() override {
        ++close_count_;
        state_ = State::Closed;
    }

    // -- Test-specific accessors --

    int frames_handled() const { return frames_handled_; }
    int close_count() const { return close_count_; }

    void set_state_for_test(State s) { state_ = s; }
    void set_buffer_level(std::size_t level) { buffer_level_ = level; }

   private:
    State state_{State::None};
    std::size_t buffer_level_{0};
    std::atomic<int> frames_handled_{0};
    int close_count_{0};
};

// ============================================================================
// Test Fixture
// ============================================================================

class TunnelManagerTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
    std::unique_ptr<TunnelManager> manager;

    void SetUp() override { manager = std::make_unique<TunnelManager>(io_ctx); }

    void TearDown() override { manager.reset(); }

    // Helper to create a TestTunnel
    std::shared_ptr<TestTunnel> create_test_tunnel(uint16_t tunnel_id) {
        return std::make_shared<TestTunnel>(tunnel_id, io_ctx);
    }
};

// ============================================================================
// 1. InitialState - verify initial manager state
// ============================================================================

TEST_F(TunnelManagerTest, InitialState_HasNoTunnels) {
    EXPECT_EQ(manager->tunnel_count(), 0u);
    EXPECT_TRUE(manager->empty());
}

TEST_F(TunnelManagerTest, InitialState_NoTunnelExists) {
    EXPECT_FALSE(manager->has_tunnel(1));
    EXPECT_FALSE(manager->has_tunnel(100));
}

TEST_F(TunnelManagerTest, InitialState_NextTunnelIdIsOne) {
    EXPECT_EQ(manager->allocate_tunnel_id().value(), 1u);
}

// ============================================================================
// 2. TunnelIdAllocation - test tunnel ID allocation
// ============================================================================

TEST_F(TunnelManagerTest, TunnelIdAllocation_Sequential) {
    auto id1 = manager->allocate_tunnel_id().value();
    auto id2 = manager->allocate_tunnel_id().value();
    auto id3 = manager->allocate_tunnel_id().value();

    EXPECT_EQ(id1, 1u);
    EXPECT_EQ(id2, 2u);
    EXPECT_EQ(id3, 3u);
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_WrapsOnOverflow) {
    // Simulate being near the end of the ID space
    manager->set_next_tunnel_id(65534);

    auto id1 = manager->allocate_tunnel_id().value();
    auto id2 = manager->allocate_tunnel_id().value();
    auto id3 = manager->allocate_tunnel_id().value();

    EXPECT_EQ(id1, 65534u);
    EXPECT_EQ(id2, 65535u);
    EXPECT_EQ(id3, 1u);  // Wraps to 1, skipping 0 (reserved)
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_SkipsZero) {
    manager->set_next_tunnel_id(0);
    auto id = manager->allocate_tunnel_id().value();
    EXPECT_EQ(id, 1u);
}

// C-19 / 2026-05-20 finding: handle_incoming_open() marks used_ids_ but
// does not actually insert a Tunnel into tunnels_ — the caller is
// expected to follow up with add_tunnel(). If the caller fails or is
// killed between the two calls, the used_ids_ slot leaks forever:
// reaper/remove_tunnel can't reach it (tunnels_.find returns end). The
// public release_tunnel_id() is the documented escape hatch, used by
// TunnelServer's RAII guard at the call site. This test pins the
// invariant: after handle_incoming_open + release_tunnel_id, a new
// allocate_tunnel_id can reclaim that slot.
TEST_F(TunnelManagerTest, IncomingOpenSlotReclaimableAfterRelease) {
    constexpr uint16_t kProbeId = 137;
    // Forge a TUNNEL_OPEN frame for the probe ID.
    auto frame = ProtocolFrame::make_tunnel_open(kProbeId, "host.example", 22);
    ASSERT_TRUE(manager->handle_incoming_open(frame));

    // Caller failed to register: simulate the RAII guard's destructor.
    manager->release_tunnel_id(kProbeId);

    // The slot must now be free: a fresh allocator pointed at kProbeId
    // should return it, not skip it.
    manager->set_next_tunnel_id(kProbeId);
    EXPECT_EQ(manager->allocate_tunnel_id().value(), kProbeId);
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_SkipsInUseIds) {
    // Allocate and create a tunnel with ID 2
    auto id1 = manager->allocate_tunnel_id().value();  // 1
    auto id2 = manager->allocate_tunnel_id().value();  // 2

    // Create tunnel with id2
    auto tunnel = create_test_tunnel(id2);
    manager->add_tunnel(id2, std::move(tunnel));

    // Release id1 so it can be reused
    manager->release_tunnel_id(id1);

    // Next allocation should skip 2 (in use) and find 3
    auto id3 = manager->allocate_tunnel_id().value();
    EXPECT_EQ(id3, 3u);
}

// ============================================================================
// 3. TunnelLifecycle - test adding and removing tunnels
// ============================================================================

TEST_F(TunnelManagerTest, TunnelLifecycle_AddTunnel) {
    auto tunnel = create_test_tunnel(1);
    manager->add_tunnel(1, std::move(tunnel));

    EXPECT_TRUE(manager->has_tunnel(1));
    EXPECT_EQ(manager->tunnel_count(), 1u);
    EXPECT_FALSE(manager->empty());
}

TEST_F(TunnelManagerTest, TunnelLifecycle_AddMultipleTunnels) {
    manager->add_tunnel(1, create_test_tunnel(1));
    manager->add_tunnel(2, create_test_tunnel(2));
    manager->add_tunnel(3, create_test_tunnel(3));

    EXPECT_EQ(manager->tunnel_count(), 3u);
    EXPECT_TRUE(manager->has_tunnel(1));
    EXPECT_TRUE(manager->has_tunnel(2));
    EXPECT_TRUE(manager->has_tunnel(3));
}

TEST_F(TunnelManagerTest, TunnelLifecycle_RemoveTunnel) {
    manager->add_tunnel(1, create_test_tunnel(1));

    EXPECT_TRUE(manager->has_tunnel(1));
    manager->remove_tunnel(1);

    EXPECT_FALSE(manager->has_tunnel(1));
    EXPECT_EQ(manager->tunnel_count(), 0u);
    EXPECT_TRUE(manager->empty());
}

TEST_F(TunnelManagerTest, TunnelLifecycle_RemoveNonExistentTunnel) {
    // Should not throw or crash
    EXPECT_NO_THROW(manager->remove_tunnel(999));
    EXPECT_EQ(manager->tunnel_count(), 0u);
}

TEST_F(TunnelManagerTest, TunnelLifecycle_GetTunnel) {
    auto tunnel = create_test_tunnel(1);
    auto* raw_ptr = tunnel.get();
    manager->add_tunnel(1, tunnel);

    auto retrieved = manager->get_tunnel(1);
    EXPECT_EQ(retrieved.get(), raw_ptr);
}

TEST_F(TunnelManagerTest, TunnelLifecycle_GetNonExistentTunnel) {
    auto retrieved = manager->get_tunnel(999);
    EXPECT_EQ(retrieved, nullptr);
}

TEST_F(TunnelManagerTest, TunnelLifecycle_CloseAll) {
    manager->add_tunnel(1, create_test_tunnel(1));
    manager->add_tunnel(2, create_test_tunnel(2));
    manager->add_tunnel(3, create_test_tunnel(3));

    manager->close_all();

    EXPECT_EQ(manager->tunnel_count(), 0u);
}

// ============================================================================
// 4. FrameRouting - test routing frames to correct tunnels
// ============================================================================

TEST_F(TunnelManagerTest, FrameRouting_RoutesDataToCorrectTunnel) {
    auto t1 = create_test_tunnel(1);
    auto t2 = create_test_tunnel(2);
    auto* t2_ptr = static_cast<TestTunnel*>(t2.get());

    manager->add_tunnel(1, std::move(t1));
    manager->add_tunnel(2, std::move(t2));

    // Route a data frame to tunnel 2
    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame data_frame = ProtocolFrame::make_tunnel_data(2, make_span(data));

    // Route the frame - tunnel 2 should process it
    EXPECT_NO_THROW(manager->route_frame(data_frame));
    EXPECT_EQ(t2_ptr->frames_handled(), 1);
}

TEST_F(TunnelManagerTest, FrameRouting_HandlesUnknownTunnelId) {
    // Route frame to non-existent tunnel - should not crash
    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame data_frame = ProtocolFrame::make_tunnel_data(999, make_span(data));

    // Set up a send handler for error responses
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    EXPECT_NO_THROW(manager->route_frame(data_frame));
}

TEST_F(TunnelManagerTest, FrameRouting_TunnelErrorTriggersOnCloseCleanup) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, /*tunnel_id=*/77, /*friend_number=*/1);
    tunnel->set_state(Tunnel::State::Connecting);
    tunnel->set_on_close([this]() { manager->remove_tunnel(77); });
    manager->add_tunnel(77, tunnel);

    auto frame = ProtocolFrame::make_tunnel_error(77, /*error_code=*/9, "upstream failed");
    manager->route_frame(frame);

    EXPECT_FALSE(manager->has_tunnel(77));
}

TEST_F(TunnelManagerTest, FrameRouting_HandlePingPong) {
    // Ping/Pong have tunnel_id = 0, should be handled by manager itself
    ProtocolFrame ping = ProtocolFrame::make_ping();
    ProtocolFrame pong = ProtocolFrame::make_pong();

    // Set up a send handler for pong responses
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    // Should not crash, even with no tunnels
    EXPECT_NO_THROW(manager->route_frame(ping));
    EXPECT_NO_THROW(manager->route_frame(pong));
}

// ============================================================================
// 5. BackpressureTracking - test buffer level monitoring
// ============================================================================

TEST_F(TunnelManagerTest, BackpressureTracking_ZeroWhenEmpty) {
    EXPECT_EQ(manager->total_buffer_level(), 0u);
}

TEST_F(TunnelManagerTest, BackpressureTracking_NoBackpressureWhenBelowThreshold) {
    manager->set_backpressure_threshold(1024);

    manager->add_tunnel(1, create_test_tunnel(1));
    manager->add_tunnel(2, create_test_tunnel(2));

    // Tunnels with no data in flight should not trigger backpressure
    EXPECT_LT(manager->total_buffer_level(), manager->backpressure_threshold());
}

// ============================================================================
// 6. CreateTunnel - test high-level tunnel creation
// ============================================================================

TEST_F(TunnelManagerTest, CreateTunnel_ReturnsValidId) {
    // Set up send handler so create_tunnel can send TUNNEL_OPEN
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    auto id = manager->create_tunnel("localhost", 8080);
    EXPECT_GT(id, 0u);
    // Note: create_tunnel just allocates an ID and sends TUNNEL_OPEN
    // It doesn't add a tunnel to the manager until the remote accepts
}

TEST_F(TunnelManagerTest, CreateTunnel_MultipleCreations) {
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    auto id1 = manager->create_tunnel("host1.example.com", 80);
    auto id2 = manager->create_tunnel("host2.example.com", 443);
    auto id3 = manager->create_tunnel("192.168.1.1", 22);

    EXPECT_NE(id1, id2);
    EXPECT_NE(id2, id3);
    EXPECT_NE(id1, id3);
}

TEST_F(TunnelManagerTest, CreateTunnel_FailsWithoutSendHandler) {
    // Without a send handler, create_tunnel should return 0
    auto id = manager->create_tunnel("localhost", 8080);
    EXPECT_EQ(id, 0u);
}

// ============================================================================
// 7. EnumerateTunnels - test tunnel enumeration
// ============================================================================

TEST_F(TunnelManagerTest, EnumerateTunnels_EmptyManager) {
    std::vector<uint16_t> ids;
    manager->for_each_tunnel([&ids](uint16_t id, Tunnel*) { ids.push_back(id); });
    EXPECT_TRUE(ids.empty());
}

TEST_F(TunnelManagerTest, EnumerateTunnels_EnumeratesAll) {
    manager->add_tunnel(1, create_test_tunnel(1));
    manager->add_tunnel(2, create_test_tunnel(2));
    manager->add_tunnel(3, create_test_tunnel(3));

    std::vector<uint16_t> ids;
    manager->for_each_tunnel([&ids](uint16_t id, Tunnel*) { ids.push_back(id); });

    EXPECT_EQ(ids.size(), 3u);
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 1) != ids.end());
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 2) != ids.end());
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 3) != ids.end());
}

TEST_F(TunnelManagerTest, EnumerateTunnels_GetActiveTunnelIds) {
    manager->add_tunnel(10, create_test_tunnel(10));
    manager->add_tunnel(20, create_test_tunnel(20));

    auto ids = manager->get_tunnel_ids();
    EXPECT_EQ(ids.size(), 2u);
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 10) != ids.end());
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 20) != ids.end());
}

// ============================================================================
// 8. Callbacks - test tunnel close callbacks
// ============================================================================

TEST_F(TunnelManagerTest, Callbacks_OnTunnelClosed) {
    std::atomic<uint16_t> closed_id{0};
    manager->set_on_tunnel_closed([&closed_id](uint16_t id) { closed_id = id; });

    manager->add_tunnel(42, create_test_tunnel(42));
    manager->remove_tunnel(42);

    // Give async operations time to complete
    io_ctx.poll();

    EXPECT_EQ(closed_id.load(), 42u);
}

TEST_F(TunnelManagerTest, Callbacks_OnTunnelCreated) {
    std::atomic<uint16_t> created_id{0};
    manager->set_on_tunnel_created([&created_id](uint16_t id) { created_id = id; });

    manager->add_tunnel(42, create_test_tunnel(42));

    // Give async operations time to complete
    io_ctx.poll();

    EXPECT_EQ(created_id.load(), 42u);
}

// ============================================================================
// 9. ThreadSafety - test concurrent access
// ============================================================================

TEST_F(TunnelManagerTest, ThreadSafety_ConcurrentTunnelAddRemove) {
    constexpr int num_threads = 4;
    constexpr int tunnels_per_thread = 100;

    manager->set_max_tunnels(num_threads * tunnels_per_thread);

    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < tunnels_per_thread; ++i) {
                uint16_t id = static_cast<uint16_t>(t * tunnels_per_thread + i + 1);
                manager->add_tunnel(id, create_test_tunnel(id));
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(manager->tunnel_count(), static_cast<size_t>(num_threads * tunnels_per_thread));

    // Now remove them concurrently
    threads.clear();
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < tunnels_per_thread; ++i) {
                uint16_t id = static_cast<uint16_t>(t * tunnels_per_thread + i + 1);
                manager->remove_tunnel(id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(manager->tunnel_count(), 0u);
}

TEST_F(TunnelManagerTest, ThreadSafety_ConcurrentFrameRouting) {
    // Add some tunnels
    for (int i = 1; i <= 10; ++i) {
        manager->add_tunnel(static_cast<uint16_t>(i), create_test_tunnel(static_cast<uint16_t>(i)));
    }

    std::vector<std::thread> threads;
    std::atomic<int> frames_routed{0};

    std::array<uint8_t, 2> data = {0x01, 0x02};

    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([this, &frames_routed, &data]() {
            for (int i = 0; i < 100; ++i) {
                uint16_t tunnel_id = static_cast<uint16_t>((i % 10) + 1);
                ProtocolFrame frame = ProtocolFrame::make_tunnel_data(tunnel_id, make_span(data));
                manager->route_frame(frame);
                frames_routed++;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(frames_routed.load(), 400);
}

// ============================================================================
// 10. TunnelOpenHandling - test handling of incoming TUNNEL_OPEN frames
// ============================================================================

TEST_F(TunnelManagerTest, TunnelOpenHandling_AcceptsIncomingOpen) {
    std::atomic<uint16_t> created_id{0};
    manager->set_on_tunnel_created([&created_id](uint16_t id) { created_id = id; });

    ProtocolFrame open_frame = ProtocolFrame::make_tunnel_open(100, "example.com", 443);

    bool accepted = manager->handle_incoming_open(open_frame);
    EXPECT_TRUE(accepted);

    // The ID should now be marked as in use (not as a tunnel)
    EXPECT_FALSE(manager->has_tunnel(100));  // handle_incoming_open just reserves the ID

    // Give async operations time to complete
    io_ctx.poll();

    EXPECT_EQ(created_id.load(), 100u);
}

TEST_F(TunnelManagerTest, TunnelOpenHandling_RejectsDuplicateTunnelId) {
    // Pre-create a tunnel with ID 100
    manager->add_tunnel(100, create_test_tunnel(100));

    // Set up send handler for error response
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    ProtocolFrame open_frame = ProtocolFrame::make_tunnel_open(100, "example.com", 443);
    bool accepted = manager->handle_incoming_open(open_frame);

    EXPECT_FALSE(accepted);
    EXPECT_EQ(manager->tunnel_count(), 1u);  // Only the original tunnel
}

TEST_F(TunnelManagerTest, TunnelOpenHandling_RespectsMaxTunnels) {
    manager->set_max_tunnels(2);

    // Create two tunnels (at limit)
    manager->add_tunnel(1, create_test_tunnel(1));
    manager->add_tunnel(2, create_test_tunnel(2));

    // Set up send handler for error response
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    ProtocolFrame open_frame = ProtocolFrame::make_tunnel_open(3, "example.com", 443);
    bool accepted = manager->handle_incoming_open(open_frame);

    EXPECT_FALSE(accepted);
    EXPECT_EQ(manager->tunnel_count(), 2u);
}

// ============================================================================
// 11. Statistics - test manager statistics
// ============================================================================

TEST_F(TunnelManagerTest, Statistics_TracksTotalBytes) {
    // Initially zero
    EXPECT_EQ(manager->total_bytes_sent(), 0u);
    EXPECT_EQ(manager->total_bytes_received(), 0u);

    // Simulate some activity
    manager->record_bytes_sent(100);
    manager->record_bytes_sent(200);
    manager->record_bytes_received(150);

    EXPECT_EQ(manager->total_bytes_sent(), 300u);
    EXPECT_EQ(manager->total_bytes_received(), 150u);
}

TEST_F(TunnelManagerTest, Statistics_TracksFrameCounts) {
    EXPECT_EQ(manager->frames_sent(), 0u);
    EXPECT_EQ(manager->frames_received(), 0u);

    manager->record_frame_sent();
    manager->record_frame_sent();
    manager->record_frame_received();

    EXPECT_EQ(manager->frames_sent(), 2u);
    EXPECT_EQ(manager->frames_received(), 1u);
}

// ============================================================================
// 12. SendFrame - test sending frames through the manager
// ============================================================================

TEST_F(TunnelManagerTest, SendFrame_QueuesFrameForSending) {
    std::vector<std::vector<uint8_t>> sent_data;
    manager->set_send_handler([&sent_data](const std::vector<uint8_t>& data) {
        sent_data.push_back(data);
        return SendOutcome::Sent;
    });

    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_TRUE(sent);
    EXPECT_EQ(sent_data.size(), 1u);
}

TEST_F(TunnelManagerTest, SendFrame_HandlesSendFailure) {
    // New semantics (2026-05-28): send_frame parks frames that the underlying
    // handler rejects with backpressure (toxcore SENDQ-full) and retries them
    // on a drain timer. The handler returning false therefore reports "queued
    // for retry" (true), not "dropped" (false). Dropping only happens when the
    // parked queue hits its cap.
    int call_count = 0;
    manager->set_send_handler([&call_count](const std::vector<uint8_t>&) {
        ++call_count;
        return SendOutcome::SendqFull;
    });

    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_TRUE(sent) << "single-frame backpressure should park, not drop";
    EXPECT_EQ(call_count, 1) << "handler should be tried exactly once before parking";
}

TEST_F(TunnelManagerTest, SendFrame_FailsWithoutHandler) {
    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_FALSE(sent);
}

// Regression test for the v0.4.5 SENDQ-loss bug: when the underlying send
// handler reports backpressure for several frames in a row, send_frame must
// park them in FIFO order and the drain timer must eventually deliver them
// (in order) once the handler starts succeeding. The timer fires on
// `io_ctx`, so the test polls the io_context until the queue is flushed.
//
// Uses a shared_ptr<TunnelManager> instance directly (rather than the
// fixture's unique_ptr) because the drain timer's async_wait handler
// captures `weak_from_this()` — and that returns null unless the manager
// is held by a shared_ptr. The fixture instance is not used here.
TEST_F(TunnelManagerTest, SendFrame_BackpressuredFramesDrainInOrder) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    // The handler refuses the first 2 attempts on the first frame, then
    // accepts everything. Records every wire payload it actually accepted.
    std::vector<std::vector<uint8_t>> accepted;
    std::atomic<int> refusals_remaining{4};  // 4 = 2 send_frame calls × 2 retries
    shared_manager->set_send_handler(
        [&accepted, &refusals_remaining](const std::vector<uint8_t>& data) {
            if (refusals_remaining.fetch_sub(1, std::memory_order_relaxed) > 0) {
                return SendOutcome::SendqFull;
            }
            accepted.push_back(data);
            return SendOutcome::Sent;
        });

    // Send three frames; the first two get parked, the third stays queued
    // behind them (FIFO).
    std::array<uint8_t, 3> data_a = {0x01, 0x02, 0x03};
    std::array<uint8_t, 3> data_b = {0x04, 0x05, 0x06};
    std::array<uint8_t, 3> data_c = {0x07, 0x08, 0x09};
    ASSERT_TRUE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(1, make_span(data_a))));
    ASSERT_TRUE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(2, make_span(data_b))));
    ASSERT_TRUE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(3, make_span(data_c))));

    // Pump io_ctx until the drain timer has fired enough times to deliver
    // all three frames, or we time out. The retry delay is 20ms; allowing
    // 3 seconds of wall time leaves plenty of headroom on slow CI runners.
    //
    // Use `poll_one` + `restart` rather than `run_for(30ms) + restart`: on
    // asio's Windows IOCP backend `run_for + restart` in a tight loop was
    // observed to hang (windows-x86_64 CI runner stalled >35 min on the
    // unit-tests step). `poll_one` is non-blocking — it dispatches at most
    // one ready handler and returns — and the explicit `sleep_for` gives
    // the steady_timer a chance to expire between polls. The `restart()`
    // call is still needed because `poll_one()` puts the io_context into
    // the stopped state when no work is ready.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (accepted.size() < 3 && std::chrono::steady_clock::now() < deadline) {
        io_ctx.poll_one();
        io_ctx.restart();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    ASSERT_EQ(accepted.size(), 3u) << "all three frames should drain within timeout";
    // FIFO: the per-tunnel id is encoded at offset 1 in the wire layout, so
    // the simplest order check is to grab byte 1 of each accepted payload.
    EXPECT_EQ(accepted[0][1], 0u);  // tunnel_id high byte
    EXPECT_EQ(accepted[0][2], 1u);  // first send: tunnel_id 1
    EXPECT_EQ(accepted[1][2], 2u);  // second send: tunnel_id 2
    EXPECT_EQ(accepted[2][2], 3u);  // third send: tunnel_id 3
}

// ============================================================================
// 13. PingPongHandling - test ping/pong handling
// ============================================================================

TEST_F(TunnelManagerTest, PingPongHandling_PingTriggersPong) {
    std::atomic<bool> pong_sent{false};
    manager->set_send_handler([&pong_sent](const std::vector<uint8_t>& data) {
        // Check if this is a PONG frame
        if (data.size() >= 1 && data[0] == static_cast<uint8_t>(FrameType::PONG)) {
            pong_sent = true;
        }
        return SendOutcome::Sent;
    });

    ProtocolFrame ping = ProtocolFrame::make_ping();
    manager->route_frame(ping);

    EXPECT_TRUE(pong_sent);
}

TEST_F(TunnelManagerTest, PingPongHandling_PongIsHandled) {
    manager->set_send_handler([](const std::vector<uint8_t>&) { return SendOutcome::Sent; });

    ProtocolFrame pong = ProtocolFrame::make_pong();
    // Should not crash
    EXPECT_NO_THROW(manager->route_frame(pong));

    // Frame should be counted
    EXPECT_EQ(manager->frames_received(), 1u);
}

// ============================================================================
// 14. CloseAllLocal — "no further send is authorised" contract
//
// close_all_local() tears down a manager whose peer has already moved on to a
// new session. Tunnel ids are recycled per friend, so ANY frame this session
// emits can hit the winner's identically-numbered tunnel. Local resources
// (target TCP sockets, tunnel ids, on_tunnel_closed bookkeeping) are still
// released.
//
// Note what is NOT claimed. The goal was once "zero outbound frames", and these
// tests were written against it. Teardown cannot deliver that: reaching it
// meant waiting for in-flight sends, and that wait deadlocked against
// coalesce_mutex_. What holds now is that no send can be AUTHORISED once the
// gate closes; a send authorised microseconds earlier may still land. See
// TunnelManager::close_all_local() for the full residual.
// ============================================================================

// ---------------------------------------------------------------------------
// Shared io_context pump helpers.
//
// These used to exist twice — here (file-local, sleep-driven) and as fixture
// methods in tunnel_coalesce_test.cpp (no-sleep). One implementation now, with
// external linkage, declared where the other translation unit needs it; both
// files link into the same unit_tests binary. They live in this file rather
// than a new header because tests/CMakeLists.txt enumerates its sources
// explicitly and adding files to it is out of scope for this change.
//
// `poll` (not `run_for`) because `run_for + restart` in a tight loop was
// observed to hang on asio's Windows IOCP backend.
//
// NEVER sleep in the pump loop — that is the surviving implementation's key
// property. std::this_thread::sleep_for(1ms) costs 1.1 ms on Linux and 1.4 ms
// on macOS, but 27-69 ms on Windows (default system timer resolution ~15.6 ms,
// worse in a VM). A sleep-driven loop with a 20 ms budget therefore got ~20
// iterations on Unix but ONE on Windows, which is exactly why the coalesce
// tests were flaky there and passed in isolation. yield() keeps the loop
// responsive on every platform, and poll() drains every ready handler per turn
// rather than one.
// ---------------------------------------------------------------------------
namespace toxtunnel::test_support {

/// Pump `io_ctx` until `pred` holds or `deadline` elapses.
bool PumpUntil(asio::io_context& io_ctx, const std::function<bool()>& pred,
               std::chrono::milliseconds deadline) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < until) {
        if (pred()) {
            return true;
        }
        if (io_ctx.poll() == 0) {
            std::this_thread::yield();
        }
        io_ctx.restart();
    }
    io_ctx.poll();
    io_ctx.restart();
    return pred();
}

/// Pump `io_ctx` for `duration`, unconditionally. Used to prove that something
/// does NOT happen (no PING, no drain) over a window of several timer ticks.
void PumpFor(asio::io_context& io_ctx, std::chrono::milliseconds duration) {
    const auto until = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < until) {
        if (io_ctx.poll() == 0) {
            std::this_thread::yield();
        }
        io_ctx.restart();
    }
    io_ctx.poll();
    io_ctx.restart();
}

}  // namespace toxtunnel::test_support

namespace {

using toxtunnel::test_support::PumpFor;

/// Thin wrapper so the many call sites below keep their 2 s default deadline
/// and can pass a bare lambda.
template <typename Pred>
bool PumpUntil(asio::io_context& io_ctx, Pred pred,
               std::chrono::milliseconds deadline = std::chrono::milliseconds(2000)) {
    return toxtunnel::test_support::PumpUntil(io_ctx, std::function<bool()>(std::move(pred)),
                                              deadline);
}

}  // namespace

// The regression this pins: muting used to be done per-tunnel, leaving the
// manager-level retry queue untouched. Frames already parked in
// pending_outbound_ (TUNNEL_CLOSE / OPEN_ACK that hit toxcore SENDQ-full) kept
// their appointment with the drain timer and went out on the wire *after*
// close_all_local() had "silenced" the session.
TEST_F(TunnelManagerTest, CloseAllLocal_DropsParkedFramesInsteadOfDrainingThem) {
    // shared_ptr: the drain timer's handler captures weak_from_this().
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    std::atomic<int> sends{0};
    std::atomic<bool> accept{false};
    shared_manager->set_send_handler([&sends, &accept](const std::vector<uint8_t>&) {
        sends.fetch_add(1, std::memory_order_relaxed);
        return accept.load(std::memory_order_relaxed) ? SendOutcome::Sent : SendOutcome::SendqFull;
    });

    // Park two frames: the first is attempted once (SENDQ-full) and parked, the
    // second queues behind it without an attempt.
    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ASSERT_TRUE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(1, make_span(data))));
    ASSERT_TRUE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(2, make_span(data))));
    ASSERT_EQ(sends.load(), 1) << "second frame should queue behind the parked one";

    // Abandon the session. From here the handler must never be called again,
    // even though the SENDQ is now (as far as the manager knows) drainable.
    shared_manager->close_all_local();
    accept.store(true, std::memory_order_relaxed);
    EXPECT_TRUE(shared_manager->outbound_muted());

    // The drain delay is 20ms; 300ms is ~15 ticks' worth of opportunity.
    PumpFor(io_ctx, std::chrono::milliseconds(300));
    EXPECT_EQ(sends.load(), 1) << "parked frames must be dropped, not drained, after "
                                  "close_all_local()";

    // And nothing new may be admitted either.
    EXPECT_FALSE(shared_manager->send_frame(ProtocolFrame::make_tunnel_data(3, make_span(data))));
    EXPECT_FALSE(shared_manager->queue_outbound_for_retry({0x01, 0x02}));
    PumpFor(io_ctx, std::chrono::milliseconds(100));
    EXPECT_EQ(sends.load(), 1);
}

// A PING emitted after the session was abandoned is exactly the "closes the
// winner's tunnel" hazard in miniature — it is addressed at a peer that is now
// talking to a different manager. close_all_local() must stop the keepalive
// chain, not merely mute one tunnel at a time.
TEST_F(TunnelManagerTest, CloseAllLocal_StopsKeepalivePings) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    std::atomic<int> pings{0};
    shared_manager->set_send_handler([&pings](const std::vector<uint8_t>& wire) {
        if (!wire.empty() && wire[0] == static_cast<uint8_t>(FrameType::PING)) {
            pings.fetch_add(1, std::memory_order_relaxed);
        }
        return SendOutcome::Sent;
    });

    // Long timeout so the peer is never declared dead; we only want the pings.
    shared_manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    ASSERT_TRUE(PumpUntil(
        io_ctx, [&pings] { return pings.load() >= 1; }, std::chrono::milliseconds(5000)))
        << "keepalive should emit at least one PING before we abandon the session";

    shared_manager->close_all_local();
    const int at_abandon = pings.load();

    // Two full intervals of opportunity.
    PumpFor(io_ctx, std::chrono::milliseconds(2400));
    EXPECT_EQ(pings.load(), at_abandon) << "an abandoned manager must not keep pinging";
}

// The other half of the contract: local state really is released.
TEST_F(TunnelManagerTest, CloseAllLocal_ClosesTunnelsAndReleasesIds) {
    auto t1 = create_test_tunnel(1);
    auto t2 = create_test_tunnel(2);
    ASSERT_TRUE(manager->add_tunnel(1, t1));
    ASSERT_TRUE(manager->add_tunnel(2, t2));

    std::atomic<int> closed_notifications{0};
    manager->set_on_tunnel_closed(
        [&closed_notifications](uint16_t) { closed_notifications.fetch_add(1); });

    manager->close_all_local();

    EXPECT_EQ(manager->tunnel_count(), 0u);
    EXPECT_EQ(t1->close_count(), 1);
    EXPECT_EQ(t2->close_count(), 1);
    // Ids back in the pool: allocation restarts at 1.
    EXPECT_EQ(manager->allocate_tunnel_id().value(), 1u);
    // on_tunnel_closed is posted, not called inline (H-01: no re-entrancy under
    // the manager lock).
    EXPECT_TRUE(PumpUntil(io_ctx, [&closed_notifications] {
        return closed_notifications.load() == 2;
    })) << "every closed tunnel must still be reported to the owner";
}

// A tunnel caught mid-half-close (Disconnecting) is where the old
// implementation leaked: it delegated to close_all(), whose plain close() is a
// documented no-op in that state, so the target TCP fd was never released and
// the tunnel never reached a terminal state. close_all_local() must force it
// down without itself emitting a teardown frame. That is what the frame count
// below checks — teardown authorises no send of its own. It is NOT the broader
// "nothing of this session reaches the wire": no concurrent sender exists here,
// and a send authorised just before the gate closed would still land (see
// TunnelManager::close_all_local()).
TEST_F(TunnelManagerTest, CloseAllLocal_ForceClosesHalfClosedTunnelWithoutEmitting) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    auto connected = std::make_shared<TunnelImpl>(io_ctx, /*tunnel_id=*/1, /*friend_number=*/0);
    auto half_closed = std::make_shared<TunnelImpl>(io_ctx, /*tunnel_id=*/2, /*friend_number=*/0);

    std::atomic<int> tox_frames{0};
    auto counting_send = [&tox_frames](std::span<const uint8_t>) {
        tox_frames.fetch_add(1, std::memory_order_relaxed);
        return true;
    };
    connected->set_on_send_to_tox(counting_send);
    half_closed->set_on_send_to_tox(counting_send);
    connected->set_state(Tunnel::State::Connected);
    half_closed->set_state(Tunnel::State::Disconnecting);

    ASSERT_TRUE(shared_manager->add_tunnel(1, connected));
    ASSERT_TRUE(shared_manager->add_tunnel(2, half_closed));

    shared_manager->close_all_local();

    EXPECT_EQ(connected->state(), Tunnel::State::Closed);
    EXPECT_EQ(half_closed->state(), Tunnel::State::Closed)
        << "a Disconnecting tunnel must be forced down, not left pinning its fd";
    EXPECT_EQ(tox_frames.load(), 0)
        << "teardown itself must not emit TUNNEL_CLOSE / TUNNEL_ERROR for an abandoned session";
    EXPECT_EQ(shared_manager->tunnel_count(), 0u);
}

// ============================================================================
// 15. Keepalive generation gate
//
// disable_keepalive() used to be cancel-only. asio's cancel() cannot stop a
// handler that is already dispatched, and that handler unconditionally sent a
// PING and then called schedule_keepalive_tick(), which set keepalive_active_
// back to true — resurrecting a chain that had just been stopped.
// ============================================================================

// Deterministic reproduction: disable from *inside* the send handler, i.e. at
// the exact point the old code was about to re-arm. Without the epoch gate the
// tick re-arms and keeps pinging forever.
TEST_F(TunnelManagerTest, DisableKeepalive_FromInsideSendHandler_DoesNotReArm) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    std::atomic<int> pings{0};
    shared_manager->set_send_handler([&pings, weak = std::weak_ptr<TunnelManager>(shared_manager)](
                                         const std::vector<uint8_t>& wire) {
        if (!wire.empty() && wire[0] == static_cast<uint8_t>(FrameType::PING)) {
            pings.fetch_add(1, std::memory_order_relaxed);
            // Runs on the io thread, synchronously inside the keepalive
            // tick, one statement before the old code's re-arm.
            if (auto self = weak.lock()) {
                self->disable_keepalive();
            }
        }
        return SendOutcome::Sent;
    });

    shared_manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    ASSERT_TRUE(
        PumpUntil(io_ctx, [&pings] { return pings.load() >= 1; }, std::chrono::milliseconds(5000)));

    // Three further intervals of opportunity to re-arm.
    PumpFor(io_ctx, std::chrono::milliseconds(3200));
    EXPECT_EQ(pings.load(), 1) << "a disabled keepalive tick must not re-arm itself";
}

// The plain case: disable between ticks stays disabled.
TEST_F(TunnelManagerTest, DisableKeepalive_StopsFurtherPings) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    std::atomic<int> pings{0};
    shared_manager->set_send_handler([&pings](const std::vector<uint8_t>& wire) {
        if (!wire.empty() && wire[0] == static_cast<uint8_t>(FrameType::PING)) {
            pings.fetch_add(1, std::memory_order_relaxed);
        }
        return SendOutcome::Sent;
    });

    shared_manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    ASSERT_TRUE(
        PumpUntil(io_ctx, [&pings] { return pings.load() >= 1; }, std::chrono::milliseconds(5000)));

    shared_manager->disable_keepalive();
    const int at_disable = pings.load();
    PumpFor(io_ctx, std::chrono::milliseconds(2400));
    EXPECT_EQ(pings.load(), at_disable);
}

// ============================================================================
// 15b. Timer state transitions are atomic (H-1, 3rd review)
//
// The epoch gate alone was not enough. The tick handler used to *check* the
// generation and then call an unconditional schedule_*_tick(), two separate
// steps. A handler preempted between them — while disable_*() + enable_*() ran,
// which is exactly the resume pause/resurrect sequence — came back and armed
// the timer for its own retired generation. `expires_after` cancels the pending
// wait, so the freshly installed chain died with operation_aborted and the
// stale wait was refused at the entry gate: ZERO live chains, silently.
//
// The interleaving cannot be produced from outside (the preemption point is
// inside an asio completion handler), so these tests drive the transition
// through the same function the handler calls: rearm_*_after_tick(). That
// function is exactly "everything the handler does from its last generation
// check through the arm" — the span the preemption falls inside. Before the
// fix that span was an unconditional schedule_*_tick(); calling it with a
// retired epoch reproduces the bug and both tests below fail (verified by
// temporarily restoring the old shape).
// ============================================================================

TEST_F(TunnelManagerTest, StaleKeepaliveRearm_DoesNotClobberTheLiveChain) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    std::atomic<int> pings{0};
    shared_manager->set_send_handler([&pings](const std::vector<uint8_t>& wire) {
        if (!wire.empty() && wire[0] == static_cast<uint8_t>(FrameType::PING)) {
            pings.fetch_add(1, std::memory_order_relaxed);
        }
        return SendOutcome::Sent;
    });

    // Generation 1 is armed; imagine its tick has just been dispatched and has
    // passed its last epoch check.
    shared_manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    const std::uint64_t stale_epoch = shared_manager->keepalive_epoch();

    // The pause/resurrect sequence runs while that tick is suspended.
    shared_manager->disable_keepalive();
    shared_manager->enable_keepalive(/*interval_seconds=*/1, /*timeout_seconds=*/30);
    ASSERT_NE(shared_manager->keepalive_epoch(), stale_epoch);

    // The suspended tick now resumes and performs its re-arm.
    shared_manager->rearm_keepalive_after_tick(stale_epoch);

    // The live chain must be untouched. Before the fix this hung at zero: the
    // stale re-arm had cancelled generation 2's wait and installed its own,
    // which the entry gate then refused.
    EXPECT_TRUE(PumpUntil(
        io_ctx, [&pings] { return pings.load() >= 1; }, std::chrono::milliseconds(5000)))
        << "a retired tick's re-arm must not cancel the live keepalive chain";
}

TEST_F(TunnelManagerTest, StaleReaperRearm_DoesNotClobberTheLiveChain) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    // A tunnel the maintenance scan is allowed to reap: any non-Connecting
    // TunnelImpl idle past the timeout qualifies.
    auto victim = std::make_shared<TunnelImpl>(io_ctx, /*tunnel_id=*/1, /*friend_number=*/0);
    victim->set_on_send_to_tox([](std::span<const uint8_t>) { return true; });
    victim->set_state(Tunnel::State::Connected);
    ASSERT_TRUE(shared_manager->add_tunnel(1, victim));

    shared_manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/1);
    const std::uint64_t stale_epoch = shared_manager->reaper_epoch();

    shared_manager->disable_reaper();
    shared_manager->enable_reaper(/*idle_timeout_seconds=*/1, /*tick_seconds=*/1);
    ASSERT_NE(shared_manager->reaper_epoch(), stale_epoch);

    shared_manager->rearm_reaper_after_tick(stale_epoch);

    // The surviving chain must still tick and reap. Before the fix the stale
    // re-arm cancelled it and nothing ever ran the scan.
    EXPECT_TRUE(PumpUntil(
        io_ctx, [&shared_manager] { return shared_manager->tunnel_count() == 0; },
        std::chrono::milliseconds(6000)))
        << "a retired tick's re-arm must not cancel the live maintenance chain";
}

// ============================================================================
// 15c. Outbound send gate (H-2, 3rd review)
//
// A mute latch alone could not stop a stale frame: every send path copies its
// callback out from under a lock and invokes it AFTER the unlock (it must — a
// Tox send re-enters the manager, and holding a lock across it deadlocks;
// H-01). A sender could therefore copy the callback *after* the latch was set
// and deliver its frame, and one stale TUNNEL_CLOSE is enough to close the
// winner's identically-numbered tunnel (ids are recycled per friend).
//
// The fix is a snapshot: gate-test and callback-copy in one critical section.
// That bounds snapshot ACQUISITION only. The stronger form — close_all_local()
// blocking until every pre-gate snapshot was released — was withdrawn because
// it deadlocked against coalesce_mutex_, so a send authorised just before the
// gate closed may still land. These tests therefore pin the post-return state
// (no NEW send can be authorised), not the absence of a running one. See
// TunnelManager::close_all_local() for the full residual.
// ============================================================================

namespace {

/// A send callback that parks inside itself until the test releases it, so the
/// test can hold a send running across close_all_local().
struct BlockingSend {
    std::atomic<bool> entered{false};  ///< Set once the callback has been entered.
    std::atomic<bool> release{false};  ///< Test sets this to let the callback finish.
    std::atomic<int> invocations{0};

    void run() {
        invocations.fetch_add(1, std::memory_order_relaxed);
        entered.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }

    void wait_until_entered() {
        while (!entered.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }
};

}  // namespace

TEST_F(TunnelManagerTest, CloseAllLocal_FencesAnInFlightManagerSend) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    BlockingSend blocking;
    shared_manager->set_send_handler([&blocking](const std::vector<uint8_t>&) {
        blocking.run();
        return SendOutcome::Sent;
    });

    // A sender that is *already inside* the handler — i.e. one that copied the
    // handler before the session was abandoned.
    std::thread sender(
        [&shared_manager] { shared_manager->send_frame(ProtocolFrame::make_ping()); });
    blocking.wait_until_entered();

    // Let it finish only after close_all_local() has had time to observe it.
    std::thread releaser([&blocking] {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        blocking.release.store(true, std::memory_order_release);
    });

    shared_manager->close_all_local();

    // The contract is deliberately NOT "nothing is in flight on return".
    // Waiting for in-flight sends deadlocked (see close_all_local()'s docs).
    // What IS guaranteed — and is what protects the winning session — is that
    // no send can acquire a handler SNAPSHOT once the gate is closed. Note the
    // assertion below is about the post-return state, not about this
    // already-entered send: a pre-gate snapshot may still land, so counting
    // invocations across close_all_local() would prove nothing.
    releaser.join();
    sender.join();

    // No new post-gate send can be authorised.
    const int baseline_invocations = blocking.invocations.load();
    EXPECT_FALSE(shared_manager->send_frame(ProtocolFrame::make_ping()));
    PumpFor(io_ctx, std::chrono::milliseconds(100));
    EXPECT_EQ(blocking.invocations.load(), baseline_invocations);
}

TEST_F(TunnelManagerTest, CloseAllLocal_FencesAnInFlightTunnelSend) {
    auto shared_manager = std::make_shared<TunnelManager>(io_ctx);

    // The per-tunnel path bypasses the manager entirely (Tunnel::on_send_to_tox
    // goes straight into ToxAdapter), so the manager's own latch cannot cover
    // it — this is the leak the review measured as "one frame per concurrently
    // sending tunnel".
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, /*tunnel_id=*/1, /*friend_number=*/0);
    BlockingSend blocking;
    tunnel->set_on_send_to_tox([&blocking](std::span<const uint8_t>) {
        blocking.run();
        return true;
    });
    tunnel->set_state(Tunnel::State::Connected);
    ASSERT_TRUE(shared_manager->add_tunnel(1, tunnel));

    std::thread sender([&tunnel] { tunnel->send_error(3, "in flight"); });
    blocking.wait_until_entered();

    std::thread releaser([&blocking] {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        blocking.release.store(true, std::memory_order_release);
    });

    shared_manager->close_all_local();

    // As above: sends authorised before the gate closed are NOT waited for
    // (that deadlocks). The guarantee under test is that the per-tunnel gate is
    // closed afterwards, so the send path that bypasses the manager entirely
    // cannot acquire another callback snapshot.

    releaser.join();
    sender.join();

    // The gate holds afterwards: a send that starts from here can no longer
    // acquire a callback, so it never reaches the peer. (A send that acquired
    // one before the gate closed is not covered — that is the documented
    // residual, and the count is sampled after the running one has finished so
    // it cannot be confused with it.)
    const int baseline_invocations = blocking.invocations.load();
    EXPECT_TRUE(tunnel->outbound_gate_closed());
    tunnel->send_error(3, "after the fence");
    EXPECT_EQ(blocking.invocations.load(), baseline_invocations)
        << "a send begun after the outbound gate closed must not reach the peer";
}

// Regression: a send callback that abandons its own session must not deadlock.
//
// The coalesced data path invokes the Tox send callback while holding the
// tunnel's `coalesce_mutex_`. If that callback tears the session down —
// close_all_local() -> force_close() -> flush_pending_writes() — the flush
// re-takes that same non-recursive mutex on the same thread and the process
// wedges. force_close() takes its local-abandon path (no flush) once the
// outbound gate is closed, which is exactly the state close_all_local()
// establishes before it force-closes anything.
//
// This test hangs forever on a regression, so it runs the teardown on its own
// thread and fails on a deadline rather than taking the suite down with it.
TEST_F(TunnelManagerTest, CloseAllLocalFromInsideSendCallbackDoesNotDeadlock) {
    // Everything the victim thread touches lives on the heap behind one
    // shared_ptr, and the thread holds its own copy. That matters only on
    // failure: a deadlocked thread cannot be joined, and detaching it while it
    // still references stack objects would turn a clean test failure into
    // undefined behaviour when this frame unwinds. On timeout we leak `state`
    // into a function-local static instead, so the wedged thread keeps a valid
    // manager, tunnel and io_context for as long as the process lives.
    struct Fixture {
        asio::io_context io;
        std::shared_ptr<TunnelManager> manager{std::make_shared<TunnelManager>(io)};
        std::shared_ptr<TunnelImpl> tunnel{
            std::make_shared<TunnelImpl>(io, /*tunnel_id=*/1, /*friend_number=*/0)};
        std::atomic<bool> torn_down{false};
        std::promise<void> done;
    };
    auto state = std::make_shared<Fixture>();

    // max_delay_us == 0 emits inline, so the callback below runs underneath
    // coalesce_mutex_ — the whole point of the reproduction.
    state->tunnel->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    state->tunnel->set_on_send_to_tox([state](std::span<const uint8_t>) {
        // Abandon the session from inside the send. No production caller does
        // this today: close_all_local()'s only production call site is the
        // resurrection-loser path (tunnel_server.cpp, resume), which runs on
        // the inbound strand, EXTERNAL to any send callback. The re-entrant
        // shape is constructed deliberately here to prove the guard holds if a
        // future caller ever does take that route.
        if (!state->torn_down.exchange(true)) {
            state->manager->close_all_local();
        }
        return true;
    });
    state->tunnel->set_state(Tunnel::State::Connected);
    ASSERT_TRUE(state->manager->add_tunnel(1, state->tunnel));

    auto done_future = state->done.get_future();
    std::thread victim([state] {
        (void)state->tunnel->send_data_to_tox(std::vector<uint8_t>{1, 2, 3, 4});
        state->done.set_value();
    });

    const auto status = done_future.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready)
        << "send callback -> close_all_local() -> force_close() self-deadlocked on "
           "coalesce_mutex_";
    if (status == std::future_status::ready) {
        victim.join();
        EXPECT_TRUE(state->torn_down.load());
        EXPECT_TRUE(state->manager->outbound_muted());
    } else {
        // Deadlocked: joining would hang the suite too. Keep the thread's state
        // alive forever and let the remaining tests run.
        static std::vector<std::shared_ptr<Fixture>> leaked_on_deadlock;
        leaked_on_deadlock.push_back(state);
        victim.detach();
    }
}

// ============================================================================
// Friend pre-seeding from the access rules
//
// The server's only path into the Tox friend list used to be
// on_friend_request(), which refuses any key not already in rules.yaml. A client
// that connected before its key was added therefore deadlocked permanently: it
// had already persisted the server, so toxcore never re-sent the friend request.
// preseed_friends_from_rules() closes the hole; friend_keys_to_preseed() is its
// pure set-difference core.
// ============================================================================

namespace {

// Valid 64-char hex public keys (content is arbitrary, shape is what matters).
constexpr const char* kPkA = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
constexpr const char* kPkB = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";
constexpr const char* kPkC = "AAAABBBBCCCCDDDDEEEEFFFF00001111AAAABBBBCCCCDDDDEEEEFFFF00002222";

}  // namespace

TEST(FriendPreseedTest, AddsEveryRuleKeyWhenFriendListIsEmpty) {
    // First-ever startup: nothing in tox_save.dat yet.
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed({kPkA, kPkB}, {});
    ASSERT_EQ(missing.size(), 2u);
    EXPECT_THAT(missing, ::testing::UnorderedElementsAre(kPkA, kPkB));
}

TEST(FriendPreseedTest, SkipsKeysAlreadyInTheFriendList) {
    // Idempotence: this is what makes it safe to call on every reload, and what
    // keeps add_friend_norequest() (which fsyncs tox_save.dat) from running and
    // logging a duplicate-add failure on every SIGHUP.
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed({kPkA, kPkB}, {kPkA});
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], kPkB);
}

TEST(FriendPreseedTest, NothingToDoWhenEveryRuleKeyIsAlreadyAFriend) {
    EXPECT_TRUE(toxtunnel::app::detail::friend_keys_to_preseed({kPkA, kPkB}, {kPkB, kPkA}).empty());
}

TEST(FriendPreseedTest, OnlyNewlyAddedRuleKeyIsSeededOnReload) {
    // The regression scenario, in the shape reload() sees it: the operator adds
    // the client's key to rules.yaml while the daemon is up. Exactly that key
    // must be handed to add_friend_norequest().
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed({kPkA, kPkB, kPkC}, {kPkA, kPkB});
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], kPkC);
}

TEST(FriendPreseedTest, ComparesKeysCaseInsensitively) {
    // RulesEngine canonicalises to uppercase and tox::bytes_to_hex emits
    // uppercase, but a lowercase key reaching either side must not be mistaken
    // for a new friend and re-added on every reload.
    std::string lower_a(kPkA);
    for (auto& c : lower_a) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    EXPECT_TRUE(toxtunnel::app::detail::friend_keys_to_preseed({lower_a}, {kPkA}).empty());

    // And the emitted key is canonical uppercase, ready for parse_public_key().
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed({lower_a}, {});
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], kPkA);
}

TEST(FriendPreseedTest, DeduplicatesRepeatedRuleKeys) {
    // Two rules for the same friend must not produce two add attempts (the
    // second would fail with "friend request already sent" and log a warning).
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed({kPkA, kPkA, kPkB}, {});
    ASSERT_EQ(missing.size(), 2u);
    EXPECT_THAT(missing, ::testing::UnorderedElementsAre(kPkA, kPkB));
}

TEST(FriendPreseedTest, DropsMalformedKeys) {
    // Nothing here may reach tox_friend_add_norequest(), which reads a fixed
    // 32-byte buffer from the pointer it is given.
    const std::vector<std::string> bad = {
        "",
        "not-hex",
        "0123456789ABCDEF",                                                  // too short
        std::string(kPkA) + "00",                                            // too long
        "ZZ23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",  // bad nibbles
    };
    EXPECT_TRUE(toxtunnel::app::detail::friend_keys_to_preseed(bad, {}).empty());

    // A malformed entry must not suppress the valid ones alongside it.
    std::vector<std::string> mixed = bad;
    mixed.push_back(kPkC);
    auto missing = toxtunnel::app::detail::friend_keys_to_preseed(mixed, {});
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], kPkC);
}
