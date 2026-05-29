#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

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
    int frames_handled_{0};
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
    // 2 seconds of wall time leaves plenty of headroom on slow CI runners.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (accepted.size() < 3 && std::chrono::steady_clock::now() < deadline) {
        io_ctx.run_for(std::chrono::milliseconds(30));
        io_ctx.restart();
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
