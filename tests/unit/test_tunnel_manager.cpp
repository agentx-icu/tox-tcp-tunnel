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
    EXPECT_EQ(manager->allocate_tunnel_id(), 1u);
}

// ============================================================================
// 2. TunnelIdAllocation - test tunnel ID allocation
// ============================================================================

TEST_F(TunnelManagerTest, TunnelIdAllocation_Sequential) {
    auto id1 = manager->allocate_tunnel_id();
    auto id2 = manager->allocate_tunnel_id();
    auto id3 = manager->allocate_tunnel_id();

    EXPECT_EQ(id1, 1u);
    EXPECT_EQ(id2, 2u);
    EXPECT_EQ(id3, 3u);
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_WrapsOnOverflow) {
    // Simulate being near the end of the ID space
    manager->set_next_tunnel_id(65534);

    auto id1 = manager->allocate_tunnel_id();
    auto id2 = manager->allocate_tunnel_id();
    auto id3 = manager->allocate_tunnel_id();

    EXPECT_EQ(id1, 65534u);
    EXPECT_EQ(id2, 65535u);
    EXPECT_EQ(id3, 1u);  // Wraps to 1, skipping 0 (reserved)
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_SkipsZero) {
    manager->set_next_tunnel_id(0);
    auto id = manager->allocate_tunnel_id();
    EXPECT_EQ(id, 1u);
}

TEST_F(TunnelManagerTest, TunnelIdAllocation_SkipsInUseIds) {
    // Allocate and create a tunnel with ID 2
    auto id1 = manager->allocate_tunnel_id();  // 1
    auto id2 = manager->allocate_tunnel_id();  // 2

    // Create tunnel with id2
    auto tunnel = create_test_tunnel(id2);
    manager->add_tunnel(id2, std::move(tunnel));

    // Release id1 so it can be reused
    manager->release_tunnel_id(id1);

    // Next allocation should skip 2 (in use) and find 3
    auto id3 = manager->allocate_tunnel_id();
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
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

    EXPECT_NO_THROW(manager->route_frame(data_frame));
}

TEST_F(TunnelManagerTest, FrameRouting_HandlePingPong) {
    // Ping/Pong have tunnel_id = 0, should be handled by manager itself
    ProtocolFrame ping = ProtocolFrame::make_ping();
    ProtocolFrame pong = ProtocolFrame::make_pong();

    // Set up a send handler for pong responses
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

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
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

    auto id = manager->create_tunnel("localhost", 8080);
    EXPECT_GT(id, 0u);
    // Note: create_tunnel just allocates an ID and sends TUNNEL_OPEN
    // It doesn't add a tunnel to the manager until the remote accepts
}

TEST_F(TunnelManagerTest, CreateTunnel_MultipleCreations) {
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

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
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

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
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

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
        return true;
    });

    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_TRUE(sent);
    EXPECT_EQ(sent_data.size(), 1u);
}

TEST_F(TunnelManagerTest, SendFrame_HandlesSendFailure) {
    manager->set_send_handler([](const std::vector<uint8_t>&) { return false; });

    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_FALSE(sent);
}

TEST_F(TunnelManagerTest, SendFrame_FailsWithoutHandler) {
    std::array<uint8_t, 3> data = {0x01, 0x02, 0x03};
    ProtocolFrame frame = ProtocolFrame::make_tunnel_data(1, make_span(data));
    bool sent = manager->send_frame(frame);

    EXPECT_FALSE(sent);
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
        return true;
    });

    ProtocolFrame ping = ProtocolFrame::make_ping();
    manager->route_frame(ping);

    EXPECT_TRUE(pong_sent);
}

TEST_F(TunnelManagerTest, PingPongHandling_PongIsHandled) {
    manager->set_send_handler([](const std::vector<uint8_t>&) { return true; });

    ProtocolFrame pong = ProtocolFrame::make_pong();
    // Should not crash
    EXPECT_NO_THROW(manager->route_frame(pong));

    // Frame should be counted
    EXPECT_EQ(manager->frames_received(), 1u);
}
