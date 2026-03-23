// Integration tests for TunnelManager + TunnelImpl working together.
//
// These tests simulate client-server tunnel data exchange by wiring two
// TunnelManager instances together via lambda-based mock transport.  Frames
// are serialized on one side, deserialized, and routed into the other
// side's TunnelManager.  An asio::io_context runs on a background thread
// to process posted handlers (e.g. tunnel-created callbacks).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace toxtunnel::integration {
namespace {

// ============================================================================
// Test Fixture
// ============================================================================

class TunnelDataFlowTest : public ::testing::Test {
   protected:
    void SetUp() override {
        // Create io_context and run it on a background thread.
        io_ctx_ = std::make_unique<asio::io_context>();
        work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io_ctx_->get_executor());
        io_thread_ = std::thread([this] { io_ctx_->run(); });

        // Create client and server TunnelManagers.
        client_mgr_ = std::make_unique<tunnel::TunnelManager>(*io_ctx_);
        server_mgr_ = std::make_unique<tunnel::TunnelManager>(*io_ctx_);

        // Wire send handlers: client -> server, server -> client.
        // The send handler receives serialized frame data.
        client_mgr_->set_send_handler([this](const std::vector<uint8_t>& data) -> bool {
            auto frame = tunnel::ProtocolFrame::deserialize(data);
            if (frame) {
                server_mgr_->route_frame(frame.value());
            }
            return frame.has_value();
        });

        server_mgr_->set_send_handler([this](const std::vector<uint8_t>& data) -> bool {
            auto frame = tunnel::ProtocolFrame::deserialize(data);
            if (frame) {
                client_mgr_->route_frame(frame.value());
            }
            return frame.has_value();
        });
    }

    void TearDown() override {
        // Clear tunnel callbacks to prevent reentrant mutex locks during
        // close_all (close -> on_send_to_tox -> mgr->send_frame -> mutex).
        auto clear_callbacks = [](tunnel::TunnelManager& mgr) {
            mgr.for_each_tunnel([](uint16_t /*id*/, tunnel::Tunnel* t) {
                auto* impl = dynamic_cast<tunnel::TunnelImpl*>(t);
                if (impl) {
                    impl->set_on_send_to_tox([](std::span<const uint8_t>) {});
                    impl->set_on_data_for_tcp([](std::span<const uint8_t>) {});
                    impl->set_on_state_change([](tunnel::Tunnel::State) {});
                    impl->set_on_error([](const tunnel::TunnelErrorPayload&) {});
                    impl->set_on_close([]() {});
                }
            });
        };
        if (client_mgr_)
            clear_callbacks(*client_mgr_);
        if (server_mgr_)
            clear_callbacks(*server_mgr_);

        // Stop the io_context and join the thread.
        work_guard_.reset();
        io_ctx_->stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }

        // Safe to destroy now -- callbacks are no-ops and no handlers are running.
        client_mgr_.reset();
        server_mgr_.reset();
    }

    /// Allow pending io_context handlers to execute.
    void poll() { std::this_thread::sleep_for(std::chrono::milliseconds(50)); }

    // -----------------------------------------------------------------------
    // Helper: create a connected tunnel pair
    // -----------------------------------------------------------------------
    //
    // Creates a TunnelImpl on the client side, calls open() to send
    // TUNNEL_OPEN.  Manually creates a matching TunnelImpl on the server
    // side and wires it into the server TunnelManager.  Then sends a
    // TUNNEL_ACK from the server to complete the handshake.
    //
    // Returns the tunnel ID.  After this call both tunnels are in
    // State::Connected and are registered in their respective managers.
    //
    // The out-parameters receive raw pointers to the TunnelImpl objects
    // (owned by their respective managers).
    uint16_t create_connected_pair(tunnel::TunnelImpl*& client_tunnel_out,
                                   tunnel::TunnelImpl*& server_tunnel_out) {
        const uint16_t tid = client_mgr_->allocate_tunnel_id();
        constexpr uint32_t kFriendNumber = 1;

        // --- Client side ---
        auto client_tunnel = std::make_unique<tunnel::TunnelImpl>(*io_ctx_, tid, kFriendNumber);

        // Wire the tunnel's on_send_to_tox so frames are forwarded through
        // the client TunnelManager's send_handler (which routes to server).
        auto* client_raw = client_tunnel.get();
        client_tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
            auto frame = tunnel::ProtocolFrame::deserialize(data);
            if (frame) {
                (void)client_mgr_->send_frame(frame.value());
            }
        });

        client_mgr_->add_tunnel(tid, std::move(client_tunnel));

        // Initiate the open -- sends TUNNEL_OPEN via send_handler -> server.
        EXPECT_TRUE(client_raw->open("127.0.0.1", 9090));
        EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Connecting);

        // --- Server side ---
        // In a real system the server TunnelManager would receive the
        // TUNNEL_OPEN via route_frame.  However, handle_incoming_open only
        // reserves the ID; it does not create a TunnelImpl.  We therefore
        // create one manually (simulating the server application layer).
        auto server_tunnel = std::make_unique<tunnel::TunnelImpl>(*io_ctx_, tid, kFriendNumber);

        auto* server_raw = server_tunnel.get();
        server_tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
            auto frame = tunnel::ProtocolFrame::deserialize(data);
            if (frame) {
                (void)server_mgr_->send_frame(frame.value());
            }
        });

        // Mark server tunnel as Connected (server accepted the open).
        server_tunnel->set_state(tunnel::Tunnel::State::Connected);

        server_mgr_->add_tunnel(tid, std::move(server_tunnel));

        // Send ACK from server to client to complete handshake.
        auto ack_frame = tunnel::ProtocolFrame::make_tunnel_ack(tid, 0);
        (void)server_mgr_->send_frame(ack_frame);

        // After the ACK the client tunnel should transition to Connected.
        poll();
        EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Connected);
        EXPECT_EQ(server_raw->state(), tunnel::Tunnel::State::Connected);

        client_tunnel_out = client_raw;
        server_tunnel_out = server_raw;
        return tid;
    }

    std::unique_ptr<asio::io_context> io_ctx_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work_guard_;
    std::thread io_thread_;
    std::unique_ptr<tunnel::TunnelManager> client_mgr_;
    std::unique_ptr<tunnel::TunnelManager> server_mgr_;
};

// ============================================================================
// 1. TunnelPairOpenAckLifecycle
//    Verify the full open-ACK handshake between two TunnelManagers.
// ============================================================================

TEST_F(TunnelDataFlowTest, TunnelPairOpenAckLifecycle) {
    constexpr uint16_t kTunnelId = 1;
    constexpr uint32_t kFriendNumber = 1;

    // Track state transitions on the client.
    std::vector<tunnel::Tunnel::State> client_states;
    std::mutex client_states_mu;

    // --- Client creates tunnel and calls open() ---
    auto client_tunnel = std::make_unique<tunnel::TunnelImpl>(*io_ctx_, kTunnelId, kFriendNumber);
    auto* client_raw = client_tunnel.get();

    client_tunnel->set_on_state_change(
        [&client_states, &client_states_mu](tunnel::Tunnel::State s) {
            std::lock_guard lock(client_states_mu);
            client_states.push_back(s);
        });

    // Wire on_send_to_tox -> client manager send_frame -> server route_frame.
    client_tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        auto frame = tunnel::ProtocolFrame::deserialize(data);
        if (frame) {
            (void)client_mgr_->send_frame(frame.value());
        }
    });

    client_mgr_->add_tunnel(kTunnelId, std::move(client_tunnel));

    // open() should transition to Connecting and send TUNNEL_OPEN.
    ASSERT_TRUE(client_raw->open("127.0.0.1", 8080));
    EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Connecting);

    // --- Server side receives the TUNNEL_OPEN ---
    // In a real deployment the application layer receives the TUNNEL_OPEN
    // frame, performs access checks, creates a TunnelImpl, wires it up,
    // and adds it to the manager.  We simulate that directly by creating
    // a TunnelImpl and adding it (skipping handle_incoming_open which
    // creates its own internal tunnel that would conflict with ours).

    // Create server-side tunnel.
    auto server_tunnel = std::make_unique<tunnel::TunnelImpl>(*io_ctx_, kTunnelId, kFriendNumber);
    auto* server_raw = server_tunnel.get();

    server_tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        auto frame = tunnel::ProtocolFrame::deserialize(data);
        if (frame) {
            (void)server_mgr_->send_frame(frame.value());
        }
    });

    server_tunnel->set_state(tunnel::Tunnel::State::Connected);
    server_mgr_->add_tunnel(kTunnelId, std::move(server_tunnel));

    // Server sends ACK back to client.
    auto ack_frame = tunnel::ProtocolFrame::make_tunnel_ack(kTunnelId, 0);
    (void)server_mgr_->send_frame(ack_frame);

    // Allow async handlers to run.
    poll();

    // Client should now be Connected.
    EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Connected);
    EXPECT_TRUE(client_raw->is_connected());
    EXPECT_EQ(server_raw->state(), tunnel::Tunnel::State::Connected);
    EXPECT_TRUE(server_raw->is_connected());

    // Verify the client went through Connecting -> Connected.
    {
        std::lock_guard lock(client_states_mu);
        ASSERT_GE(client_states.size(), 2u);
        EXPECT_EQ(client_states[0], tunnel::Tunnel::State::Connecting);
        EXPECT_EQ(client_states[1], tunnel::Tunnel::State::Connected);
    }

    // Both managers should contain the tunnel.
    EXPECT_TRUE(client_mgr_->has_tunnel(kTunnelId));
    EXPECT_TRUE(server_mgr_->has_tunnel(kTunnelId));
}

// ============================================================================
// 2. TunnelPairDataExchange
//    After establishing a connected pair, send TUNNEL_DATA in both
//    directions and verify the data callbacks fire with correct content.
// ============================================================================

TEST_F(TunnelDataFlowTest, TunnelPairDataExchange) {
    tunnel::TunnelImpl* client_raw = nullptr;
    tunnel::TunnelImpl* server_raw = nullptr;
    uint16_t tid = create_connected_pair(client_raw, server_raw);
    (void)tid;

    // Capture data that arrives at each side's TCP callback.
    std::vector<uint8_t> data_at_server;
    std::mutex server_data_mu;

    std::vector<uint8_t> data_at_client;
    std::mutex client_data_mu;

    server_raw->set_on_data_for_tcp(
        [&data_at_server, &server_data_mu](std::span<const uint8_t> data) {
            std::lock_guard lock(server_data_mu);
            data_at_server.insert(data_at_server.end(), data.begin(), data.end());
        });

    client_raw->set_on_data_for_tcp(
        [&data_at_client, &client_data_mu](std::span<const uint8_t> data) {
            std::lock_guard lock(client_data_mu);
            data_at_client.insert(data_at_client.end(), data.begin(), data.end());
        });

    // --- Client -> Server ---
    const std::vector<uint8_t> c2s_payload = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_TRUE(client_raw->send_data_to_tox(c2s_payload));
    poll();

    {
        std::lock_guard lock(server_data_mu);
        EXPECT_EQ(data_at_server, c2s_payload);
    }

    // --- Server -> Client ---
    const std::vector<uint8_t> s2c_payload = {0xCA, 0xFE, 0xBA, 0xBE, 0x42};
    EXPECT_TRUE(server_raw->send_data_to_tox(s2c_payload));
    poll();

    {
        std::lock_guard lock(client_data_mu);
        EXPECT_EQ(data_at_client, s2c_payload);
    }

    // Verify byte counters.
    EXPECT_EQ(client_raw->bytes_sent(), c2s_payload.size());
    EXPECT_EQ(client_raw->bytes_received(), s2c_payload.size());
    EXPECT_EQ(server_raw->bytes_sent(), s2c_payload.size());
    EXPECT_EQ(server_raw->bytes_received(), c2s_payload.size());
}

// ============================================================================
// 3. TunnelPairGracefulClose
//    After establishing a connected pair, one side sends TUNNEL_CLOSE.
//    The other side should transition to Closed.
// ============================================================================

TEST_F(TunnelDataFlowTest, TunnelPairGracefulClose) {
    tunnel::TunnelImpl* client_raw = nullptr;
    tunnel::TunnelImpl* server_raw = nullptr;
    (void)create_connected_pair(client_raw, server_raw);

    // Install callbacks to observe the close.
    std::atomic<bool> server_close_cb_fired{false};
    server_raw->set_on_close([&server_close_cb_fired]() {
        server_close_cb_fired.store(true, std::memory_order_release);
    });

    std::atomic<bool> server_state_changed_to_closed{false};
    server_raw->set_on_state_change([&server_state_changed_to_closed](tunnel::Tunnel::State s) {
        if (s == tunnel::Tunnel::State::Closed) {
            server_state_changed_to_closed.store(true, std::memory_order_release);
        }
    });

    // Client closes the tunnel.  This sends TUNNEL_CLOSE via the wired
    // transport, which routes to the server tunnel's handle_frame.
    client_raw->close();
    poll();

    // Client should be in Disconnecting (it initiated the close).
    EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Disconnecting);

    // Server should have received the TUNNEL_CLOSE and moved to Closed.
    EXPECT_EQ(server_raw->state(), tunnel::Tunnel::State::Closed);
    EXPECT_TRUE(server_close_cb_fired.load(std::memory_order_acquire));
    EXPECT_TRUE(server_state_changed_to_closed.load(std::memory_order_acquire));
}

// ============================================================================
// 4. TunnelPairErrorHandling
//    After establishing a connected pair, one side sends TUNNEL_ERROR.
//    The other side should receive the error and transition to Error state.
// ============================================================================

TEST_F(TunnelDataFlowTest, TunnelPairErrorHandling) {
    tunnel::TunnelImpl* client_raw = nullptr;
    tunnel::TunnelImpl* server_raw = nullptr;
    (void)create_connected_pair(client_raw, server_raw);

    // Install error callback on the client to observe the error.
    std::optional<tunnel::TunnelErrorPayload> received_error;
    std::mutex error_mu;
    client_raw->set_on_error([&received_error, &error_mu](const tunnel::TunnelErrorPayload& err) {
        std::lock_guard lock(error_mu);
        received_error = err;
    });

    std::atomic<bool> client_error_state{false};
    client_raw->set_on_state_change([&client_error_state](tunnel::Tunnel::State s) {
        if (s == tunnel::Tunnel::State::Error) {
            client_error_state.store(true, std::memory_order_release);
        }
    });

    // Server sends an error frame to the client.
    server_raw->send_error(42, "Connection refused by target");
    poll();

    // Server should have transitioned to Error as well (send_error does that).
    EXPECT_EQ(server_raw->state(), tunnel::Tunnel::State::Error);

    // Client should receive the error and transition to Error.
    EXPECT_EQ(client_raw->state(), tunnel::Tunnel::State::Error);
    EXPECT_TRUE(client_error_state.load(std::memory_order_acquire));

    {
        std::lock_guard lock(error_mu);
        ASSERT_TRUE(received_error.has_value());
        EXPECT_EQ(received_error->error_code, 42);
        EXPECT_EQ(received_error->description, "Connection refused by target");
    }
}

// ============================================================================
// 5. MultipleTunnelsOnSameManager
//    Create multiple tunnels on the same manager pair and verify each
//    can independently send and receive data without interference.
// ============================================================================

TEST_F(TunnelDataFlowTest, MultipleTunnelsOnSameManager) {
    constexpr std::size_t kNumTunnels = 5;

    struct TunnelPair {
        uint16_t tunnel_id{0};
        tunnel::TunnelImpl* client{nullptr};
        tunnel::TunnelImpl* server{nullptr};
        std::vector<uint8_t> server_received;
        std::vector<uint8_t> client_received;
        std::mutex server_mu;
        std::mutex client_mu;
    };

    std::vector<std::unique_ptr<TunnelPair>> pairs;
    pairs.reserve(kNumTunnels);

    // Create all pairs.
    for (std::size_t i = 0; i < kNumTunnels; ++i) {
        auto pair = std::make_unique<TunnelPair>();
        pair->tunnel_id = create_connected_pair(pair->client, pair->server);
        pairs.push_back(std::move(pair));
    }

    // Verify all tunnels are registered.
    EXPECT_EQ(client_mgr_->tunnel_count(), kNumTunnels);
    EXPECT_EQ(server_mgr_->tunnel_count(), kNumTunnels);

    // Wire data-for-tcp callbacks.
    for (auto& pair : pairs) {
        pair->server->set_on_data_for_tcp([p = pair.get()](std::span<const uint8_t> data) {
            std::lock_guard lock(p->server_mu);
            p->server_received.insert(p->server_received.end(), data.begin(), data.end());
        });

        pair->client->set_on_data_for_tcp([p = pair.get()](std::span<const uint8_t> data) {
            std::lock_guard lock(p->client_mu);
            p->client_received.insert(p->client_received.end(), data.begin(), data.end());
        });
    }

    // Send unique data through each tunnel.
    for (std::size_t i = 0; i < kNumTunnels; ++i) {
        auto tag = static_cast<uint8_t>(i + 1);
        std::vector<uint8_t> c2s = {tag, 0xAA};
        std::vector<uint8_t> s2c = {tag, 0xBB};

        EXPECT_TRUE(pairs[i]->client->send_data_to_tox(c2s));
        EXPECT_TRUE(pairs[i]->server->send_data_to_tox(s2c));
    }

    poll();

    // Verify each tunnel received exactly its own data.
    for (std::size_t i = 0; i < kNumTunnels; ++i) {
        auto tag = static_cast<uint8_t>(i + 1);
        const std::vector<uint8_t> expected_c2s = {tag, 0xAA};
        const std::vector<uint8_t> expected_s2c = {tag, 0xBB};

        {
            std::lock_guard lock(pairs[i]->server_mu);
            EXPECT_EQ(pairs[i]->server_received, expected_c2s)
                << "Tunnel " << pairs[i]->tunnel_id << " server data mismatch";
        }

        {
            std::lock_guard lock(pairs[i]->client_mu);
            EXPECT_EQ(pairs[i]->client_received, expected_s2c)
                << "Tunnel " << pairs[i]->tunnel_id << " client data mismatch";
        }
    }
}

// ============================================================================
// 6. TunnelManagerFrameRouting
//    Verify that route_frame() dispatches frames to the correct tunnel
//    based on tunnel_id.
// ============================================================================

TEST_F(TunnelDataFlowTest, TunnelManagerFrameRouting) {
    constexpr uint32_t kFriendNumber = 1;

    // Create three tunnels on the server manager with known IDs.
    constexpr uint16_t kId1 = 10;
    constexpr uint16_t kId2 = 20;
    constexpr uint16_t kId3 = 30;

    auto make_tunnel = [this, kFriendNumber](uint16_t tid) {
        auto t = std::make_unique<tunnel::TunnelImpl>(*io_ctx_, tid, kFriendNumber);
        t->set_state(tunnel::Tunnel::State::Connected);
        t->set_on_send_to_tox([](std::span<const uint8_t>) {
            // No-op: we only care about receiving, not sending ACKs back.
        });
        return t;
    };

    // Track which data each tunnel receives.
    struct ReceivedData {
        std::vector<uint8_t> data;
        std::mutex mu;
    };

    auto rd1 = std::make_shared<ReceivedData>();
    auto rd2 = std::make_shared<ReceivedData>();
    auto rd3 = std::make_shared<ReceivedData>();

    auto t1 = make_tunnel(kId1);
    t1->set_on_data_for_tcp([rd1](std::span<const uint8_t> d) {
        std::lock_guard lock(rd1->mu);
        rd1->data.insert(rd1->data.end(), d.begin(), d.end());
    });

    auto t2 = make_tunnel(kId2);
    t2->set_on_data_for_tcp([rd2](std::span<const uint8_t> d) {
        std::lock_guard lock(rd2->mu);
        rd2->data.insert(rd2->data.end(), d.begin(), d.end());
    });

    auto t3 = make_tunnel(kId3);
    t3->set_on_data_for_tcp([rd3](std::span<const uint8_t> d) {
        std::lock_guard lock(rd3->mu);
        rd3->data.insert(rd3->data.end(), d.begin(), d.end());
    });

    server_mgr_->add_tunnel(kId1, std::move(t1));
    server_mgr_->add_tunnel(kId2, std::move(t2));
    server_mgr_->add_tunnel(kId3, std::move(t3));

    // Route frames with different tunnel IDs.
    const std::vector<uint8_t> payload1 = {0x11};
    const std::vector<uint8_t> payload2 = {0x22, 0x33};
    const std::vector<uint8_t> payload3 = {0x44, 0x55, 0x66};

    auto frame1 = tunnel::ProtocolFrame::make_tunnel_data(kId1, payload1);
    auto frame2 = tunnel::ProtocolFrame::make_tunnel_data(kId2, payload2);
    auto frame3 = tunnel::ProtocolFrame::make_tunnel_data(kId3, payload3);

    server_mgr_->route_frame(frame1);
    server_mgr_->route_frame(frame2);
    server_mgr_->route_frame(frame3);

    // Also route a second frame to tunnel 1 to verify accumulation.
    const std::vector<uint8_t> payload1b = {0x77};
    auto frame1b = tunnel::ProtocolFrame::make_tunnel_data(kId1, payload1b);
    server_mgr_->route_frame(frame1b);

    poll();

    // Verify each tunnel received only its frames.
    {
        std::lock_guard lock(rd1->mu);
        const std::vector<uint8_t> expected = {0x11, 0x77};
        EXPECT_EQ(rd1->data, expected);
    }
    {
        std::lock_guard lock(rd2->mu);
        EXPECT_EQ(rd2->data, payload2);
    }
    {
        std::lock_guard lock(rd3->mu);
        EXPECT_EQ(rd3->data, payload3);
    }
}

}  // namespace
}  // namespace toxtunnel::integration
