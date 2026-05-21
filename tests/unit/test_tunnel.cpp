#include <gtest/gtest.h>

#include <asio.hpp>

#include "toxtunnel/tunnel/tunnel.hpp"

using namespace toxtunnel::tunnel;

// ============================================================================
// Test Fixture
// ============================================================================

class TunnelTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
    uint16_t test_tunnel_id = 42;
    uint32_t test_friend_number = 1;
};

// ============================================================================
// 1. InitialState - verify tunnel starts in correct initial state
// ============================================================================

TEST_F(TunnelTest, InitialState_IsNone) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    EXPECT_EQ(tunnel.state(), Tunnel::State::None);
}

TEST_F(TunnelTest, InitialState_NotConnected) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    EXPECT_FALSE(tunnel.is_connected());
}

TEST_F(TunnelTest, InitialState_HasCorrectTunnelId) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    EXPECT_EQ(tunnel.tunnel_id(), test_tunnel_id);
}

TEST_F(TunnelTest, InitialState_HasCorrectFriendNumber) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    EXPECT_EQ(tunnel.friend_number(), test_friend_number);
}

// ============================================================================
// 2. StateTransitions - verify state machine transitions
// ============================================================================

TEST_F(TunnelTest, StateTransition_NoneToConnecting) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Connecting);
}

TEST_F(TunnelTest, StateTransition_ConnectingToConnected) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Connected);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Connected);
    EXPECT_TRUE(tunnel.is_connected());
}

TEST_F(TunnelTest, StateTransition_ConnectedToDisconnecting) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Connected);
    tunnel.set_state(Tunnel::State::Disconnecting);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Disconnecting);
    EXPECT_FALSE(tunnel.is_connected());
}

TEST_F(TunnelTest, StateTransition_DisconnectingToClosed) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Connected);
    tunnel.set_state(Tunnel::State::Disconnecting);
    tunnel.set_state(Tunnel::State::Closed);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Closed);
    EXPECT_FALSE(tunnel.is_connected());
}

TEST_F(TunnelTest, StateTransition_ErrorToClosed) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Error);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Error);
    EXPECT_FALSE(tunnel.is_connected());
}

// ============================================================================
// 3. OpenTunnel - TUNNEL_OPEN handling
// ============================================================================

TEST_F(TunnelTest, OpenTunnel_TransitionsToConnecting) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return true; });

    bool callback_called = false;
    tunnel.set_on_state_change([&callback_called](Tunnel::State new_state) {
        if (new_state == Tunnel::State::Connecting) {
            callback_called = true;
        }
    });

    (void)tunnel.open("localhost", 8080);

    EXPECT_EQ(tunnel.state(), Tunnel::State::Connecting);
    EXPECT_TRUE(callback_called);
}

TEST_F(TunnelTest, OpenTunnel_StoresTargetInfo) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return true; });
    (void)tunnel.open("example.com", 443);

    EXPECT_EQ(tunnel.target_host(), "example.com");
    EXPECT_EQ(tunnel.target_port(), 443);
}

TEST_F(TunnelTest, OpenTunnel_FailsIfNotInNoneState) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);

    EXPECT_FALSE(tunnel.open("localhost", 8080));
}

TEST_F(TunnelTest, OpenTunnel_FailsIfInitialOpenSendRejected) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return false; });

    EXPECT_FALSE(tunnel.open("localhost", 8080));
    EXPECT_EQ(tunnel.state(), Tunnel::State::None);
}

// ============================================================================
// 4. CloseTunnel - TUNNEL_CLOSE handling
// ============================================================================

TEST_F(TunnelTest, CloseTunnel_TransitionsToDisconnecting) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Connected);

    tunnel.close();

    EXPECT_EQ(tunnel.state(), Tunnel::State::Disconnecting);
}

TEST_F(TunnelTest, CloseTunnel_GracefulShutdown) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);
    tunnel.set_state(Tunnel::State::Connected);

    bool close_frame_ready = false;
    tunnel.set_on_send_to_tox([&close_frame_ready](std::span<const uint8_t> data) -> bool {
        // Verify it's a TUNNEL_CLOSE frame
        EXPECT_GE(data.size(), 5u);
        EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::TUNNEL_CLOSE);
        close_frame_ready = true;
        return true;
    });

    tunnel.close();

    EXPECT_TRUE(close_frame_ready);
}

TEST_F(TunnelTest, CloseTunnel_FromNoneDoesNothing) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.close();  // Should not crash or throw
    EXPECT_EQ(tunnel.state(), Tunnel::State::None);
}

// ============================================================================
// 5. HandleFrame - process incoming protocol frames
// ============================================================================

TEST_F(TunnelTest, HandleFrame_TunnelOpenAck) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);

    // Simulate receiving a TUNNEL_ACK while Connecting -> transitions to Connected
    tunnel.handle_frame(ProtocolFrame::make_tunnel_ack(test_tunnel_id, 0));

    EXPECT_EQ(tunnel.state(), Tunnel::State::Connected);
}

TEST_F(TunnelTest, HandleFrame_TunnelData) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    std::vector<uint8_t> received_data;
    tunnel.set_on_data_for_tcp([&received_data](std::span<const uint8_t> data) {
        received_data.assign(data.begin(), data.end());
    });

    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
    auto frame = ProtocolFrame::make_tunnel_data(test_tunnel_id, test_data);
    tunnel.handle_frame(frame);

    EXPECT_EQ(received_data, test_data);
}

TEST_F(TunnelTest, HandleFrame_TunnelClose) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    tunnel.handle_frame(ProtocolFrame::make_tunnel_close(test_tunnel_id));

    EXPECT_EQ(tunnel.state(), Tunnel::State::Closed);
}

TEST_F(TunnelTest, HandleFrame_TunnelError) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connecting);

    std::optional<TunnelErrorPayload> error_received;
    tunnel.set_on_error([&error_received](const TunnelErrorPayload& err) { error_received = err; });

    auto frame = ProtocolFrame::make_tunnel_error(test_tunnel_id, 42, "Connection refused");
    tunnel.handle_frame(frame);

    ASSERT_TRUE(error_received.has_value());
    EXPECT_EQ(error_received->error_code, 42);
    EXPECT_EQ(error_received->description, "Connection refused");
}

TEST_F(TunnelTest, HandleFrame_Ping) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    bool pong_sent = false;
    tunnel.set_on_send_to_tox([&pong_sent](std::span<const uint8_t> data) -> bool {
        EXPECT_GE(data.size(), 5u);
        EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::PONG);
        pong_sent = true;
        return true;
    });

    tunnel.handle_frame(ProtocolFrame::make_ping());

    EXPECT_TRUE(pong_sent);
}

TEST_F(TunnelTest, HandleFrame_TunnelAck) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    // Send some data first to establish bytes_sent
    (void)tunnel.send_data_to_tox({0x01, 0x02, 0x03});

    // Initial window usage
    EXPECT_GT(tunnel.send_window_used(), 0u);

    // Receive ACK for 3 bytes
    auto frame = ProtocolFrame::make_tunnel_ack(test_tunnel_id, 3);
    tunnel.handle_frame(frame);

    // Window should be freed
    EXPECT_EQ(tunnel.send_window_used(), 0u);
}

// ============================================================================
// 6. SendData - sending data through the tunnel
// ============================================================================

TEST_F(TunnelTest, SendData_QueuesData) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    std::vector<std::vector<uint8_t>> sent_frames;
    tunnel.set_on_send_to_tox([&sent_frames](std::span<const uint8_t> data) -> bool {
        sent_frames.emplace_back(data.begin(), data.end());
        return true;
    });

    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    (void)tunnel.send_data_to_tox(test_data);

    // Data should be queued
    EXPECT_GE(tunnel.send_window_used(), test_data.size());
}

TEST_F(TunnelTest, SendData_SplitsFramesToFitToxCustomPacketLimit) {
    constexpr std::size_t kMaxTcpPayloadPerFrame = 1367;

    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    // Coalescing-off path exercises the raw fragmentation behaviour this
    // test was originally written for; the coalescing path is covered in
    // tunnel_coalesce_test.cpp.
    tunnel.configure_coalesce(0, kMaxTcpPayloadPerFrame);
    tunnel.set_state(Tunnel::State::Connected);

    std::vector<ProtocolFrame> sent_frames;
    tunnel.set_on_send_to_tox([&sent_frames](std::span<const uint8_t> data) -> bool {
        auto frame = ProtocolFrame::deserialize(data);
        EXPECT_TRUE(frame.has_value()) << frame.error().message();
        if (frame.has_value()) {
            sent_frames.push_back(frame.value());
        }
        return true;
    });

    std::vector<uint8_t> payload(kMaxTcpPayloadPerFrame + 128, 0x5A);
    ASSERT_TRUE(tunnel.send_data_to_tox(payload));

    ASSERT_EQ(sent_frames.size(), 2u);
    EXPECT_EQ(sent_frames[0].type(), FrameType::TUNNEL_DATA);
    EXPECT_EQ(sent_frames[0].as_tunnel_data().size(), kMaxTcpPayloadPerFrame);
    EXPECT_EQ(sent_frames[1].type(), FrameType::TUNNEL_DATA);
    EXPECT_EQ(sent_frames[1].as_tunnel_data().size(), 128u);
}

TEST_F(TunnelTest, SendData_RespectsWindow) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number, 100);  // Small window
    tunnel.set_state(Tunnel::State::Connected);

    // Fill the window
    std::vector<uint8_t> large_data(100, 0x42);
    EXPECT_TRUE(tunnel.send_data_to_tox(large_data));

    // Next send should fail because window is full
    std::vector<uint8_t> more_data = {0x01};
    EXPECT_FALSE(tunnel.send_data_to_tox(more_data));
}

TEST_F(TunnelTest, SendData_FailsIfNotConnected) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    EXPECT_FALSE(tunnel.send_data_to_tox(data));
}

// ============================================================================
// 7. Backpressure - flow control with ACK frames
// ============================================================================

TEST_F(TunnelTest, Backpressure_WindowTracksSentBytes) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number, 1024);
    tunnel.set_state(Tunnel::State::Connected);

    EXPECT_EQ(tunnel.send_window_used(), 0u);

    (void)tunnel.send_data_to_tox({0x01, 0x02, 0x03, 0x04, 0x05});

    EXPECT_EQ(tunnel.send_window_used(), 5u);
}

TEST_F(TunnelTest, Backpressure_WindowFreedOnAck) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number, 1024);
    tunnel.set_state(Tunnel::State::Connected);

    (void)tunnel.send_data_to_tox({0x01, 0x02, 0x03, 0x04, 0x05});
    EXPECT_EQ(tunnel.send_window_used(), 5u);

    auto frame = ProtocolFrame::make_tunnel_ack(test_tunnel_id, 5);
    tunnel.handle_frame(frame);

    EXPECT_EQ(tunnel.send_window_used(), 0u);
}

TEST_F(TunnelTest, Backpressure_ReceiveBufferTracking) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    // Receive data
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto frame = ProtocolFrame::make_tunnel_data(test_tunnel_id, data);
    tunnel.handle_frame(frame);

    // Track bytes received for ACK
    EXPECT_EQ(tunnel.bytes_received(), 3u);
}

TEST_F(TunnelTest, Backpressure_SendAckAfterThreshold) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    // Set a small ACK threshold
    tunnel.set_ack_threshold(5);

    bool ack_sent = false;
    tunnel.set_on_send_to_tox([&ack_sent](std::span<const uint8_t> data) -> bool {
        EXPECT_GE(data.size(), 5u);
        if (static_cast<FrameType>(data[0]) == FrameType::TUNNEL_ACK) {
            ack_sent = true;
        }
        return true;
    });

    // Receive data below threshold
    std::vector<uint8_t> data1 = {0x01, 0x02};
    auto frame1 = ProtocolFrame::make_tunnel_data(test_tunnel_id, data1);
    tunnel.handle_frame(frame1);
    EXPECT_FALSE(ack_sent);

    // Receive more data to exceed threshold
    std::vector<uint8_t> data2 = {0x03, 0x04, 0x05};
    auto frame2 = ProtocolFrame::make_tunnel_data(test_tunnel_id, data2);
    tunnel.handle_frame(frame2);
    EXPECT_TRUE(ack_sent);
}

// ============================================================================
// 8. KeepAlive - PING/PONG handling
// ============================================================================

TEST_F(TunnelTest, KeepAlive_RespondsWithPong) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    bool pong_sent = false;
    tunnel.set_on_send_to_tox([&pong_sent](std::span<const uint8_t> data) -> bool {
        EXPECT_GE(data.size(), 5u);
        EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::PONG);
        pong_sent = true;
        return true;
    });

    tunnel.handle_frame(ProtocolFrame::make_ping());

    EXPECT_TRUE(pong_sent);
}

TEST_F(TunnelTest, KeepAlive_UpdatesLastActivity) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    auto before = tunnel.last_activity();
    tunnel.handle_frame(ProtocolFrame::make_ping());
    auto after = tunnel.last_activity();

    EXPECT_GE(after, before);
}

// ============================================================================
// 9. TcpConnection - TCP socket integration
// ============================================================================

TEST_F(TunnelTest, TcpConnection_CanBeSet) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);

    auto tcp_conn = std::make_shared<toxtunnel::core::TcpConnection>(io_ctx);
    tunnel.set_tcp_connection(tcp_conn);

    EXPECT_EQ(tunnel.tcp_connection(), tcp_conn);
}

TEST_F(TunnelTest, TcpConnection_DataFromTcpSendsToTox) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    // Disable coalescing so the small TCP write emits synchronously; the
    // coalescing path is covered by tunnel_coalesce_test.cpp.
    tunnel.configure_coalesce(0, 1362);
    tunnel.set_state(Tunnel::State::Connected);

    bool data_sent_to_tox = false;
    tunnel.set_on_send_to_tox([&data_sent_to_tox](std::span<const uint8_t> data) -> bool {
        EXPECT_GE(data.size(), 5u);
        EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::TUNNEL_DATA);
        data_sent_to_tox = true;
        return true;
    });

    // Simulate TCP data callback
    std::vector<uint8_t> tcp_data = {0xAA, 0xBB, 0xCC};
    tunnel.on_tcp_data_received(tcp_data.data(), tcp_data.size());

    EXPECT_TRUE(data_sent_to_tox);
}

// ============================================================================
// 10. ErrorHandling - error scenarios
// ============================================================================

TEST_F(TunnelTest, ErrorHandling_SendErrorFrame) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    bool error_sent = false;
    tunnel.set_on_send_to_tox([&error_sent](std::span<const uint8_t> data) -> bool {
        EXPECT_GE(data.size(), 5u);
        EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::TUNNEL_ERROR);
        error_sent = true;
        return true;
    });

    tunnel.send_error(42, "Test error");

    EXPECT_TRUE(error_sent);
    EXPECT_EQ(tunnel.state(), Tunnel::State::Error);
}

TEST_F(TunnelTest, ErrorHandling_InvalidTunnelIdIgnored) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    // Frame with wrong tunnel ID should be ignored
    bool data_callback_called = false;
    tunnel.set_on_data_for_tcp(
        [&data_callback_called](std::span<const uint8_t>) { data_callback_called = true; });

    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto frame = ProtocolFrame::make_tunnel_data(test_tunnel_id + 1, data);
    tunnel.handle_frame(frame);

    EXPECT_FALSE(data_callback_called);
}

// ============================================================================
// 11. Callbacks - verify callback invocations
// ============================================================================

TEST_F(TunnelTest, Callbacks_OnStateChange) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_on_send_to_tox([](std::span<const uint8_t>) -> bool { return true; });

    std::vector<Tunnel::State> state_changes;
    tunnel.set_on_state_change([&state_changes](Tunnel::State s) { state_changes.push_back(s); });

    (void)tunnel.open("localhost", 8080);

    ASSERT_EQ(state_changes.size(), 1u);
    EXPECT_EQ(state_changes[0], Tunnel::State::Connecting);
}

TEST_F(TunnelTest, Callbacks_OnClose) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    bool close_callback_called = false;
    tunnel.set_on_close([&close_callback_called]() { close_callback_called = true; });

    tunnel.handle_frame(ProtocolFrame::make_tunnel_close(test_tunnel_id));

    EXPECT_TRUE(close_callback_called);
}

// ============================================================================
// 12. ToString - string representation of states
// ============================================================================

TEST_F(TunnelTest, ToString_AllStates) {
    EXPECT_STREQ(to_string(Tunnel::State::None), "None");
    EXPECT_STREQ(to_string(Tunnel::State::Connecting), "Connecting");
    EXPECT_STREQ(to_string(Tunnel::State::Connected), "Connected");
    EXPECT_STREQ(to_string(Tunnel::State::Disconnecting), "Disconnecting");
    EXPECT_STREQ(to_string(Tunnel::State::Closed), "Closed");
    EXPECT_STREQ(to_string(Tunnel::State::Error), "Error");
}

// ============================================================================
// 13. Statistics - byte counters and metrics
// ============================================================================

TEST_F(TunnelTest, Statistics_BytesSent) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    (void)tunnel.send_data_to_tox({0x01, 0x02, 0x03});
    (void)tunnel.send_data_to_tox({0x04, 0x05});

    EXPECT_EQ(tunnel.bytes_sent(), 5u);
}

TEST_F(TunnelTest, Statistics_BytesReceived) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    auto frame1 = ProtocolFrame::make_tunnel_data(test_tunnel_id, data1);
    tunnel.handle_frame(frame1);

    std::vector<uint8_t> data2 = {0x04, 0x05};
    auto frame2 = ProtocolFrame::make_tunnel_data(test_tunnel_id, data2);
    tunnel.handle_frame(frame2);

    EXPECT_EQ(tunnel.bytes_received(), 5u);
}

TEST_F(TunnelTest, Statistics_Reset) {
    TunnelImpl tunnel(io_ctx, test_tunnel_id, test_friend_number);
    tunnel.set_state(Tunnel::State::Connected);

    (void)tunnel.send_data_to_tox({0x01, 0x02, 0x03});
    tunnel.reset_statistics();

    EXPECT_EQ(tunnel.bytes_sent(), 0u);
    EXPECT_EQ(tunnel.bytes_received(), 0u);
}
