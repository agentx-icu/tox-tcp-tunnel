// Regression for issue #33: a remote TUNNEL_CLOSE that lands behind a burst of
// TUNNEL_DATA must not discard the bytes still queued on the local TCP socket.
//
// Field signature: the application reads exactly the first coalesced frame
// (1362 bytes) of a 64 KiB echo and then a clean EOF. The frames after it had
// been accepted by the tunnel and handed to TcpConnection::write(), but were
// still sitting in its user-space write queue when the tunnel was torn down.
// TunnelManager::remove_tunnel_impl() routes a tunnel that is already Closed
// through TunnelImpl::force_close(), and force_close() used to
// TcpConnection::force_close() the socket — discarding that queue.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace {

using namespace toxtunnel;
using namespace std::chrono_literals;

constexpr std::uint16_t kTunnelId = 7;
constexpr std::uint32_t kFriendNumber = 1;
constexpr std::size_t kFrameBytes = 1362;  // one coalesced frame, the default cap

class RemoteCloseDrainTest : public ::testing::Test {
   protected:
    void SetUp() override {
        work_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io_ctx_.get_executor());
        for (int i = 0; i < kIoThreads; ++i) {
            threads_.emplace_back([this] { io_ctx_.run(); });
        }
    }

    void TearDown() override {
        work_.reset();
        io_ctx_.stop();
        for (auto& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    /// Park every io_context worker on a latch so that everything posted in
    /// the meantime queues up in FIFO order — the same pile-up a busy TCP
    /// strand shows in the field when the Tox thread delivers a burst.
    void park_io_threads() {
        parked_ = true;
        for (int i = 0; i < kIoThreads; ++i) {
            asio::post(io_ctx_, [this] {
                std::unique_lock<std::mutex> lock(park_mutex_);
                ++parked_count_;
                park_cv_.notify_all();
                park_cv_.wait(lock, [this] { return !parked_; });
            });
        }
        std::unique_lock<std::mutex> lock(park_mutex_);
        park_cv_.wait(lock, [this] { return parked_count_ == kIoThreads; });
    }

    void release_io_threads() {
        {
            std::lock_guard<std::mutex> lock(park_mutex_);
            parked_ = false;
        }
        park_cv_.notify_all();
    }

    static constexpr int kIoThreads = 2;
    asio::io_context io_ctx_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work_;
    std::vector<std::thread> threads_;

    std::mutex park_mutex_;
    std::condition_variable park_cv_;
    bool parked_{false};
    int parked_count_{0};
};

TEST_F(RemoteCloseDrainTest, DataQueuedOnTheLocalSocketSurvivesARemoteClose) {
    // Loopback pair: `conn` is the tunnel's local socket, `app` the application.
    asio::ip::tcp::acceptor acceptor(
        io_ctx_, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    asio::ip::tcp::socket app(io_ctx_);
    auto conn = std::make_shared<core::TcpConnection>(io_ctx_);

    std::promise<bool> accepted;
    acceptor.async_accept(app, [&accepted](const std::error_code& ec) { accepted.set_value(!ec); });
    std::promise<bool> connected;
    conn->async_connect(acceptor.local_endpoint(),
                        [&connected](const std::error_code& ec) { connected.set_value(!ec); });
    ASSERT_TRUE(accepted.get_future().get());
    ASSERT_TRUE(connected.get_future().get());

    // Wire the tunnel exactly as TunnelClient::on_tcp_connection_accepted does.
    auto mgr = std::make_shared<tunnel::TunnelManager>(io_ctx_);
    mgr->set_send_handler(
        [](const std::vector<std::uint8_t>&) { return tunnel::SendOutcome::Sent; });
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx_, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) { return tunnel::SendOutcome::Sent; });
    tunnel->set_tcp_connection(conn);
    tunnel->set_on_data_for_tcp_owned(
        [conn](core::OwnedBufferView buf) -> bool { return conn->write(std::move(buf)); });
    tunnel->set_on_data_for_tcp([conn](std::span<const std::uint8_t> data) -> bool {
        return conn->write(data.data(), data.size());
    });
    tunnel->set_on_state_change([conn](tunnel::Tunnel::State s) {
        if (s == tunnel::Tunnel::State::Closed || s == tunnel::Tunnel::State::Error) {
            conn->close();
        }
    });
    const std::weak_ptr<tunnel::TunnelImpl> weak_tunnel = tunnel;
    tunnel->set_on_close([mgr, weak_tunnel]() {
        if (auto self = weak_tunnel.lock()) {
            (void)mgr->remove_tunnel_if(kTunnelId, self.get());
        }
    });
    conn->set_on_read_eof([weak_tunnel]() {
        if (auto t = weak_tunnel.lock()) {
            t->on_tcp_read_eof();
        }
    });
    conn->set_on_disconnect([weak_tunnel](const std::error_code&) {
        if (auto t = weak_tunnel.lock()) {
            t->close();
        }
    });
    tunnel->set_state(tunnel::Tunnel::State::Connected);
    ASSERT_TRUE(mgr->add_tunnel(kTunnelId, tunnel));
    conn->start_read();

    // The application half-closes first (the echo client's shutdown(SHUT_WR)),
    // so the tunnel emits its own half-close and waits for the peer's.
    std::error_code ec;
    app.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    ASSERT_FALSE(ec);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (tunnel->state() != tunnel::Tunnel::State::Disconnecting &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(tunnel->state(), tunnel::Tunnel::State::Disconnecting);

    // The peer's echo: a burst of DATA followed by CLOSE, delivered back to
    // back from one thread, exactly as the Tox thread does. The io threads are
    // parked so every socket write queues behind the first one, and the
    // teardown that follows the CLOSE lands behind all of them.
    constexpr std::size_t kFrames = 48;
    std::vector<std::uint8_t> expected;
    expected.reserve(kFrames * kFrameBytes);
    park_io_threads();
    for (std::size_t i = 0; i < kFrames; ++i) {
        std::vector<std::uint8_t> payload(kFrameBytes);
        for (std::size_t j = 0; j < payload.size(); ++j) {
            payload[j] = static_cast<std::uint8_t>((i * 131u + j * 7u) & 0xFFu);
        }
        expected.insert(expected.end(), payload.begin(), payload.end());
        tunnel->handle_frame(tunnel::ProtocolFrame::make_tunnel_data(
            kTunnelId, std::span<const std::uint8_t>(payload.data(), payload.size())));
    }
    tunnel->handle_frame(tunnel::ProtocolFrame::make_tunnel_close(kTunnelId));
    release_io_threads();

    // The application reads to EOF. Every byte the tunnel accepted must arrive.
    std::vector<std::uint8_t> got;
    std::array<std::uint8_t, 8192> buf{};
    for (;;) {
        std::error_code read_ec;
        const std::size_t n = app.read_some(asio::buffer(buf), read_ec);
        if (n > 0) {
            got.insert(got.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
        }
        if (read_ec) {
            EXPECT_EQ(read_ec, asio::error::eof) << read_ec.message();
            break;
        }
    }
    EXPECT_EQ(got.size(), expected.size())
        << "the tail of the stream was discarded by the post-close teardown";
    EXPECT_EQ(got, expected);
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Closed);
}

}  // namespace

// ---------------------------------------------------------------------------
// tunnels_closed_total bookkeeping (issue #36): one sample per tunnel.
// ---------------------------------------------------------------------------

namespace {

std::uint64_t closed_total() {
    using R = util::MetricsRegistry::CloseReason;
    auto& m = util::MetricsRegistry::instance();
    return m.tunnels_closed(R::Local) + m.tunnels_closed(R::Remote) + m.tunnels_closed(R::Timeout) +
           m.tunnels_closed(R::Error);
}

}  // namespace

TEST(TunnelCloseBookkeepingTest, HalfCloseThenRemoteCloseBooksExactlyOneSample) {
    util::MetricsRegistry::instance().reset();
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) { return tunnel::SendOutcome::Sent; });
    tunnel->set_state(tunnel::Tunnel::State::Connected);

    // The local application half-closes: a TUNNEL_CLOSE goes out, the tunnel
    // is Disconnecting — still open in the other direction, so not a close.
    tunnel->on_tcp_read_eof();
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Disconnecting);
    EXPECT_EQ(closed_total(), 0u) << "a half-close is not a tunnel close";

    // The peer reciprocates: now the tunnel ends, once.
    tunnel->handle_frame(tunnel::ProtocolFrame::make_tunnel_close(kTunnelId));
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Closed);
    EXPECT_EQ(closed_total(), 1u);
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_closed(
                  util::MetricsRegistry::CloseReason::Remote),
              1u);

    // Manager-style cleanup afterwards books nothing more.
    tunnel->force_close(tunnel::TunnelImpl::ResourceRelease::DrainIfClosed);
    EXPECT_EQ(closed_total(), 1u);
}

TEST(TunnelCloseBookkeepingTest, LocalTerminalErrorBooksAnErrorSample) {
    util::MetricsRegistry::instance().reset();
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    std::vector<std::uint8_t> sent;
    tunnel->set_on_send_to_tox([&sent](std::span<const std::uint8_t> wire) {
        sent.insert(sent.end(), wire.begin(), wire.end());
        return tunnel::SendOutcome::Sent;
    });
    tunnel->set_state(tunnel::Tunnel::State::Connected);
    int closes = 0;
    tunnel->set_on_close([&closes]() { ++closes; });

    tunnel->fail_locally(2, "resume declined by server");

    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Error);
    EXPECT_EQ(closes, 1);
    EXPECT_TRUE(sent.empty()) << "fail_locally must put nothing on the wire";
    EXPECT_EQ(tunnel->last_error_code(), 2);
    EXPECT_EQ(tunnel->last_error_description(), "resume declined by server");
    EXPECT_EQ(
        util::MetricsRegistry::instance().tunnels_closed(util::MetricsRegistry::CloseReason::Error),
        1u);
    EXPECT_EQ(closed_total(), 1u);

    // Duplicate terminal claims are suppressed, and nothing books twice.
    tunnel->fail_locally(2, "again");
    tunnel->force_close();
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(closed_total(), 1u);
}

TEST(TunnelCloseBookkeepingTest, SentErrorBooksAnErrorSample) {
    util::MetricsRegistry::instance().reset();
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) { return tunnel::SendOutcome::Sent; });
    tunnel->set_state(tunnel::Tunnel::State::Connected);

    tunnel->send_error(4, "target connection ended abnormally");
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Error);
    EXPECT_EQ(
        util::MetricsRegistry::instance().tunnels_closed(util::MetricsRegistry::CloseReason::Error),
        1u);
    EXPECT_EQ(closed_total(), 1u);
}

// ---------------------------------------------------------------------------
// OPEN_ACK deadline (issue #36): a tunnel whose OPEN never gets an ACK ends.
// ---------------------------------------------------------------------------

TEST(TunnelOpenTimeoutTest, ConnectingTunnelIsClosedWhenTheAckNeverArrives) {
    util::MetricsRegistry::instance().reset();
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    std::vector<tunnel::FrameType> on_wire;
    tunnel->set_on_send_to_tox([&on_wire](std::span<const std::uint8_t> wire) {
        on_wire.push_back(static_cast<tunnel::FrameType>(wire[0]));
        return tunnel::SendOutcome::Sent;
    });
    std::vector<tunnel::Tunnel::State> states;
    tunnel->set_on_state_change([&states](tunnel::Tunnel::State s) { states.push_back(s); });
    int closes = 0;
    tunnel->set_on_close([&closes]() { ++closes; });
    tunnel->set_open_timeout(std::chrono::seconds(1));

    ASSERT_TRUE(tunnel->open("example.invalid", 80));
    ASSERT_EQ(tunnel->state(), tunnel::Tunnel::State::Connecting);
    ASSERT_EQ(on_wire, (std::vector<tunnel::FrameType>{tunnel::FrameType::TUNNEL_OPEN}));

    // Nothing answers. The deadline fires (io_context-driven) and the tunnel
    // takes the handshake-close path: a CLOSE for the OPEN the peer did
    // receive, then Closed, then the close notification.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (tunnel->state() == tunnel::Tunnel::State::Connecting &&
           std::chrono::steady_clock::now() < deadline) {
        io_ctx.run_for(std::chrono::milliseconds(20));
        io_ctx.restart();
    }
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Closed);
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(on_wire, (std::vector<tunnel::FrameType>{tunnel::FrameType::TUNNEL_OPEN,
                                                       tunnel::FrameType::TUNNEL_CLOSE}));
    EXPECT_EQ(closed_total(), 1u);
}

TEST(TunnelOpenTimeoutTest, DeadlineIsDisarmedOnceTheAckArrives) {
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) { return tunnel::SendOutcome::Sent; });
    int closes = 0;
    tunnel->set_on_close([&closes]() { ++closes; });
    tunnel->set_open_timeout(std::chrono::seconds(1));

    ASSERT_TRUE(tunnel->open("example.invalid", 80));
    tunnel->handle_frame(tunnel::ProtocolFrame::make_tunnel_ack(kTunnelId, 0));
    ASSERT_EQ(tunnel->state(), tunnel::Tunnel::State::Connected);

    // Well past the deadline: the disarmed timer must not touch the tunnel.
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(1300);
    while (std::chrono::steady_clock::now() < until) {
        io_ctx.run_for(std::chrono::milliseconds(50));
        io_ctx.restart();
    }
    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Connected);
    EXPECT_EQ(closes, 0);
}

// ---------------------------------------------------------------------------
// Issue #33, the receiving side under load: a shutdown_send() request must take
// effect in strand order with the writes posted before it.
// ---------------------------------------------------------------------------

TEST_F(RemoteCloseDrainTest, ShutdownSendDoesNotOvertakeWritesStillInTheStrandQueue) {
    // The interleaving that lost the tail in the field, made deterministic:
    // the strand is pinned INSIDE A's write-completion handler (a blocking
    // on_writable callback runs there, before do_write() decides whether the
    // send half may be shut down). While it is pinned, the peer's last DATA
    // (write(B)) and its CLOSE (shutdown_send()) arrive and queue behind it.
    // Before the fix, shutdown_send() raised its flag at CALL time, so when the
    // completion resumed it found "shutdown requested" and an empty queue,
    // shut the send half down, and B was then written into a FIN'd socket:
    // the application read A, then EOF.
    asio::ip::tcp::acceptor acceptor(
        io_ctx_, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    asio::ip::tcp::socket app(io_ctx_);
    auto conn = std::make_shared<core::TcpConnection>(io_ctx_);
    std::promise<bool> accepted;
    acceptor.async_accept(app, [&accepted](const std::error_code& ec) { accepted.set_value(!ec); });
    std::promise<bool> connected;
    conn->async_connect(acceptor.local_endpoint(),
                        [&connected](const std::error_code& ec) { connected.set_value(!ec); });
    ASSERT_TRUE(accepted.get_future().get());
    ASSERT_TRUE(connected.get_future().get());

    // A crosses the (tiny) watermark, so its completion runs on_writable_.
    // The gate is shared-owned: the callback runs on an io thread and may
    // still be waking from the condition variable after this test body has
    // unwound (a fatal ASSERT), so the state it touches must outlive the
    // locals. The releaser opens the gate on scope exit for the same reason.
    conn->set_max_write_buffer_size(1024);
    struct Gate {
        std::mutex mutex;
        std::condition_variable cv;
        bool pinned = false;
        bool release = false;
    };
    auto gate = std::make_shared<Gate>();
    struct GateReleaser {
        std::shared_ptr<Gate> gate;
        ~GateReleaser() {
            {
                std::lock_guard<std::mutex> lock(gate->mutex);
                gate->release = true;
            }
            gate->cv.notify_all();
        }
    } releaser{gate};
    conn->set_on_writable([gate]() -> bool {
        std::unique_lock<std::mutex> lock(gate->mutex);
        gate->pinned = true;
        gate->cv.notify_all();
        gate->cv.wait(lock, [&] { return gate->release; });
        return true;
    });

    const std::vector<std::uint8_t> a(2048, 0xA1);
    const std::vector<std::uint8_t> b(212, 0xB2);
    (void)conn->write(a.data(), a.size());
    {
        std::unique_lock<std::mutex> lock(gate->mutex);
        ASSERT_TRUE(gate->cv.wait_for(lock, 5s, [&] { return gate->pinned; }))
            << "A's completion did not reach on_writable";
    }

    // The strand is pinned inside A's completion: the last DATA and the CLOSE
    // now queue behind it, in that order, as the tunnel delivers them.
    ASSERT_TRUE(conn->write(b.data(), b.size()));
    conn->shutdown_send();
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->release = true;
    }
    gate->cv.notify_all();

    // The application must read A and B, then EOF.
    std::vector<std::uint8_t> got;
    std::array<std::uint8_t, 8192> buf{};
    for (;;) {
        std::error_code read_ec;
        const std::size_t n = app.read_some(asio::buffer(buf), read_ec);
        if (n > 0) {
            got.insert(got.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
        }
        if (read_ec) {
            EXPECT_EQ(read_ec, asio::error::eof) << read_ec.message();
            break;
        }
    }
    std::vector<std::uint8_t> expected = a;
    expected.insert(expected.end(), b.begin(), b.end());
    EXPECT_EQ(got.size(), expected.size()) << "the FIN overtook a write that was already posted";
    EXPECT_EQ(got, expected);

    std::error_code ec;
    app.close(ec);
    conn->force_close();
}
