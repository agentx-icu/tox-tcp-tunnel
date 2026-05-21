// Integration tests for TcpListener + TcpConnection over actual loopback networking.
//
// These tests exercise the real async TCP path: listener accepts connections,
// clients connect, data is transferred bidirectionally, and connections are
// closed gracefully.  All I/O runs on the IoContext thread pool while the test
// thread synchronises via std::promise / std::future with timeouts.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <numeric>
#include <vector>

#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/core/tcp_listener.hpp"

namespace toxtunnel::integration {
namespace {

using namespace std::chrono_literals;

// Default timeout for all futures -- generous to avoid flakiness on slow CI.
constexpr auto kTimeout = 5s;

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class TcpLoopbackTest : public ::testing::Test {
   protected:
    void SetUp() override {
        io_ctx_ = std::make_unique<core::IoContext>(2);
        io_ctx_->run();
    }

    void TearDown() override { io_ctx_->stop(); }

    /// Return the underlying asio::io_context for constructing TCP objects.
    asio::io_context& io() { return io_ctx_->get_io_context(); }

    /// Create a TcpListener on an OS-assigned port (port 0) and return it.
    /// The actual port is available via listener->port() after construction.
    std::unique_ptr<core::TcpListener> make_listener() {
        return std::make_unique<core::TcpListener>(io(), std::uint16_t{0});
    }

    /// Build a loopback endpoint targeting the given port.
    static asio::ip::tcp::endpoint loopback(std::uint16_t port) {
        return {asio::ip::make_address("127.0.0.1"), port};
    }

    std::unique_ptr<core::IoContext> io_ctx_;
};

// ===========================================================================
// 1. ListenerAcceptsConnection
// ===========================================================================

TEST_F(TcpLoopbackTest, ListenerAcceptsConnection) {
    auto listener = make_listener();
    const auto port = listener->port();
    ASSERT_NE(port, 0);

    // Promise fulfilled when the server sees an accepted connection.
    std::promise<std::shared_ptr<core::TcpConnection>> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();

    listener->start_accept([&server_conn_promise](std::shared_ptr<core::TcpConnection> conn) {
        server_conn_promise.set_value(std::move(conn));
    });

    // Client connects.
    auto client = std::make_shared<core::TcpConnection>(io());

    std::promise<std::error_code> connect_promise;
    auto connect_future = connect_promise.get_future();

    client->async_connect(loopback(port), [&connect_promise](const std::error_code& ec) {
        connect_promise.set_value(ec);
    });

    // Wait for the client connect to complete.
    ASSERT_EQ(connect_future.wait_for(kTimeout), std::future_status::ready);
    const auto ec = connect_future.get();
    EXPECT_FALSE(ec) << "connect error: " << ec.message();
    EXPECT_TRUE(client->is_connected());

    // Wait for the server side to see the connection.
    ASSERT_EQ(server_conn_future.wait_for(kTimeout), std::future_status::ready);
    auto server_conn = server_conn_future.get();
    ASSERT_NE(server_conn, nullptr);
    EXPECT_TRUE(server_conn->is_connected());

    // Clean up.
    client->close();
    server_conn->close();
    listener->stop();
}

// ===========================================================================
// 2. BidirectionalDataTransfer
// ===========================================================================

TEST_F(TcpLoopbackTest, BidirectionalDataTransfer) {
    auto listener = make_listener();
    const auto port = listener->port();

    // -- Accept --
    std::promise<std::shared_ptr<core::TcpConnection>> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();

    listener->start_accept([&server_conn_promise](std::shared_ptr<core::TcpConnection> conn) {
        server_conn_promise.set_value(std::move(conn));
    });

    // -- Client connect --
    auto client = std::make_shared<core::TcpConnection>(io());

    std::promise<void> connected_promise;
    auto connected_future = connected_promise.get_future();

    client->async_connect(loopback(port), [&connected_promise](const std::error_code& ec) {
        ASSERT_FALSE(ec) << ec.message();
        connected_promise.set_value();
    });

    ASSERT_EQ(connected_future.wait_for(kTimeout), std::future_status::ready);
    connected_future.get();

    ASSERT_EQ(server_conn_future.wait_for(kTimeout), std::future_status::ready);
    auto server = server_conn_future.get();

    // -- Prepare data callbacks --

    // Client -> Server
    const std::vector<uint8_t> c2s_payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    std::promise<std::vector<uint8_t>> server_data_promise;
    auto server_data_future = server_data_promise.get_future();

    {
        auto received = std::make_shared<std::vector<uint8_t>>();
        auto target_size = c2s_payload.size();
        auto promise_ptr =
            std::make_shared<std::promise<std::vector<uint8_t>>>(std::move(server_data_promise));

        server->set_on_data(
            [received, target_size, promise_ptr](const uint8_t* data, std::size_t len) {
                received->insert(received->end(), data, data + len);
                if (received->size() >= target_size) {
                    promise_ptr->set_value(*received);
                }
            });
    }

    // Server -> Client
    const std::vector<uint8_t> s2c_payload = {0xCA, 0xFE, 0xBA, 0xBE};
    std::promise<std::vector<uint8_t>> client_data_promise;
    auto client_data_future = client_data_promise.get_future();

    {
        auto received = std::make_shared<std::vector<uint8_t>>();
        auto target_size = s2c_payload.size();
        auto promise_ptr =
            std::make_shared<std::promise<std::vector<uint8_t>>>(std::move(client_data_promise));

        client->set_on_data(
            [received, target_size, promise_ptr](const uint8_t* data, std::size_t len) {
                received->insert(received->end(), data, data + len);
                if (received->size() >= target_size) {
                    promise_ptr->set_value(*received);
                }
            });
    }

    // Start reading on both sides.
    server->start_read();
    client->start_read();

    // -- Send data --
    EXPECT_TRUE(client->write(c2s_payload.data(), c2s_payload.size()));
    EXPECT_TRUE(server->write(s2c_payload.data(), s2c_payload.size()));

    // -- Verify --
    ASSERT_EQ(server_data_future.wait_for(kTimeout), std::future_status::ready);
    auto received_by_server = server_data_future.get();
    EXPECT_EQ(received_by_server, c2s_payload);

    ASSERT_EQ(client_data_future.wait_for(kTimeout), std::future_status::ready);
    auto received_by_client = client_data_future.get();
    EXPECT_EQ(received_by_client, s2c_payload);

    // Clean up.
    client->close();
    server->close();
    listener->stop();
}

// ===========================================================================
// 3. MultipleConnections
// ===========================================================================

TEST_F(TcpLoopbackTest, MultipleConnections) {
    auto listener = make_listener();
    const auto port = listener->port();

    constexpr std::size_t kNumClients = 5;

    // Collect accepted server-side connections.
    std::mutex server_mu;
    std::vector<std::shared_ptr<core::TcpConnection>> server_conns;
    std::promise<void> all_accepted_promise;
    auto all_accepted_future = all_accepted_promise.get_future();
    bool all_accepted_notified = false;

    listener->start_accept([&server_mu, &server_conns, &all_accepted_promise,
                            &all_accepted_notified](std::shared_ptr<core::TcpConnection> conn) {
        std::lock_guard lock(server_mu);
        server_conns.push_back(std::move(conn));
        if (server_conns.size() == kNumClients && !all_accepted_notified) {
            all_accepted_notified = true;
            all_accepted_promise.set_value();
        }
    });

    // Connect N clients.
    std::vector<std::shared_ptr<core::TcpConnection>> clients;
    std::vector<std::future<std::error_code>> connect_futures;

    for (std::size_t i = 0; i < kNumClients; ++i) {
        auto client = std::make_shared<core::TcpConnection>(io());
        auto promise = std::make_shared<std::promise<std::error_code>>();
        connect_futures.push_back(promise->get_future());

        client->async_connect(loopback(port),
                              [promise](const std::error_code& ec) { promise->set_value(ec); });

        clients.push_back(std::move(client));
    }

    // All clients should connect successfully.
    for (std::size_t i = 0; i < kNumClients; ++i) {
        ASSERT_EQ(connect_futures[i].wait_for(kTimeout), std::future_status::ready)
            << "client " << i << " timed out";
        const auto ec = connect_futures[i].get();
        EXPECT_FALSE(ec) << "client " << i << ": " << ec.message();
        EXPECT_TRUE(clients[i]->is_connected());
    }

    // Server should have accepted all.
    ASSERT_EQ(all_accepted_future.wait_for(kTimeout), std::future_status::ready);
    {
        std::lock_guard lock(server_mu);
        ASSERT_EQ(server_conns.size(), kNumClients);
    }

    // Verify each pair works independently by sending a unique byte and
    // checking the server receives it.
    for (std::size_t i = 0; i < kNumClients; ++i) {
        auto promise_ptr = std::make_shared<std::promise<uint8_t>>();
        auto data_future = promise_ptr->get_future();

        std::shared_ptr<core::TcpConnection> srv;
        {
            std::lock_guard lock(server_mu);
            srv = server_conns[i];
        }

        srv->set_on_data([promise_ptr](const uint8_t* data, std::size_t len) {
            if (len > 0) {
                promise_ptr->set_value(data[0]);
            }
        });
        srv->start_read();

        const auto tag = static_cast<uint8_t>(i);
        EXPECT_TRUE(clients[i]->write(&tag, 1));

        ASSERT_EQ(data_future.wait_for(kTimeout), std::future_status::ready)
            << "data on client " << i;
        EXPECT_EQ(data_future.get(), tag);
    }

    // Clean up.
    for (auto& c : clients) {
        c->close();
    }
    {
        std::lock_guard lock(server_mu);
        for (auto& s : server_conns) {
            s->close();
        }
    }
    listener->stop();
}

// ===========================================================================
// 4. GracefulClose
// ===========================================================================

TEST_F(TcpLoopbackTest, GracefulClose) {
    auto listener = make_listener();
    const auto port = listener->port();

    std::promise<std::shared_ptr<core::TcpConnection>> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();

    listener->start_accept([&server_conn_promise](std::shared_ptr<core::TcpConnection> conn) {
        server_conn_promise.set_value(std::move(conn));
    });

    // Client connects.
    auto client = std::make_shared<core::TcpConnection>(io());

    std::promise<void> connected_promise;
    auto connected_future = connected_promise.get_future();

    client->async_connect(loopback(port), [&connected_promise](const std::error_code& ec) {
        ASSERT_FALSE(ec) << ec.message();
        connected_promise.set_value();
    });

    ASSERT_EQ(connected_future.wait_for(kTimeout), std::future_status::ready);
    connected_future.get();

    ASSERT_EQ(server_conn_future.wait_for(kTimeout), std::future_status::ready);
    auto server = server_conn_future.get();

    // Send some data from client to server before closing.
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03};

    std::promise<std::vector<uint8_t>> data_promise;
    auto data_future = data_promise.get_future();

    {
        auto received = std::make_shared<std::vector<uint8_t>>();
        auto target_size = payload.size();
        auto promise_ptr =
            std::make_shared<std::promise<std::vector<uint8_t>>>(std::move(data_promise));

        server->set_on_data(
            [received, target_size, promise_ptr](const uint8_t* data, std::size_t len) {
                received->insert(received->end(), data, data + len);
                if (received->size() >= target_size) {
                    promise_ptr->set_value(*received);
                }
            });
    }

    // Server disconnect notification.
    std::promise<std::error_code> server_disconnect_promise;
    auto server_disconnect_future = server_disconnect_promise.get_future();

    server->set_on_disconnect([&server_disconnect_promise](const std::error_code& ec) {
        server_disconnect_promise.set_value(ec);
    });

    server->start_read();

    EXPECT_TRUE(client->write(payload.data(), payload.size()));

    // Verify data arrived.
    ASSERT_EQ(data_future.wait_for(kTimeout), std::future_status::ready);
    EXPECT_EQ(data_future.get(), payload);

    // Close the client side.
    client->close();

    // The server side should observe a disconnect.
    ASSERT_EQ(server_disconnect_future.wait_for(kTimeout), std::future_status::ready);
    // We do not check the specific error code -- it may be eof, connection_reset
    // or empty depending on timing.  The key assertion is that the callback fires.

    EXPECT_FALSE(server->is_connected());

    listener->stop();
}

// ===========================================================================
// 5. LargeDataTransfer
// ===========================================================================

TEST_F(TcpLoopbackTest, LargeDataTransfer) {
    auto listener = make_listener();
    const auto port = listener->port();

    std::promise<std::shared_ptr<core::TcpConnection>> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();

    listener->start_accept([&server_conn_promise](std::shared_ptr<core::TcpConnection> conn) {
        server_conn_promise.set_value(std::move(conn));
    });

    auto client = std::make_shared<core::TcpConnection>(io());

    // Allow a large write buffer so the 1 MiB payload is not rejected.
    client->set_max_write_buffer_size(2 * 1024 * 1024);

    std::promise<void> connected_promise;
    auto connected_future = connected_promise.get_future();

    client->async_connect(loopback(port), [&connected_promise](const std::error_code& ec) {
        ASSERT_FALSE(ec) << ec.message();
        connected_promise.set_value();
    });

    ASSERT_EQ(connected_future.wait_for(kTimeout), std::future_status::ready);
    connected_future.get();

    ASSERT_EQ(server_conn_future.wait_for(kTimeout), std::future_status::ready);
    auto server = server_conn_future.get();

    // Build a 1 MiB payload with a recognisable pattern (0x00, 0x01, ..., 0xFF, 0x00, ...).
    constexpr std::size_t kPayloadSize = 1024 * 1024;  // 1 MiB
    std::vector<uint8_t> payload(kPayloadSize);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    // Server accumulates received data.
    auto received = std::make_shared<std::vector<uint8_t>>();
    received->reserve(kPayloadSize);

    std::promise<void> all_received_promise;
    auto all_received_future = all_received_promise.get_future();

    {
        auto mu = std::make_shared<std::mutex>();
        auto promise_ptr = std::make_shared<std::promise<void>>(std::move(all_received_promise));
        bool notified = false;
        auto notified_ptr = std::make_shared<bool>(notified);

        server->set_on_data(
            [received, mu, promise_ptr, notified_ptr](const uint8_t* data, std::size_t len) {
                std::lock_guard lock(*mu);
                received->insert(received->end(), data, data + len);
                if (received->size() >= kPayloadSize && !*notified_ptr) {
                    *notified_ptr = true;
                    promise_ptr->set_value();
                }
            });
    }

    server->start_read();

    // Send the entire payload.  The write may be internally split into
    // multiple async_write operations -- that is fine.
    EXPECT_TRUE(client->write(payload.data(), payload.size()));

    // Wait for all data to arrive.
    ASSERT_EQ(all_received_future.wait_for(kTimeout), std::future_status::ready);

    ASSERT_EQ(received->size(), kPayloadSize);
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), received->begin()));

    // Clean up.
    client->close();
    server->close();
    listener->stop();
}

// ===========================================================================
// 6. PauseReadHaltsDataDelivery (C-18 — T5 backpressure)
// ===========================================================================

// C-18 / 2026-05-20 finding: TunnelImpl now calls TcpConnection::pause_read
// when its send window is full, and resume_read when an ACK drains it.
//
// pause_read is *soft* backpressure — it stops posting new
// async_read_some calls. An in-flight read completes and delivers
// whatever it already had, then the loop stops. The kernel receive
// buffer then fills, the TCP receive window collapses, and the remote
// peer is throttled at the protocol level. This test exercises the
// end-to-end shape: pause + bombard with bulk data + expect the
// receiver to stop well short of the sent volume, then resume and
// expect the rest.
TEST_F(TcpLoopbackTest, PauseReadHaltsBulkDeliveryUntilResume) {
    auto listener = make_listener();
    const auto port = listener->port();

    std::promise<std::shared_ptr<core::TcpConnection>> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();
    listener->start_accept([&server_conn_promise](std::shared_ptr<core::TcpConnection> conn) {
        server_conn_promise.set_value(std::move(conn));
    });

    auto client = std::make_shared<core::TcpConnection>(io());
    client->set_max_write_buffer_size(8 * 1024 * 1024);  // permissive client side

    std::promise<void> connected_promise;
    auto connected_future = connected_promise.get_future();
    client->async_connect(loopback(port), [&connected_promise](const std::error_code& ec) {
        ASSERT_FALSE(ec) << ec.message();
        connected_promise.set_value();
    });
    ASSERT_EQ(connected_future.wait_for(kTimeout), std::future_status::ready);
    connected_future.get();
    ASSERT_EQ(server_conn_future.wait_for(kTimeout), std::future_status::ready);
    auto server = server_conn_future.get();

    std::atomic<std::size_t> received_bytes{0};
    server->set_on_data(
        [&received_bytes](const uint8_t* /*data*/, std::size_t len) { received_bytes += len; });

    // Pause BEFORE start_read so no read is in flight at the moment we
    // pause — guarantees nothing surfaces before the resume.
    server->pause_read();
    EXPECT_TRUE(server->is_read_paused());
    server->start_read();

    constexpr std::size_t kBulkSize = 4 * 1024 * 1024;  // 4 MiB
    std::vector<uint8_t> payload(kBulkSize, 0xAB);
    EXPECT_TRUE(client->write(payload.data(), payload.size()));

    // Give the kernel time to drain whatever it can into its receive
    // buffer; with no reader, that bounds at the SO_RCVBUF size
    // (typically 256 KiB-2 MiB on Linux/macOS — comfortably below 4 MiB).
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const auto leaked = received_bytes.load();
    EXPECT_LT(leaked, kBulkSize)
        << "all bulk data delivered while paused — pause_read had no effect";

    // Resume → the rest must surface.
    server->resume_read();
    EXPECT_FALSE(server->is_read_paused());

    const auto deadline = std::chrono::steady_clock::now() + kTimeout;
    while (received_bytes.load() < kBulkSize && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_EQ(received_bytes.load(), kBulkSize);

    client->close();
    server->close();
    listener->stop();
}

}  // namespace
}  // namespace toxtunnel::integration
