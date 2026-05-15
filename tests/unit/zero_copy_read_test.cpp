// Zero-copy inbound read-path tests.
//
// These tests pin the contract added by the read-path optimisation:
//
//   1. Functional: tunneled bytes arrive in order and intact when carried
//      end-to-end through the new OwnedBufferView path (deserialize -> Tunnel
//      reader -> TcpConnection::write(OwnedBufferView) -> loopback socket).
//
//   2. Buffer lifetime: a payload submitted on the Tox-thread side is freed
//      only AFTER the TCP async-write completion runs. A sentinel destructor
//      counter (held inside the shared payload buffer) catches any premature
//      release that would otherwise show up as a UAF under ASan.
//
//   3. Multiple concurrent tunnels never cross-contaminate buffers. Each
//      tunnel's payload arrives at its own TCP socket in the original byte
//      order with no interleaving.
//
// The strand discipline added in 0006fc1 (per-friend serial inbound packet
// handling) is preserved here implicitly: each test runs a single tunnel's
// frames through a single TunnelImpl, with TUNNEL_DATA delivery already
// serialised by `handle_frame`. The "concurrent tunnels" test ensures that
// even when several tunnels run in parallel, their owned buffers never alias
// or get mixed up — the shared_ptr lifetime model is what protects them.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <numeric>
#include <span>
#include <thread>
#include <vector>

#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/owned_buffer.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"

namespace toxtunnel::test {
namespace {

using namespace std::chrono_literals;

constexpr auto kTimeout = 5s;

// -----------------------------------------------------------------------------
// Lifetime sentinel: a vector<uint8_t> subclass whose destructor decrements
// a counter. Used to assert that the payload buffer survives until the async
// TCP write completes — not a byte earlier.
// -----------------------------------------------------------------------------

class SentinelVector : public std::vector<uint8_t> {
   public:
    SentinelVector(std::vector<uint8_t> data, std::atomic<int>* live_counter)
        : std::vector<uint8_t>(std::move(data)), live_counter_(live_counter) {
        live_counter_->fetch_add(1, std::memory_order_acq_rel);
    }

    ~SentinelVector() { live_counter_->fetch_sub(1, std::memory_order_acq_rel); }

    SentinelVector(const SentinelVector&) = delete;
    SentinelVector& operator=(const SentinelVector&) = delete;

   private:
    std::atomic<int>* live_counter_;
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// Build a deterministic byte pattern for verification: bytes[i] = (i + seed) & 0xFF.
std::vector<uint8_t> make_pattern(std::size_t size, uint8_t seed = 0) {
    std::vector<uint8_t> v(size);
    for (std::size_t i = 0; i < size; ++i) {
        v[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    }
    return v;
}

// Block-until-ready helper for std::future<T>.
template <typename T>
T wait_for(std::future<T>& fut) {
    EXPECT_EQ(fut.wait_for(kTimeout), std::future_status::ready);
    return fut.get();
}

// -----------------------------------------------------------------------------
// Test fixture: spins up a loopback TcpListener + TcpConnection pair and a
// TunnelImpl wired into the connection via the new owned-buffer callback.
// -----------------------------------------------------------------------------

class ZeroCopyReadTest : public ::testing::Test {
   protected:
    void SetUp() override {
        io_ = std::make_unique<core::IoContext>(2);
        io_->run();
    }

    void TearDown() override { io_->stop(); }

    asio::io_context& io_ctx() { return io_->get_io_context(); }

    std::unique_ptr<core::IoContext> io_;
};

// =============================================================================
// 1. Functional: deserialized TUNNEL_DATA flows through Tunnel and lands on
//    the TCP socket intact and in order.
// =============================================================================

TEST_F(ZeroCopyReadTest, TunneledBytesArriveIntactAndInOrder) {
    // --- Loopback listener + connected pair ------------------------------
    core::TcpListener listener(io_ctx(), uint16_t{0});
    const auto port = listener.port();
    ASSERT_NE(port, 0);

    std::promise<std::shared_ptr<core::TcpConnection>> server_promise;
    auto server_fut = server_promise.get_future();
    listener.start_accept([&](std::shared_ptr<core::TcpConnection> conn) {
        server_promise.set_value(std::move(conn));
    });

    auto client_conn = std::make_shared<core::TcpConnection>(io_ctx());
    std::promise<std::error_code> client_connect_promise;
    auto client_connect_fut = client_connect_promise.get_future();
    client_conn->async_connect(
        {asio::ip::make_address("127.0.0.1"), port},
        [&](const std::error_code& ec) { client_connect_promise.set_value(ec); });
    ASSERT_FALSE(wait_for(client_connect_fut));
    auto server_conn = wait_for(server_fut);
    ASSERT_TRUE(server_conn);

    // Collect bytes the listener side reads.
    std::mutex received_mu;
    std::vector<uint8_t> received;
    std::atomic<std::size_t> received_total{0};
    server_conn->set_on_data([&](const uint8_t* data, std::size_t length) {
        std::lock_guard<std::mutex> lock(received_mu);
        received.insert(received.end(), data, data + length);
        received_total.fetch_add(length, std::memory_order_release);
    });
    server_conn->start_read();

    // --- Tunnel wired to the client side --------------------------------
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx(), /*tunnel_id=*/7,
                                                       /*friend_number=*/42);
    tunnel->set_state(tunnel::Tunnel::State::Connected);
    tunnel->set_on_data_for_tcp_owned(
        [client_conn](core::OwnedBufferView buf) { client_conn->write(std::move(buf)); });

    // --- Drive a stream of TUNNEL_DATA frames through the tunnel --------
    constexpr std::size_t kFrameSize = 1300;  // below MTU ceiling
    constexpr int kFrames = 16;
    std::vector<uint8_t> expected;
    expected.reserve(kFrameSize * kFrames);

    for (int i = 0; i < kFrames; ++i) {
        auto pattern = make_pattern(kFrameSize, static_cast<uint8_t>(i));
        expected.insert(expected.end(), pattern.begin(), pattern.end());

        // Build a TUNNEL_DATA frame the same way the wire would: serialize
        // then deserialize, so payload_shared_ is populated as on the real
        // inbound path.
        auto built = tunnel::ProtocolFrame::make_tunnel_data(
            tunnel->tunnel_id(), std::span<const uint8_t>(pattern.data(), pattern.size()));
        auto wire = built.serialize();
        auto parsed = tunnel::ProtocolFrame::deserialize(wire);
        ASSERT_TRUE(parsed);
        tunnel->handle_frame(parsed.value());
    }

    // Wait until the server has read every byte we sent.
    auto deadline = std::chrono::steady_clock::now() + kTimeout;
    while (received_total.load(std::memory_order_acquire) < expected.size() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(2ms);
    }

    std::lock_guard<std::mutex> lock(received_mu);
    EXPECT_EQ(received.size(), expected.size());
    EXPECT_EQ(received, expected);

    client_conn->close();
    server_conn->close();
}

// =============================================================================
// 2. Buffer lifetime: the payload buffer must survive until the async TCP
//    write completes. We watch the live-instance counter via SentinelVector:
//    it must stay >0 after we drop our own reference, until the bytes are
//    fully written out.
// =============================================================================

TEST_F(ZeroCopyReadTest, OwnedBufferOutlivesAsyncWrite) {
    core::TcpListener listener(io_ctx(), uint16_t{0});
    const auto port = listener.port();

    std::promise<std::shared_ptr<core::TcpConnection>> server_promise;
    auto server_fut = server_promise.get_future();
    listener.start_accept([&](std::shared_ptr<core::TcpConnection> conn) {
        server_promise.set_value(std::move(conn));
    });

    auto client_conn = std::make_shared<core::TcpConnection>(io_ctx());
    std::promise<std::error_code> connect_promise;
    auto connect_fut = connect_promise.get_future();
    client_conn->async_connect({asio::ip::make_address("127.0.0.1"), port},
                               [&](const std::error_code& ec) { connect_promise.set_value(ec); });
    ASSERT_FALSE(wait_for(connect_fut));
    auto server_conn = wait_for(server_fut);

    // Sink for the receiving side.
    std::atomic<std::size_t> bytes_read{0};
    constexpr std::size_t kPayloadSize = 4096;
    server_conn->set_on_data([&](const uint8_t*, std::size_t length) {
        bytes_read.fetch_add(length, std::memory_order_release);
    });
    server_conn->start_read();

    std::atomic<int> live{0};

    // Build a shared payload wrapped in our sentinel type so the live counter
    // tracks exactly when the bytes are released.
    {
        auto payload = std::make_shared<SentinelVector>(make_pattern(kPayloadSize), &live);
        EXPECT_EQ(live.load(), 1);

        // Alias the SentinelVector as `const vector<uint8_t>` via aliasing
        // shared_ptr constructor — this is exactly how the production path
        // hands ownership over without a vector copy.
        std::shared_ptr<const std::vector<uint8_t>> alias(
            payload, static_cast<const std::vector<uint8_t>*>(payload.get()));

        core::OwnedBufferView view(alias);
        ASSERT_EQ(view.size(), kPayloadSize);

        // Hand to the TCP connection. The write queue must keep the buffer
        // alive until the async_write completes — even after we drop our
        // local references right after.
        ASSERT_TRUE(client_conn->write(std::move(view)));

        // alias goes out of scope here; only the write queue still holds the
        // SentinelVector. live should remain at 1 until the write completes.
        alias.reset();
        payload.reset();
    }

    // Pump the IO loop until the server has read everything. live must stay
    // strictly positive throughout — if it ever hits 0 before bytes_read
    // reaches kPayloadSize, the buffer was freed too early.
    auto deadline = std::chrono::steady_clock::now() + kTimeout;
    bool ever_zero_before_done = false;
    while (bytes_read.load(std::memory_order_acquire) < kPayloadSize &&
           std::chrono::steady_clock::now() < deadline) {
        if (live.load(std::memory_order_acquire) == 0) {
            ever_zero_before_done = true;
            break;
        }
        std::this_thread::sleep_for(1ms);
    }

    EXPECT_FALSE(ever_zero_before_done)
        << "SentinelVector was freed before async_write completed (UAF window)";
    EXPECT_EQ(bytes_read.load(), kPayloadSize);

    // After the write completes the queue should drop its ref → counter
    // returns to 0. Allow a brief grace period for the completion handler.
    auto cleanup_deadline = std::chrono::steady_clock::now() + 1s;
    while (live.load() != 0 && std::chrono::steady_clock::now() < cleanup_deadline) {
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(live.load(), 0) << "Buffer leaked past completion";

    client_conn->close();
    server_conn->close();
}

// =============================================================================
// 3. Concurrent tunnels: multiple TunnelImpls running in parallel must not
//    cross-contaminate their owned buffers. Each tunnel's bytes must arrive
//    at its own TCP socket, in order, with no interleaving.
// =============================================================================

TEST_F(ZeroCopyReadTest, ConcurrentTunnelsDoNotCrossContaminate) {
    constexpr int kTunnelCount = 4;
    constexpr std::size_t kPayloadSize = 2048;
    constexpr int kFramesPerTunnel = 8;

    struct PerTunnel {
        std::shared_ptr<core::TcpConnection> client;
        std::shared_ptr<core::TcpConnection> server;
        std::shared_ptr<tunnel::TunnelImpl> tunnel;
        std::vector<uint8_t> received;
        std::mutex received_mu;
        std::atomic<std::size_t> received_total{0};
        std::vector<uint8_t> expected;
    };

    std::vector<std::unique_ptr<PerTunnel>> tunnels;
    tunnels.reserve(kTunnelCount);

    core::TcpListener listener(io_ctx(), uint16_t{0});
    const auto port = listener.port();
    ASSERT_NE(port, 0);

    // Queue server-side accepted connections in FIFO order; the test pairs
    // them with client connects below by accept index.
    std::mutex accept_mu;
    std::vector<std::shared_ptr<core::TcpConnection>> accepted;
    listener.start_accept([&](std::shared_ptr<core::TcpConnection> conn) {
        std::lock_guard<std::mutex> lock(accept_mu);
        accepted.push_back(std::move(conn));
    });

    for (int t = 0; t < kTunnelCount; ++t) {
        auto entry = std::make_unique<PerTunnel>();
        entry->client = std::make_shared<core::TcpConnection>(io_ctx());

        std::promise<std::error_code> connect_promise;
        auto connect_fut = connect_promise.get_future();
        entry->client->async_connect(
            {asio::ip::make_address("127.0.0.1"), port},
            [&connect_promise](const std::error_code& ec) { connect_promise.set_value(ec); });
        ASSERT_FALSE(wait_for(connect_fut));

        // Match the just-connected client to the corresponding accepted
        // server side (FIFO by accept order).
        auto deadline = std::chrono::steady_clock::now() + kTimeout;
        while (true) {
            std::lock_guard<std::mutex> lock(accept_mu);
            if (static_cast<int>(accepted.size()) > t) {
                entry->server = accepted[t];
                break;
            }
            if (std::chrono::steady_clock::now() > deadline) {
                FAIL() << "Server side never accepted tunnel " << t;
            }
            std::this_thread::sleep_for(1ms);
        }

        auto* raw = entry.get();
        entry->server->set_on_data([raw](const uint8_t* d, std::size_t n) {
            std::lock_guard<std::mutex> lock(raw->received_mu);
            raw->received.insert(raw->received.end(), d, d + n);
            raw->received_total.fetch_add(n, std::memory_order_release);
        });
        entry->server->start_read();

        entry->tunnel = std::make_shared<tunnel::TunnelImpl>(
            io_ctx(), static_cast<uint16_t>(100 + t), static_cast<uint32_t>(t));
        entry->tunnel->set_state(tunnel::Tunnel::State::Connected);

        auto client = entry->client;
        entry->tunnel->set_on_data_for_tcp_owned(
            [client](core::OwnedBufferView buf) { client->write(std::move(buf)); });

        tunnels.push_back(std::move(entry));
    }

    // Drive frames in interleaved fashion across all tunnels from several
    // sender threads — this stresses the shared_ptr-based ownership against
    // any potential cross-tunnel aliasing bugs.
    std::vector<std::thread> senders;
    senders.reserve(kTunnelCount);
    for (int t = 0; t < kTunnelCount; ++t) {
        senders.emplace_back([t, &tunnels]() {
            auto& entry = *tunnels[t];
            for (int f = 0; f < kFramesPerTunnel; ++f) {
                auto pattern = make_pattern(kPayloadSize, static_cast<uint8_t>(t * 31 + f * 7));
                entry.expected.insert(entry.expected.end(), pattern.begin(), pattern.end());

                auto built = tunnel::ProtocolFrame::make_tunnel_data(
                    entry.tunnel->tunnel_id(),
                    std::span<const uint8_t>(pattern.data(), pattern.size()));
                auto wire = built.serialize();
                auto parsed = tunnel::ProtocolFrame::deserialize(wire);
                ASSERT_TRUE(parsed);
                entry.tunnel->handle_frame(parsed.value());
            }
        });
    }
    for (auto& s : senders) s.join();

    // Wait until each tunnel has received its full expected stream.
    auto deadline = std::chrono::steady_clock::now() + kTimeout;
    auto all_done = [&] {
        for (auto& e : tunnels) {
            if (e->received_total.load(std::memory_order_acquire) < e->expected.size()) {
                return false;
            }
        }
        return true;
    };
    while (!all_done() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(2ms);
    }

    for (int t = 0; t < kTunnelCount; ++t) {
        auto& e = *tunnels[t];
        std::lock_guard<std::mutex> lock(e.received_mu);
        EXPECT_EQ(e.received.size(), e.expected.size()) << "Tunnel " << t << " short read";
        EXPECT_EQ(e.received, e.expected) << "Tunnel " << t << " cross-contaminated";
    }

    for (auto& e : tunnels) {
        e->client->close();
        e->server->close();
    }
}

// =============================================================================
// 4. ProtocolFrame::as_tunnel_data_owned() returns the SAME shared buffer for
//    deserialized frames (no second copy).
// =============================================================================

TEST(ZeroCopyProtocol, DeserializedFrameSharesPayloadBuffer) {
    auto payload = make_pattern(1024);
    auto built = tunnel::ProtocolFrame::make_tunnel_data(
        /*tunnel_id=*/1, std::span<const uint8_t>(payload.data(), payload.size()));
    auto wire = built.serialize();
    auto parsed = tunnel::ProtocolFrame::deserialize(wire);
    ASSERT_TRUE(parsed);

    // Capture the underlying shared_ptr on two consecutive calls. They must
    // refer to the same managed object — no copy is made on the hot read
    // path.
    auto view1 = parsed.value().as_tunnel_data_owned();
    auto view2 = parsed.value().as_tunnel_data_owned();
    ASSERT_FALSE(view1.empty());
    ASSERT_FALSE(view2.empty());
    EXPECT_EQ(view1.buffer().get(), view2.buffer().get());
    EXPECT_EQ(view1.size(), payload.size());

    // Round-trip the bytes.
    std::vector<uint8_t> got(view1.data().begin(), view1.data().end());
    EXPECT_EQ(got, payload);
}

}  // namespace
}  // namespace toxtunnel::test
