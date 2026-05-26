#include "toxtunnel/app/socks5_listener.hpp"

#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/core/tcp_connection.hpp"

using namespace toxtunnel;
using namespace toxtunnel::app;
using namespace std::chrono_literals;

namespace {

// Convenience helper to drain whatever the server has written to a blocking
// asio socket without hanging if there's nothing yet.
std::vector<uint8_t> read_some(asio::ip::tcp::socket& sock, std::size_t want_at_least,
                               std::chrono::milliseconds timeout = 500ms) {
    std::vector<uint8_t> out;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (out.size() < want_at_least && std::chrono::steady_clock::now() < deadline) {
        uint8_t buf[256];
        sock.non_blocking(true);
        asio::error_code ec;
        const auto n = sock.read_some(asio::buffer(buf), ec);
        if (!ec && n > 0) {
            out.insert(out.end(), buf, buf + n);
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Pure-parser tests (no sockets needed)
// ---------------------------------------------------------------------------

TEST(Socks5GreetingTest, AcceptsValidNoAuthGreeting) {
    const uint8_t bytes[] = {0x05, 0x01, 0x00};
    auto r = parse_socks5_greeting(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    ASSERT_EQ(r.methods.size(), 1u);
    EXPECT_EQ(r.methods[0], 0x00);
    EXPECT_EQ(r.consumed, 3u);
}

TEST(Socks5GreetingTest, AcceptsMultipleMethods) {
    const uint8_t bytes[] = {0x05, 0x02, 0x00, 0x02};
    auto r = parse_socks5_greeting(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.methods.size(), 2u);
}

TEST(Socks5GreetingTest, NeedsMoreForTruncatedInput) {
    const uint8_t bytes[] = {0x05, 0x03, 0x00, 0x02};
    auto r = parse_socks5_greeting(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::NeedMore);
}

TEST(Socks5GreetingTest, RejectsWrongVersion) {
    const uint8_t bytes[] = {0x04, 0x01, 0x00};
    auto r = parse_socks5_greeting(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
}

TEST(Socks5GreetingTest, RejectsZeroMethodCount) {
    const uint8_t bytes[] = {0x05, 0x00};
    auto r = parse_socks5_greeting(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
}

TEST(Socks5RequestTest, ParsesIPv4Connect) {
    const uint8_t bytes[] = {0x05, 0x01, 0x00, 0x01, 192, 168, 1, 42, 0x01, 0xBB};
    auto r = parse_socks5_request(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.atyp, socks5::kAtypIPv4);
    EXPECT_EQ(r.host, "192.168.1.42");
    EXPECT_EQ(r.port, 443);
    EXPECT_EQ(r.consumed, sizeof(bytes));
}

TEST(Socks5RequestTest, ParsesDomainConnect) {
    const char host[] = "example.com";
    std::vector<uint8_t> bytes = {0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(sizeof(host) - 1)};
    bytes.insert(bytes.end(), host, host + sizeof(host) - 1);
    bytes.push_back(0x00);
    bytes.push_back(0x50);
    auto r = parse_socks5_request(bytes.data(), bytes.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.atyp, socks5::kAtypDomain);
    EXPECT_EQ(r.host, "example.com");
    EXPECT_EQ(r.port, 80);
}

TEST(Socks5RequestTest, ParsesIPv6Connect) {
    std::vector<uint8_t> bytes = {0x05, 0x01, 0x00, 0x04};
    // ::1
    for (int i = 0; i < 15; ++i) {
        bytes.push_back(0x00);
    }
    bytes.push_back(0x01);
    bytes.push_back(0x01);
    bytes.push_back(0xBB);
    auto r = parse_socks5_request(bytes.data(), bytes.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.atyp, socks5::kAtypIPv6);
    EXPECT_EQ(r.port, 443);
    asio::error_code ec;
    auto addr = asio::ip::make_address(r.host, ec);
    EXPECT_FALSE(ec);
    EXPECT_TRUE(addr.is_v6());
}

TEST(Socks5RequestTest, RejectsBindCommand) {
    const uint8_t bytes[] = {0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    auto r = parse_socks5_request(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
    EXPECT_EQ(r.reply_code, socks5::kReplyCmdNotSupported);
}

TEST(Socks5RequestTest, RejectsUdpAssociateCommand) {
    const uint8_t bytes[] = {0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    auto r = parse_socks5_request(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
    EXPECT_EQ(r.reply_code, socks5::kReplyCmdNotSupported);
}

TEST(Socks5RequestTest, RejectsUnknownAddressType) {
    const uint8_t bytes[] = {0x05, 0x01, 0x00, 0x09};
    auto r = parse_socks5_request(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
    EXPECT_EQ(r.reply_code, socks5::kReplyAtypNotSupported);
}

TEST(Socks5RequestTest, NeedsMoreForTruncatedDomain) {
    const uint8_t bytes[] = {0x05, 0x01, 0x00, 0x03, 0x05, 'a', 'b'};
    auto r = parse_socks5_request(bytes, sizeof(bytes));
    EXPECT_EQ(r.status, Socks5ParseStatus::NeedMore);
}

TEST(Socks5ReplyTest, EncodesSuccess) {
    auto r = encode_socks5_reply(socks5::kReplySuccess);
    ASSERT_EQ(r.size(), 10u);
    EXPECT_EQ(r[0], socks5::kVersion);
    EXPECT_EQ(r[1], socks5::kReplySuccess);
    EXPECT_EQ(r[2], 0x00);
    EXPECT_EQ(r[3], socks5::kAtypIPv4);
}

TEST(HttpConnectTest, ParsesValidRequest) {
    const std::string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.host, "example.com");
    EXPECT_EQ(r.port, 443);
    EXPECT_EQ(r.consumed, req.size());
}

TEST(HttpConnectTest, ParsesBracketedIPv6) {
    const std::string req = "CONNECT [::1]:8443 HTTP/1.1\r\n\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Ok);
    EXPECT_EQ(r.host, "::1");
    EXPECT_EQ(r.port, 8443);
}

TEST(HttpConnectTest, NeedsMoreUntilHeadersEnd) {
    const std::string req = "CONNECT host:443 HTTP/1.1\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::NeedMore);
}

TEST(HttpConnectTest, RejectsNonConnectMethod) {
    const std::string req = "GET / HTTP/1.1\r\nHost: foo\r\n\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
}

TEST(HttpConnectTest, RejectsMissingPort) {
    const std::string req = "CONNECT example.com HTTP/1.1\r\n\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
}

TEST(HttpConnectTest, RejectsBadHttpVersionToken) {
    const std::string req = "CONNECT example.com:443 GIBBERISH\r\n\r\n";
    auto r = parse_http_connect(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_EQ(r.status, Socks5ParseStatus::Malformed);
}

// ---------------------------------------------------------------------------
// Listener lifecycle + end-to-end handshake against a real localhost socket
// ---------------------------------------------------------------------------

class Socks5ListenerLifecycleTest : public ::testing::Test {
   protected:
    void SetUp() override {
        listener_ = std::make_shared<Socks5Listener>();
        work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            asio::make_work_guard(io_ctx_));
        worker_ = std::thread([this] { io_ctx_.run(); });
    }

    void TearDown() override {
        listener_->stop();
        listener_.reset();
        if (work_guard_) {
            work_guard_->reset();
        }
        io_ctx_.stop();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    void start_listener(OpenTunnelFn fn) {
        auto err = listener_->start(io_ctx_, "127.0.0.1", 0, std::move(fn));
        ASSERT_TRUE(err.empty()) << err;
    }

    asio::io_context io_ctx_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work_guard_;
    std::thread worker_;
    std::shared_ptr<Socks5Listener> listener_;
};

TEST_F(Socks5ListenerLifecycleTest, StartsBindsRandomPort) {
    start_listener([](auto, auto, auto, auto, auto) {});
    EXPECT_TRUE(listener_->is_running());
    EXPECT_GT(listener_->bound_port(), 0);
}

TEST_F(Socks5ListenerLifecycleTest, StopIsIdempotent) {
    start_listener([](auto, auto, auto, auto, auto) {});
    listener_->stop();
    EXPECT_FALSE(listener_->is_running());
    listener_->stop();  // Second call is a no-op.
    EXPECT_FALSE(listener_->is_running());
}

// C-7 / 2026-05-20 finding: Socks5Listener::start() must refuse a
// non-loopback bind, not delegate that check to the upstream config
// parser. SOCKS5 v1 has no authentication; an accidental 0.0.0.0 bind
// is an open proxy on the LAN.
TEST_F(Socks5ListenerLifecycleTest, RejectsNonLoopbackBind) {
    auto err = listener_->start(io_ctx_, "0.0.0.0", 0, [](auto, auto, auto, auto, auto) {});
    EXPECT_FALSE(err.empty()) << "start() should refuse non-loopback bind";
    EXPECT_NE(err.find("non-loopback"), std::string::npos) << err;
    EXPECT_FALSE(listener_->is_running());
}

TEST_F(Socks5ListenerLifecycleTest, ParsesSocks5HandshakeAndInvokesOpenTunnel) {
    std::atomic<bool> got_dest{false};
    std::string got_host;
    uint16_t got_port = 0;
    std::function<void(bool)> captured_reply_cb;

    start_listener([&](std::shared_ptr<core::TcpConnection> /*conn*/, std::string host,
                       uint16_t port, std::vector<uint8_t> /*initial_payload*/,
                       std::function<void(bool)> reply_cb) {
        got_host = std::move(host);
        got_port = port;
        captured_reply_cb = std::move(reply_cb);
        got_dest.store(true);
    });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const uint8_t greeting[] = {0x05, 0x01, 0x00};
    asio::write(sock, asio::buffer(greeting, sizeof(greeting)));

    auto greeting_reply = read_some(sock, 2);
    ASSERT_EQ(greeting_reply.size(), 2u);
    EXPECT_EQ(greeting_reply[0], 0x05);
    EXPECT_EQ(greeting_reply[1], 0x00);

    const uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x01, 0xBB};
    asio::write(sock, asio::buffer(req, sizeof(req)));

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!got_dest.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(got_dest.load());
    EXPECT_EQ(got_host, "10.0.0.7");
    EXPECT_EQ(got_port, 443);

    if (captured_reply_cb) {
        captured_reply_cb(true);
    }
    auto reply = read_some(sock, 10);
    ASSERT_EQ(reply.size(), 10u);
    EXPECT_EQ(reply[0], 0x05);
    EXPECT_EQ(reply[1], socks5::kReplySuccess);
}

TEST_F(Socks5ListenerLifecycleTest, RejectsClientThatOffersNoNoAuth) {
    std::atomic<bool> got_dest{false};
    start_listener([&](std::shared_ptr<core::TcpConnection>, std::string, uint16_t,
                       std::vector<uint8_t>, std::function<void(bool)>) { got_dest.store(true); });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const uint8_t greeting[] = {0x05, 0x01, 0x02};  // method 0x02 (GSSAPI), not 0x00
    asio::write(sock, asio::buffer(greeting, sizeof(greeting)));

    auto reply = read_some(sock, 2);
    ASSERT_EQ(reply.size(), 2u);
    EXPECT_EQ(reply[0], 0x05);
    EXPECT_EQ(reply[1], socks5::kAuthNoAcceptable);
    EXPECT_FALSE(got_dest.load());
}

TEST_F(Socks5ListenerLifecycleTest, RejectsBindCommandAtRequest) {
    std::atomic<bool> got_dest{false};
    start_listener([&](std::shared_ptr<core::TcpConnection>, std::string, uint16_t,
                       std::vector<uint8_t>, std::function<void(bool)>) { got_dest.store(true); });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const uint8_t greeting[] = {0x05, 0x01, 0x00};
    asio::write(sock, asio::buffer(greeting, sizeof(greeting)));
    (void)read_some(sock, 2);

    const uint8_t req[] = {0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    asio::write(sock, asio::buffer(req, sizeof(req)));

    auto reply = read_some(sock, 10);
    ASSERT_EQ(reply.size(), 10u);
    EXPECT_EQ(reply[0], 0x05);
    EXPECT_EQ(reply[1], socks5::kReplyCmdNotSupported);
    EXPECT_FALSE(got_dest.load());
}

TEST_F(Socks5ListenerLifecycleTest, ParsesHttpConnectAndInvokesOpenTunnel) {
    std::atomic<bool> got_dest{false};
    std::string got_host;
    uint16_t got_port = 0;
    std::function<void(bool)> captured_reply_cb;

    start_listener([&](std::shared_ptr<core::TcpConnection> /*conn*/, std::string host,
                       uint16_t port, std::vector<uint8_t> /*initial_payload*/,
                       std::function<void(bool)> reply_cb) {
        got_host = std::move(host);
        got_port = port;
        captured_reply_cb = std::move(reply_cb);
        got_dest.store(true);
    });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const std::string req = "CONNECT host.example:8080 HTTP/1.1\r\nHost: host.example:8080\r\n\r\n";
    asio::write(sock, asio::buffer(req));

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!got_dest.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(got_dest.load());
    EXPECT_EQ(got_host, "host.example");
    EXPECT_EQ(got_port, 8080);

    if (captured_reply_cb) {
        captured_reply_cb(true);
    }
    auto reply = read_some(sock, 17);
    ASSERT_GE(reply.size(), 12u);
    const std::string reply_str(reply.begin(), reply.end());
    EXPECT_NE(reply_str.find("HTTP/1.1 200"), std::string::npos);
}

TEST_F(Socks5ListenerLifecycleTest, HttpConnectReturns502OnTunnelFailure) {
    std::function<void(bool)> captured_reply_cb;
    start_listener(
        [&](std::shared_ptr<core::TcpConnection>, std::string, uint16_t, std::vector<uint8_t>,
            std::function<void(bool)> reply_cb) { captured_reply_cb = std::move(reply_cb); });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const std::string req = "CONNECT host.example:80 HTTP/1.1\r\n\r\n";
    asio::write(sock, asio::buffer(req));

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!captured_reply_cb && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(captured_reply_cb);
    captured_reply_cb(false);

    auto reply = read_some(sock, 12);
    const std::string reply_str(reply.begin(), reply.end());
    EXPECT_NE(reply_str.find("HTTP/1.1 502"), std::string::npos);
}

// Regression: a SOCKS5 client that coalesces the CONNECT request with the
// first stream bytes in a single TCP write must not lose those bytes.
TEST_F(Socks5ListenerLifecycleTest, Socks5HandoffForwardsPipelinedPayload) {
    std::atomic<bool> got_dest{false};
    std::vector<uint8_t> captured_payload;
    start_listener([&](std::shared_ptr<core::TcpConnection> /*conn*/, std::string /*host*/,
                       uint16_t /*port*/, std::vector<uint8_t> initial_payload,
                       std::function<void(bool)> /*reply_cb*/) {
        captured_payload = std::move(initial_payload);
        got_dest.store(true);
    });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const uint8_t greeting[] = {0x05, 0x01, 0x00};
    asio::write(sock, asio::buffer(greeting, sizeof(greeting)));
    (void)read_some(sock, 2);

    // Request + 4 bytes of pipelined payload, all in one write — simulates a
    // naive client that doesn't wait for the success reply before streaming.
    const uint8_t req_plus_payload[] = {
        0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x01, 0xBB,  // SOCKS5 CONNECT 10.0.0.7:443
        0xDE, 0xAD, 0xBE, 0xEF                            // first 4 stream bytes
    };
    asio::write(sock, asio::buffer(req_plus_payload, sizeof(req_plus_payload)));

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!got_dest.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(got_dest.load());
    ASSERT_EQ(captured_payload.size(), 4u);
    EXPECT_EQ(captured_payload[0], 0xDE);
    EXPECT_EQ(captured_payload[1], 0xAD);
    EXPECT_EQ(captured_payload[2], 0xBE);
    EXPECT_EQ(captured_payload[3], 0xEF);
}

// Regression: same hazard for HTTP CONNECT — naive clients (and some TLS
// libraries doing TCP fast-open) write the CONNECT line and a TLS ClientHello
// in the same TCP segment without waiting for `200 OK`.
TEST_F(Socks5ListenerLifecycleTest, HttpConnectHandoffForwardsPipelinedPayload) {
    std::atomic<bool> got_dest{false};
    std::vector<uint8_t> captured_payload;
    start_listener([&](std::shared_ptr<core::TcpConnection> /*conn*/, std::string /*host*/,
                       uint16_t /*port*/, std::vector<uint8_t> initial_payload,
                       std::function<void(bool)> /*reply_cb*/) {
        captured_payload = std::move(initial_payload);
        got_dest.store(true);
    });

    asio::io_context client_io;
    asio::ip::tcp::socket sock(client_io);
    sock.connect({asio::ip::make_address("127.0.0.1"), listener_->bound_port()});

    const std::string req = "CONNECT host.example:443 HTTP/1.1\r\nHost: host.example:443\r\n\r\n";
    const std::vector<uint8_t> client_hello = {0x16, 0x03, 0x01, 0x00, 0x05,
                                               'h',  'e',  'l',  'l',  'o'};
    std::vector<uint8_t> combined(req.begin(), req.end());
    combined.insert(combined.end(), client_hello.begin(), client_hello.end());
    asio::write(sock, asio::buffer(combined));

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!got_dest.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(got_dest.load());
    EXPECT_EQ(captured_payload, client_hello);
}
