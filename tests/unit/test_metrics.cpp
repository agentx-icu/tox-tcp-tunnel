#include <gtest/gtest.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/metrics.hpp"

using namespace toxtunnel;
using util::MetricsRegistry;
using util::MetricsServer;

namespace {

// Drop-in fixture that resets the global registry before every test so a
// counter set in one case does not leak into the next.
class MetricsTest : public ::testing::Test {
   protected:
    void SetUp() override { MetricsRegistry::instance().reset(); }
    void TearDown() override { MetricsRegistry::instance().reset(); }
};

// Drive a minimal HTTP GET against host:port using blocking asio and return
// the full response body (after the CRLFCRLF header terminator). Returns
// the status line + body to keep the test simple.
struct HttpResponse {
    int status = 0;
    std::string body;
    std::string raw;
};

HttpResponse http_get(asio::io_context& io_ctx, std::uint16_t port, std::string_view path) {
    asio::ip::tcp::socket sock(io_ctx);
    asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), port);
    asio::error_code ec;
    sock.connect(ep, ec);
    if (ec) {
        return {};
    }
    std::string req = "GET ";
    req.append(path);
    req.append(" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    asio::write(sock, asio::buffer(req), ec);
    if (ec) {
        return {};
    }
    std::string response;
    std::array<char, 4096> chunk{};
    for (;;) {
        std::size_t n = sock.read_some(asio::buffer(chunk), ec);
        if (n > 0) {
            response.append(chunk.data(), n);
        }
        if (ec) {
            break;
        }
    }
    HttpResponse out;
    out.raw = response;
    // Parse "HTTP/1.1 NNN ..." status line.
    if (response.rfind("HTTP/1.", 0) == 0) {
        auto first_space = response.find(' ');
        if (first_space != std::string::npos) {
            try {
                out.status = std::stoi(response.substr(first_space + 1, 3));
            } catch (...) {
                out.status = 0;
            }
        }
    }
    auto header_end = response.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        out.body = response.substr(header_end + 4);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// MetricsRegistry — counters + gauges
// ---------------------------------------------------------------------------

TEST_F(MetricsTest, CounterIncrementAndRead) {
    auto& m = MetricsRegistry::instance();
    m.inc_tunnels_opened(MetricsRegistry::OpenResult::Ok);
    m.inc_tunnels_opened(MetricsRegistry::OpenResult::Ok);
    m.inc_tunnels_opened(MetricsRegistry::OpenResult::Denied);

    EXPECT_EQ(m.tunnels_opened(MetricsRegistry::OpenResult::Ok), 2u);
    EXPECT_EQ(m.tunnels_opened(MetricsRegistry::OpenResult::Denied), 1u);
    EXPECT_EQ(m.tunnels_opened(MetricsRegistry::OpenResult::Failed), 0u);
}

TEST_F(MetricsTest, ActiveGaugeIncDecSaturatesAtZero) {
    auto& m = MetricsRegistry::instance();
    m.inc_tunnels_active(MetricsRegistry::Role::Server);
    m.inc_tunnels_active(MetricsRegistry::Role::Server);
    m.dec_tunnels_active(MetricsRegistry::Role::Server);
    EXPECT_EQ(m.tunnels_active(MetricsRegistry::Role::Server), 1u);

    m.dec_tunnels_active(MetricsRegistry::Role::Server);
    EXPECT_EQ(m.tunnels_active(MetricsRegistry::Role::Server), 0u);
    // Over-decrement must not underflow into UINT64_MAX.
    m.dec_tunnels_active(MetricsRegistry::Role::Server);
    EXPECT_EQ(m.tunnels_active(MetricsRegistry::Role::Server), 0u);
}

TEST_F(MetricsTest, ConcurrentCountersAreRaceFree) {
    // 8 threads, each adding 10k. The total must match exactly, which only
    // holds if the underlying atomic op is correctly synchronised.
    auto& m = MetricsRegistry::instance();
    constexpr int kThreads = 8;
    constexpr int kPerThread = 10000;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&m] {
            for (int j = 0; j < kPerThread; ++j) {
                m.add_bytes_in(1);
                m.inc_tunnels_opened(MetricsRegistry::OpenResult::Ok);
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(m.bytes_in(), static_cast<std::uint64_t>(kThreads * kPerThread));
    EXPECT_EQ(m.tunnels_opened(MetricsRegistry::OpenResult::Ok),
              static_cast<std::uint64_t>(kThreads * kPerThread));
}

TEST_F(MetricsTest, IterateLagSummaryTracksSumCountMax) {
    auto& m = MetricsRegistry::instance();
    m.observe_iterate_lag_ms(1.0);
    m.observe_iterate_lag_ms(2.5);
    m.observe_iterate_lag_ms(4.0);
    const auto text = m.render();
    EXPECT_NE(text.find("toxtunnel_tox_iterate_lag_milliseconds_count 3"), std::string::npos)
        << text;
    EXPECT_NE(text.find("toxtunnel_tox_iterate_lag_milliseconds_sum 7.5"), std::string::npos)
        << text;
    EXPECT_NE(text.find("toxtunnel_tox_iterate_lag_milliseconds_max 4"), std::string::npos) << text;
}

// ---------------------------------------------------------------------------
// MetricsRegistry — Prometheus text format
// ---------------------------------------------------------------------------

TEST_F(MetricsTest, RenderEmitsHelpAndTypeForEveryMetric) {
    auto& m = MetricsRegistry::instance();
    const std::string text = m.render();

    for (std::string_view name : {
             "toxtunnel_build_info",
             "toxtunnel_tunnels_active",
             "toxtunnel_tunnels_opened_total",
             "toxtunnel_tunnels_closed_total",
             "toxtunnel_bytes_in_total",
             "toxtunnel_bytes_out_total",
             "toxtunnel_friends_online",
             "toxtunnel_tox_iterate_lag_milliseconds",
         }) {
        const std::string help = "# HELP " + std::string(name);
        const std::string type = "# TYPE " + std::string(name);
        EXPECT_NE(text.find(help), std::string::npos) << "missing HELP: " << name;
        EXPECT_NE(text.find(type), std::string::npos) << "missing TYPE: " << name;
    }
}

TEST_F(MetricsTest, RenderEscapesBuildInfoLabels) {
    auto& m = MetricsRegistry::instance();
    m.set_build_info("v\"1\\0\nbeta", "abc123");
    const std::string text = m.render();
    // The literal `\"`, `\\`, and `\n` (two characters: backslash + n) must
    // appear inside the version label value.
    // MSVC's preprocessor mis-parses default-delimited raw strings that contain
    // unescaped `"` characters; use a custom delimiter to stay portable.
    EXPECT_NE(text.find(R"~(version="v\"1\\0\nbeta")~"), std::string::npos) << text;
    EXPECT_NE(text.find(R"~(git_sha="abc123")~"), std::string::npos) << text;
}

TEST_F(MetricsTest, RenderEndsWithNewline) {
    const std::string text = MetricsRegistry::instance().render();
    ASSERT_FALSE(text.empty());
    EXPECT_EQ(text.back(), '\n');
}

TEST_F(MetricsTest, EscapeLabelValueHandlesAllSpecialChars) {
    EXPECT_EQ(util::escape_label_value(""), "");
    EXPECT_EQ(util::escape_label_value("plain"), "plain");
    EXPECT_EQ(util::escape_label_value(R"(a\b"c)"), R"(a\\b\"c)");
    EXPECT_EQ(util::escape_label_value("line\nbreak"), "line\\nbreak");
}

// ---------------------------------------------------------------------------
// parse_listen_spec
// ---------------------------------------------------------------------------

TEST_F(MetricsTest, ParseListenSpecAcceptsIpv4) {
    std::string host;
    std::uint16_t port = 0;
    ASSERT_TRUE(util::parse_listen_spec("127.0.0.1:9100", host, port));
    EXPECT_EQ(host, "127.0.0.1");
    EXPECT_EQ(port, 9100);
}

TEST_F(MetricsTest, ParseListenSpecAcceptsIpv6Brackets) {
    std::string host;
    std::uint16_t port = 0;
    ASSERT_TRUE(util::parse_listen_spec("[::1]:9100", host, port));
    EXPECT_EQ(host, "::1");
    EXPECT_EQ(port, 9100);
}

TEST_F(MetricsTest, ParseListenSpecRejectsMalformed) {
    std::string host;
    std::uint16_t port = 0;
    EXPECT_FALSE(util::parse_listen_spec("", host, port));
    EXPECT_FALSE(util::parse_listen_spec("127.0.0.1", host, port));
    EXPECT_FALSE(util::parse_listen_spec(":9100", host, port));
    EXPECT_FALSE(util::parse_listen_spec("127.0.0.1:", host, port));
    EXPECT_FALSE(util::parse_listen_spec("127.0.0.1:99999", host, port));
    EXPECT_FALSE(util::parse_listen_spec("127.0.0.1:abc", host, port));
    // Port 0 is allowed: the OS picks an ephemeral port at bind time. Tests
    // rely on this to avoid port-conflict flakes in CI.
    EXPECT_TRUE(util::parse_listen_spec("127.0.0.1:0", host, port));
    EXPECT_EQ(port, 0);
}

// ---------------------------------------------------------------------------
// Config — metrics roundtrip
// ---------------------------------------------------------------------------

TEST(ConfigMetricsTest, DefaultsAreDisabled) {
    MetricsConfig def;
    EXPECT_FALSE(def.enabled);
    EXPECT_EQ(def.listen, "127.0.0.1:9100");
    EXPECT_EQ(def.path, "/metrics");
}

TEST(ConfigMetricsTest, ParsesMetricsBlockFromYaml) {
    const char* yaml = R"(
mode: server
data_dir: /tmp/toxtunnel
metrics:
  enabled: true
  listen: 0.0.0.0:9101
  path: /m
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    EXPECT_TRUE(cfg.metrics.enabled);
    EXPECT_EQ(cfg.metrics.listen, "0.0.0.0:9101");
    EXPECT_EQ(cfg.metrics.path, "/m");
}

TEST(ConfigMetricsTest, ShorthandBooleanTogglesEnabled) {
    const char* yaml = R"(
mode: server
data_dir: /tmp/toxtunnel
metrics: true
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    EXPECT_TRUE(cfg.metrics.enabled);
    EXPECT_EQ(cfg.metrics.listen, "127.0.0.1:9100");
    EXPECT_EQ(cfg.metrics.path, "/metrics");
}

TEST(ConfigMetricsTest, RoundtripThroughToYaml) {
    Config cfg = Config::default_server();
    cfg.metrics.enabled = true;
    cfg.metrics.listen = "0.0.0.0:9200";
    cfg.metrics.path = "/m";
    const auto yaml = cfg.to_yaml();
    auto parsed = Config::from_string(yaml);
    ASSERT_TRUE(parsed.has_value()) << parsed.error();
    EXPECT_EQ(parsed.value().metrics, cfg.metrics);
}

// ---------------------------------------------------------------------------
// MetricsServer — HTTP serving
// ---------------------------------------------------------------------------

TEST_F(MetricsTest, HttpServerServesMetricsOnConfiguredPath) {
    asio::io_context io_ctx;
    asio::executor_work_guard<asio::io_context::executor_type> guard(io_ctx.get_executor());
    std::thread io_thread([&io_ctx] { io_ctx.run(); });

    MetricsServer server(io_ctx, MetricsRegistry::instance());
    MetricsRegistry::instance().add_bytes_in(1234);
    MetricsRegistry::instance().set_build_info("test-1.2.3", "deadbeef");
    auto err = server.start("127.0.0.1:0", "/metrics");
    ASSERT_TRUE(err.empty()) << err;
    const auto port = server.local_port();
    ASSERT_GT(port, 0);

    const auto resp = http_get(io_ctx, port, "/metrics");
    EXPECT_EQ(resp.status, 200) << resp.raw;
    EXPECT_NE(resp.body.find("toxtunnel_bytes_in_total 1234"), std::string::npos) << resp.body;
    EXPECT_NE(resp.body.find("test-1.2.3"), std::string::npos) << resp.body;

    server.stop();
    guard.reset();
    io_ctx.stop();
    io_thread.join();
}

TEST_F(MetricsTest, HttpServerReturns404ForUnknownPath) {
    asio::io_context io_ctx;
    asio::executor_work_guard<asio::io_context::executor_type> guard(io_ctx.get_executor());
    std::thread io_thread([&io_ctx] { io_ctx.run(); });

    MetricsServer server(io_ctx, MetricsRegistry::instance());
    auto err = server.start("127.0.0.1:0", "/metrics");
    ASSERT_TRUE(err.empty()) << err;
    const auto port = server.local_port();

    const auto resp = http_get(io_ctx, port, "/nope");
    EXPECT_EQ(resp.status, 404) << resp.raw;

    server.stop();
    guard.reset();
    io_ctx.stop();
    io_thread.join();
}

TEST_F(MetricsTest, HttpServerRespectsCustomPath) {
    asio::io_context io_ctx;
    asio::executor_work_guard<asio::io_context::executor_type> guard(io_ctx.get_executor());
    std::thread io_thread([&io_ctx] { io_ctx.run(); });

    MetricsServer server(io_ctx, MetricsRegistry::instance());
    auto err = server.start("127.0.0.1:0", "/custom");
    ASSERT_TRUE(err.empty()) << err;
    const auto port = server.local_port();

    EXPECT_EQ(http_get(io_ctx, port, "/metrics").status, 404);
    EXPECT_EQ(http_get(io_ctx, port, "/custom").status, 200);
    // Query string after the path must still route to /custom.
    EXPECT_EQ(http_get(io_ctx, port, "/custom?foo=bar").status, 200);

    server.stop();
    guard.reset();
    io_ctx.stop();
    io_thread.join();
}

TEST_F(MetricsTest, HttpServerRejectsInvalidListenSpec) {
    asio::io_context io_ctx;
    MetricsServer server(io_ctx, MetricsRegistry::instance());
    const auto err = server.start("not-a-host:port", "/metrics");
    EXPECT_FALSE(err.empty());
}
