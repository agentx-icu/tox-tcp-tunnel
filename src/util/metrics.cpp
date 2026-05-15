#include "toxtunnel/util/metrics.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sstream>
#include <utility>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::util {

namespace {

// Per-spec maximum HTTP request line we'll consider. Keep this tight so
// a malicious client can't make us allocate. Real Prometheus scrapers
// send a few hundred bytes; 8 KiB is generous and bounded.
constexpr std::size_t kMaxRequestBytes = 8 * 1024;

const char* role_label(MetricsRegistry::Role role) {
    return role == MetricsRegistry::Role::Server ? "server" : "client";
}

const char* open_result_label(MetricsRegistry::OpenResult r) {
    switch (r) {
        case MetricsRegistry::OpenResult::Ok:
            return "ok";
        case MetricsRegistry::OpenResult::Denied:
            return "denied";
        case MetricsRegistry::OpenResult::Failed:
            return "failed";
    }
    return "unknown";
}

const char* close_reason_label(MetricsRegistry::CloseReason r) {
    switch (r) {
        case MetricsRegistry::CloseReason::Local:
            return "local";
        case MetricsRegistry::CloseReason::Remote:
            return "remote";
        case MetricsRegistry::CloseReason::Timeout:
            return "timeout";
        case MetricsRegistry::CloseReason::Error:
            return "error";
    }
    return "unknown";
}

void atomic_add_double(std::atomic<double>& target, double delta) {
    double current = target.load(std::memory_order_relaxed);
    while (!target.compare_exchange_weak(current, current + delta, std::memory_order_relaxed)) {
        // current is updated by compare_exchange_weak on failure; loop.
    }
}

void atomic_max_double(std::atomic<double>& target, double value) {
    double current = target.load(std::memory_order_relaxed);
    while (value > current &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
        // current is updated by compare_exchange_weak on failure; loop.
    }
}

// Render a Prometheus-formatted floating point number. We use std::to_string
// for simplicity (sub-millisecond precision is plenty for ms summaries and
// integer-valued gauges/counters render correctly).
std::string format_double(double v) {
    if (std::isnan(v) || std::isinf(v)) {
        return "0";
    }
    char buf[64];
    // %g picks the shortest representation; 17 digits is enough to
    // round-trip a double if anyone cares.
    std::snprintf(buf, sizeof(buf), "%.17g", v);
    return buf;
}

}  // namespace

// ===========================================================================
// MetricsRegistry
// ===========================================================================

MetricsRegistry& MetricsRegistry::instance() {
    static MetricsRegistry global;
    return global;
}

void MetricsRegistry::reset() {
    for (auto& v : tunnels_active_) v.store(0, std::memory_order_relaxed);
    for (auto& v : tunnels_opened_) v.store(0, std::memory_order_relaxed);
    for (auto& v : tunnels_closed_) v.store(0, std::memory_order_relaxed);
    bytes_in_.store(0, std::memory_order_relaxed);
    bytes_out_.store(0, std::memory_order_relaxed);
    friends_online_.store(0, std::memory_order_relaxed);
    iterate_lag_count_.store(0, std::memory_order_relaxed);
    iterate_lag_sum_ms_.store(0.0, std::memory_order_relaxed);
    iterate_lag_max_ms_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(labels_mutex_);
    build_version_.clear();
    build_git_sha_.clear();
}

void MetricsRegistry::set_build_info(std::string_view version, std::string_view git_sha) {
    std::lock_guard<std::mutex> lock(labels_mutex_);
    build_version_ = std::string(version);
    build_git_sha_ = std::string(git_sha);
}

void MetricsRegistry::inc_tunnels_active(Role role) {
    tunnels_active_[static_cast<std::size_t>(role)].fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::dec_tunnels_active(Role role) {
    auto& slot = tunnels_active_[static_cast<std::size_t>(role)];
    // Saturate at zero so paired open/close that races a teardown can't
    // produce a negative gauge in the rendered output.
    std::int64_t current = slot.load(std::memory_order_relaxed);
    while (current > 0 &&
           !slot.compare_exchange_weak(current, current - 1, std::memory_order_relaxed)) {
        // retry
    }
}

void MetricsRegistry::inc_tunnels_opened(OpenResult result) {
    tunnels_opened_[static_cast<std::size_t>(result)].fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::inc_tunnels_closed(CloseReason reason) {
    tunnels_closed_[static_cast<std::size_t>(reason)].fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::add_bytes_in(std::size_t n) {
    bytes_in_.fetch_add(n, std::memory_order_relaxed);
}

void MetricsRegistry::add_bytes_out(std::size_t n) {
    bytes_out_.fetch_add(n, std::memory_order_relaxed);
}

void MetricsRegistry::set_friends_online(std::size_t n) {
    friends_online_.store(n, std::memory_order_relaxed);
}

void MetricsRegistry::observe_iterate_lag_ms(double ms) {
    if (ms < 0.0 || std::isnan(ms)) {
        return;
    }
    iterate_lag_count_.fetch_add(1, std::memory_order_relaxed);
    atomic_add_double(iterate_lag_sum_ms_, ms);
    atomic_max_double(iterate_lag_max_ms_, ms);
}

std::uint64_t MetricsRegistry::tunnels_active(Role role) const {
    auto v = tunnels_active_[static_cast<std::size_t>(role)].load(std::memory_order_relaxed);
    return v < 0 ? 0 : static_cast<std::uint64_t>(v);
}
std::uint64_t MetricsRegistry::tunnels_opened(OpenResult result) const {
    return tunnels_opened_[static_cast<std::size_t>(result)].load(std::memory_order_relaxed);
}
std::uint64_t MetricsRegistry::tunnels_closed(CloseReason reason) const {
    return tunnels_closed_[static_cast<std::size_t>(reason)].load(std::memory_order_relaxed);
}
std::uint64_t MetricsRegistry::bytes_in() const {
    return bytes_in_.load(std::memory_order_relaxed);
}
std::uint64_t MetricsRegistry::bytes_out() const {
    return bytes_out_.load(std::memory_order_relaxed);
}
std::uint64_t MetricsRegistry::friends_online() const {
    return friends_online_.load(std::memory_order_relaxed);
}

std::string MetricsRegistry::render() const {
    std::ostringstream out;

    // Build info: gauge fixed at 1, labels carry the data. Snapshot the
    // label strings under the lock so concurrent set_build_info doesn't
    // tear them mid-render.
    std::string version;
    std::string git_sha;
    {
        std::lock_guard<std::mutex> lock(labels_mutex_);
        version = build_version_;
        git_sha = build_git_sha_;
    }
    out << "# HELP toxtunnel_build_info Build information for the running toxtunnel binary.\n"
           "# TYPE toxtunnel_build_info gauge\n"
           "toxtunnel_build_info{version=\""
        << escape_label_value(version) << "\",git_sha=\"" << escape_label_value(git_sha)
        << "\"} 1\n";

    // tunnels_active gauge
    out << "# HELP toxtunnel_tunnels_active Currently open tunnels.\n"
           "# TYPE toxtunnel_tunnels_active gauge\n";
    for (auto role : {Role::Server, Role::Client}) {
        out << "toxtunnel_tunnels_active{role=\"" << role_label(role) << "\"} "
            << tunnels_active(role) << "\n";
    }

    // tunnels_opened_total counter
    out << "# HELP toxtunnel_tunnels_opened_total Tunnel open attempts by outcome.\n"
           "# TYPE toxtunnel_tunnels_opened_total counter\n";
    for (auto r : {OpenResult::Ok, OpenResult::Denied, OpenResult::Failed}) {
        out << "toxtunnel_tunnels_opened_total{result=\"" << open_result_label(r) << "\"} "
            << tunnels_opened(r) << "\n";
    }

    // tunnels_closed_total counter
    out << "# HELP toxtunnel_tunnels_closed_total Tunnel closes by reason.\n"
           "# TYPE toxtunnel_tunnels_closed_total counter\n";
    for (auto r :
         {CloseReason::Local, CloseReason::Remote, CloseReason::Timeout, CloseReason::Error}) {
        out << "toxtunnel_tunnels_closed_total{reason=\"" << close_reason_label(r) << "\"} "
            << tunnels_closed(r) << "\n";
    }

    // bytes counters
    out << "# HELP toxtunnel_bytes_in_total Bytes received from Tox peers.\n"
           "# TYPE toxtunnel_bytes_in_total counter\n"
           "toxtunnel_bytes_in_total "
        << bytes_in() << "\n";
    out << "# HELP toxtunnel_bytes_out_total Bytes sent to Tox peers.\n"
           "# TYPE toxtunnel_bytes_out_total counter\n"
           "toxtunnel_bytes_out_total "
        << bytes_out() << "\n";

    // friends_online gauge
    out << "# HELP toxtunnel_friends_online Number of currently-online Tox friends.\n"
           "# TYPE toxtunnel_friends_online gauge\n"
           "toxtunnel_friends_online "
        << friends_online() << "\n";

    // iterate-lag summary (count + sum + a `_max` companion gauge for
    // the maximum observation since process start)
    const auto count = iterate_lag_count_.load(std::memory_order_relaxed);
    const auto sum = iterate_lag_sum_ms_.load(std::memory_order_relaxed);
    const auto max = iterate_lag_max_ms_.load(std::memory_order_relaxed);
    out << "# HELP toxtunnel_tox_iterate_lag_milliseconds tox_iterate() elapsed time per tick.\n"
           "# TYPE toxtunnel_tox_iterate_lag_milliseconds summary\n"
           "toxtunnel_tox_iterate_lag_milliseconds_count "
        << count << "\n"
        << "toxtunnel_tox_iterate_lag_milliseconds_sum " << format_double(sum) << "\n";
    out << "# HELP toxtunnel_tox_iterate_lag_milliseconds_max Maximum observed iterate lag.\n"
           "# TYPE toxtunnel_tox_iterate_lag_milliseconds_max gauge\n"
           "toxtunnel_tox_iterate_lag_milliseconds_max "
        << format_double(max) << "\n";

    return out.str();
}

// ===========================================================================
// Helpers
// ===========================================================================

bool parse_listen_spec(std::string_view spec, std::string& host_out, std::uint16_t& port_out) {
    if (spec.empty()) {
        return false;
    }
    // IPv6 bracketed form: [::1]:9100
    if (spec.front() == '[') {
        auto close = spec.find(']');
        if (close == std::string_view::npos || close + 1 >= spec.size() || spec[close + 1] != ':') {
            return false;
        }
        host_out.assign(spec.substr(1, close - 1));
        const auto port_sv = spec.substr(close + 2);
        unsigned int port = 0;
        auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
        if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || port > 65535) {
            return false;
        }
        port_out = static_cast<std::uint16_t>(port);
        return true;
    }

    auto colon = spec.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= spec.size()) {
        return false;
    }
    host_out.assign(spec.substr(0, colon));
    const auto port_sv = spec.substr(colon + 1);
    unsigned int port = 0;
    auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
    if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || port > 65535) {
        return false;
    }
    port_out = static_cast<std::uint16_t>(port);
    return true;
}

std::string escape_label_value(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

// ===========================================================================
// MetricsServer
// ===========================================================================

MetricsServer::MetricsServer(asio::io_context& io_ctx, MetricsRegistry& registry)
    : io_ctx_(io_ctx), registry_(registry) {}

MetricsServer::~MetricsServer() {
    stop();
}

std::string MetricsServer::start(std::string_view listen_spec, std::string_view metrics_path) {
    if (running_.exchange(true)) {
        return "MetricsServer already running";
    }

    std::string host;
    std::uint16_t port = 0;
    if (!parse_listen_spec(listen_spec, host, port)) {
        running_ = false;
        return "Invalid listen spec: " + std::string(listen_spec);
    }

    asio::error_code ec;
    asio::ip::address addr = asio::ip::make_address(host, ec);
    if (ec) {
        running_ = false;
        return "Invalid listen address '" + host + "': " + ec.message();
    }

    metrics_path_.assign(metrics_path);

    asio::ip::tcp::endpoint endpoint(addr, port);
    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(io_ctx_);
    acceptor_->open(endpoint.protocol(), ec);
    if (ec) {
        acceptor_.reset();
        running_ = false;
        return "acceptor.open: " + ec.message();
    }
    acceptor_->set_option(asio::socket_base::reuse_address(true), ec);
    // reuse_address failing is non-fatal — proceed without it.
    acceptor_->bind(endpoint, ec);
    if (ec) {
        acceptor_.reset();
        running_ = false;
        return "acceptor.bind " + host + ":" + std::to_string(port) + ": " + ec.message();
    }
    acceptor_->listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        acceptor_.reset();
        running_ = false;
        return "acceptor.listen: " + ec.message();
    }

    bound_port_ = acceptor_->local_endpoint().port();
    Logger::info("Metrics endpoint listening on {}:{} {}", host, bound_port_.load(), metrics_path_);

    do_accept();
    return {};
}

void MetricsServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (acceptor_) {
        asio::error_code ec;
        acceptor_->close(ec);
        // ec ignored: closing an already-closed acceptor is fine.
    }
    bound_port_ = 0;
}

std::uint16_t MetricsServer::local_port() const noexcept {
    return bound_port_.load();
}

void MetricsServer::do_accept() {
    if (!running_.load() || !acceptor_) {
        return;
    }
    auto socket = std::make_shared<asio::ip::tcp::socket>(io_ctx_);
    acceptor_->async_accept(*socket, [this, socket](const asio::error_code& ec) {
        if (ec) {
            // Acceptor closed (stop()) or transient error; just bail if
            // we're shutting down, otherwise schedule another accept.
            if (running_.load()) {
                Logger::warn("Metrics accept error: {}", ec.message());
                do_accept();
            }
            return;
        }

        // Read the request line. We don't care about headers — for a
        // /metrics endpoint we only need the first line ("GET /path HTTP/1.x").
        auto buffer = std::make_shared<asio::streambuf>(kMaxRequestBytes);
        asio::async_read_until(
            *socket, *buffer, "\r\n\r\n",
            [this, socket, buffer](const asio::error_code& read_ec, std::size_t) {
                // Even on EOF we may have a usable first line in the buffer.
                std::string request_line;
                if (buffer->size() > 0) {
                    std::istream is(buffer.get());
                    std::getline(is, request_line);
                    // Strip a trailing CR if present.
                    if (!request_line.empty() && request_line.back() == '\r') {
                        request_line.pop_back();
                    }
                }

                std::string response;
                bool ok = false;
                // Expected form: "GET /metrics HTTP/1.1"
                if (request_line.starts_with("GET ")) {
                    auto space2 = request_line.find(' ', 4);
                    if (space2 != std::string::npos) {
                        std::string path = request_line.substr(4, space2 - 4);
                        // Drop query string if any.
                        auto qmark = path.find('?');
                        if (qmark != std::string::npos) {
                            path.resize(qmark);
                        }
                        if (path == metrics_path_) {
                            ok = true;
                        }
                    }
                }

                if (ok) {
                    const std::string body = registry_.render();
                    response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                        "Content-Length: " +
                        std::to_string(body.size()) +
                        "\r\n"
                        "Connection: close\r\n"
                        "\r\n" +
                        body;
                } else {
                    const std::string body = "Not Found\n";
                    response =
                        "HTTP/1.1 404 Not Found\r\n"
                        "Content-Type: text/plain; charset=utf-8\r\n"
                        "Content-Length: " +
                        std::to_string(body.size()) +
                        "\r\n"
                        "Connection: close\r\n"
                        "\r\n" +
                        body;
                }
                // Ignore read_ec — even partial requests with no CRLF can
                // still produce a usable first line, and async_write below
                // will surface the real failure.
                (void)read_ec;

                auto response_buf = std::make_shared<std::string>(std::move(response));
                asio::async_write(*socket, asio::buffer(*response_buf),
                                  [socket, response_buf](const asio::error_code& /*write_ec*/,
                                                         std::size_t /*bytes*/) {
                                      asio::error_code ignore;
                                      socket->shutdown(asio::ip::tcp::socket::shutdown_both,
                                                       ignore);
                                      socket->close(ignore);
                                  });
            });

        do_accept();
    });
}

}  // namespace toxtunnel::util
