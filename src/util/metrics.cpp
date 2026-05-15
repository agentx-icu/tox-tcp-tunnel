#include "toxtunnel/util/metrics.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <system_error>
#include <utility>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::util {

namespace {

// std::atomic<double> isn't always lock-free across platforms, so we route
// every double through its bit-pattern in a uint64. memory_order_relaxed is
// fine here: metrics readers tolerate slightly-stale samples in exchange for
// avoiding contention with hot-path writers.
inline double bits_to_double(uint64_t bits) noexcept {
    return std::bit_cast<double>(bits);
}

inline uint64_t double_to_bits(double v) noexcept {
    return std::bit_cast<uint64_t>(v);
}

std::string format_double(double v) {
    if (std::isnan(v)) {
        return "NaN";
    }
    if (std::isinf(v)) {
        return v < 0 ? "-Inf" : "+Inf";
    }
    // Drop trailing .0 for integer-valued counters so the wire stays small.
    if (v == static_cast<double>(static_cast<int64_t>(v)) && std::abs(v) < 1e15) {
        return std::to_string(static_cast<int64_t>(v));
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.6g", v);
    return std::string(buf);
}

const char* type_to_prom(MetricType t) {
    switch (t) {
        case MetricType::Counter:
            return "counter";
        case MetricType::Gauge:
            return "gauge";
        case MetricType::Summary:
            return "summary";
    }
    return "untyped";
}

// Prometheus 0.0.4 label-value escaping: backslash, double-quote, newline.
std::string escape_label_value(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
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

// HELP escaping is narrower than label-value: only backslash and newline.
std::string escape_help(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        switch (c) {
            case '\\':
                out += "\\\\";
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

void append_labels(std::string& out, const Labels& labels, const Label* extra = nullptr) {
    if (labels.empty() && !extra) {
        return;
    }
    out += '{';
    bool first = true;
    for (const auto& l : labels) {
        if (!first) {
            out += ',';
        }
        first = false;
        out += l.name;
        out += "=\"";
        out += escape_label_value(l.value);
        out += '"';
    }
    if (extra) {
        if (!first) {
            out += ',';
        }
        out += extra->name;
        out += "=\"";
        out += escape_label_value(extra->value);
        out += '"';
    }
    out += '}';
}

}  // namespace

// ===========================================================================
// Sample
// ===========================================================================

void Sample::inc(double v) noexcept {
    uint64_t old = bits_.load(std::memory_order_relaxed);
    while (true) {
        double new_val = bits_to_double(old) + v;
        uint64_t desired = double_to_bits(new_val);
        if (bits_.compare_exchange_weak(old, desired, std::memory_order_relaxed)) {
            return;
        }
    }
}

void Sample::set(double v) noexcept {
    bits_.store(double_to_bits(v), std::memory_order_relaxed);
}

double Sample::value() const noexcept {
    return bits_to_double(bits_.load(std::memory_order_relaxed));
}

// ===========================================================================
// SummarySample
// ===========================================================================

void SummarySample::observe(double v) noexcept {
    count_.fetch_add(1, std::memory_order_relaxed);

    uint64_t old_sum = sum_bits_.load(std::memory_order_relaxed);
    while (true) {
        double new_sum = bits_to_double(old_sum) + v;
        if (sum_bits_.compare_exchange_weak(old_sum, double_to_bits(new_sum),
                                            std::memory_order_relaxed)) {
            break;
        }
    }

    uint64_t old_max = max_bits_.load(std::memory_order_relaxed);
    while (true) {
        double current_max =
            (count_.load(std::memory_order_relaxed) == 1 || old_max == 0)
                ? -std::numeric_limits<double>::infinity()
                : bits_to_double(old_max);
        if (v <= current_max) {
            break;
        }
        if (max_bits_.compare_exchange_weak(old_max, double_to_bits(v),
                                            std::memory_order_relaxed)) {
            break;
        }
    }
}

uint64_t SummarySample::count() const noexcept {
    return count_.load(std::memory_order_relaxed);
}

double SummarySample::sum() const noexcept {
    return bits_to_double(sum_bits_.load(std::memory_order_relaxed));
}

double SummarySample::max() const noexcept {
    uint64_t b = max_bits_.load(std::memory_order_relaxed);
    if (count_.load(std::memory_order_relaxed) == 0) {
        return 0.0;
    }
    return bits_to_double(b);
}

// ===========================================================================
// MetricsRegistry
// ===========================================================================

MetricsRegistry::MetricsRegistry() = default;

bool MetricsRegistry::register_family(std::string name, MetricType type, std::string help) {
    std::unique_lock lock(mutex_);
    auto it = families_.find(name);
    if (it != families_.end()) {
        return it->second.type == type && it->second.help == help;
    }
    Family f;
    f.name = name;
    f.type = type;
    f.help = std::move(help);
    families_.emplace(std::move(name), std::move(f));
    return true;
}

MetricsRegistry::Family* MetricsRegistry::find_family(std::string_view name) {
    auto it = families_.find(name);
    return (it == families_.end()) ? nullptr : &it->second;
}

const MetricsRegistry::Family* MetricsRegistry::find_family(std::string_view name) const {
    auto it = families_.find(name);
    return (it == families_.end()) ? nullptr : &it->second;
}

bool MetricsRegistry::counter_inc(std::string_view name, const Labels& labels, double v) {
    std::unique_lock lock(mutex_);
    auto* f = find_family(name);
    if (!f || f->type != MetricType::Counter) {
        return false;
    }
    auto it = f->samples.find(labels);
    if (it == f->samples.end()) {
        it = f->samples.emplace(labels, std::make_unique<Sample>()).first;
    }
    it->second->inc(v);
    return true;
}

bool MetricsRegistry::gauge_set(std::string_view name, const Labels& labels, double v) {
    std::unique_lock lock(mutex_);
    auto* f = find_family(name);
    if (!f || f->type != MetricType::Gauge) {
        return false;
    }
    auto it = f->samples.find(labels);
    if (it == f->samples.end()) {
        it = f->samples.emplace(labels, std::make_unique<Sample>()).first;
    }
    it->second->set(v);
    return true;
}

bool MetricsRegistry::gauge_inc(std::string_view name, const Labels& labels, double v) {
    std::unique_lock lock(mutex_);
    auto* f = find_family(name);
    if (!f || f->type != MetricType::Gauge) {
        return false;
    }
    auto it = f->samples.find(labels);
    if (it == f->samples.end()) {
        it = f->samples.emplace(labels, std::make_unique<Sample>()).first;
    }
    it->second->inc(v);
    return true;
}

bool MetricsRegistry::summary_observe(std::string_view name, const Labels& labels, double v) {
    std::unique_lock lock(mutex_);
    auto* f = find_family(name);
    if (!f || f->type != MetricType::Summary) {
        return false;
    }
    auto it = f->summaries.find(labels);
    if (it == f->summaries.end()) {
        it = f->summaries.emplace(labels, std::make_unique<SummarySample>()).first;
    }
    it->second->observe(v);
    return true;
}

double MetricsRegistry::counter_value(std::string_view name, const Labels& labels) const {
    std::shared_lock lock(mutex_);
    const auto* f = find_family(name);
    if (!f) {
        return 0.0;
    }
    auto it = f->samples.find(labels);
    return (it == f->samples.end()) ? 0.0 : it->second->value();
}

double MetricsRegistry::gauge_value(std::string_view name, const Labels& labels) const {
    return counter_value(name, labels);
}

std::string MetricsRegistry::render() const {
    std::shared_lock lock(mutex_);
    std::string out;
    out.reserve(2048);

    for (const auto& [name, family] : families_) {
        out += "# HELP ";
        out += name;
        out += ' ';
        out += escape_help(family.help);
        out += '\n';
        out += "# TYPE ";
        out += name;
        out += ' ';
        out += type_to_prom(family.type);
        out += '\n';

        if (family.type == MetricType::Summary) {
            for (const auto& [labels, summary] : family.summaries) {
                Label count_label{"", ""};  // not used; we emit explicit suffixes
                (void)count_label;
                // toxtunnel_xxx_count{labels...}
                out += name;
                out += "_count";
                append_labels(out, labels);
                out += ' ';
                out += format_double(static_cast<double>(summary->count()));
                out += '\n';

                out += name;
                out += "_sum";
                append_labels(out, labels);
                out += ' ';
                out += format_double(summary->sum());
                out += '\n';

                out += name;
                out += "_max";
                append_labels(out, labels);
                out += ' ';
                out += format_double(summary->max());
                out += '\n';
            }
        } else {
            for (const auto& [labels, sample] : family.samples) {
                out += name;
                append_labels(out, labels);
                out += ' ';
                out += format_double(sample->value());
                out += '\n';
            }
        }
    }

    return out;
}

// ===========================================================================
// MetricsServer
// ===========================================================================

MetricsServer::MetricsServer(asio::io_context& io, MetricsRegistry& registry,
                             std::string listen_addr, std::string path)
    : io_(io),
      registry_(registry),
      listen_addr_(std::move(listen_addr)),
      path_(std::move(path)) {}

bool MetricsServer::parse_listen(std::string_view spec, std::string& host_out,
                                 uint16_t& port_out) {
    // IPv6: [::1]:9100
    if (!spec.empty() && spec.front() == '[') {
        const auto rb = spec.find(']');
        if (rb == std::string_view::npos || rb + 2 > spec.size() || spec[rb + 1] != ':') {
            return false;
        }
        host_out = std::string(spec.substr(1, rb - 1));
        const auto port_str = spec.substr(rb + 2);
        uint16_t port = 0;
        auto result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
        if (result.ec != std::errc{} || port == 0) {
            return false;
        }
        port_out = port;
        return true;
    }

    const auto colon = spec.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= spec.size()) {
        return false;
    }
    host_out = std::string(spec.substr(0, colon));
    const auto port_str = spec.substr(colon + 1);
    uint16_t port = 0;
    auto result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
    if (result.ec != std::errc{} || port == 0) {
        return false;
    }
    port_out = port;
    return true;
}

std::string MetricsServer::start() {
    std::string host;
    uint16_t port = 0;
    if (!parse_listen(listen_addr_, host, port)) {
        return "invalid metrics.listen syntax: " + listen_addr_;
    }

    asio::error_code ec;
    auto addr = asio::ip::make_address(host, ec);
    if (ec) {
        return "invalid metrics.listen address '" + host + "': " + ec.message();
    }

    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(io_);
    asio::ip::tcp::endpoint endpoint(addr, port);

    acceptor_->open(endpoint.protocol(), ec);
    if (ec) {
        return "metrics acceptor open failed: " + ec.message();
    }
    acceptor_->set_option(asio::socket_base::reuse_address(true), ec);
    acceptor_->bind(endpoint, ec);
    if (ec) {
        return "metrics bind failed for " + listen_addr_ + ": " + ec.message();
    }
    acceptor_->listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        return "metrics listen failed: " + ec.message();
    }

    bound_port_ = acceptor_->local_endpoint().port();
    do_accept();

    Logger::info("Metrics endpoint listening on {} (path={})", listen_addr_, path_);
    return {};
}

void MetricsServer::stop() {
    if (!acceptor_) {
        return;
    }
    asio::error_code ec;
    acceptor_->cancel(ec);
    acceptor_->close(ec);
    acceptor_.reset();
}

uint16_t MetricsServer::bound_port() const {
    return bound_port_;
}

void MetricsServer::do_accept() {
    auto sock = std::make_shared<asio::ip::tcp::socket>(io_);
    acceptor_->async_accept(*sock, [this, sock](const asio::error_code& ec) {
        if (ec) {
            // Cancellation during stop() is expected.
            if (ec != asio::error::operation_aborted) {
                Logger::debug("Metrics accept error: {}", ec.message());
            }
            return;
        }
        handle_connection(sock);
        do_accept();
    });
}

void MetricsServer::handle_connection(std::shared_ptr<asio::ip::tcp::socket> socket) {
    auto buffer = std::make_shared<asio::streambuf>();
    asio::async_read_until(
        *socket, *buffer, "\r\n\r\n",
        [this, socket, buffer](const asio::error_code& ec, std::size_t /*bytes*/) {
            if (ec) {
                return;
            }
            std::istream is(buffer.get());
            std::string request_line;
            std::getline(is, request_line);
            if (!request_line.empty() && request_line.back() == '\r') {
                request_line.pop_back();
            }

            std::string method;
            std::string uri;
            {
                std::istringstream iss(request_line);
                iss >> method >> uri;
            }

            auto write_response = [socket](std::string status, std::string body,
                                           const char* content_type) {
                auto resp = std::make_shared<std::string>();
                *resp = "HTTP/1.1 " + std::move(status) + "\r\n";
                *resp += "Content-Type: ";
                *resp += content_type;
                *resp += "\r\n";
                *resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
                *resp += "Connection: close\r\n\r\n";
                *resp += body;
                asio::async_write(*socket, asio::buffer(*resp),
                                  [socket, resp](const asio::error_code&, std::size_t) {
                                      asio::error_code ig;
                                      socket->shutdown(asio::ip::tcp::socket::shutdown_both, ig);
                                      socket->close(ig);
                                  });
            };

            if (method != "GET") {
                write_response("405 Method Not Allowed", "Method Not Allowed\n", "text/plain");
                return;
            }
            // Ignore query string when matching the configured path.
            auto qpos = uri.find('?');
            std::string uri_path = (qpos == std::string::npos) ? uri : uri.substr(0, qpos);
            if (uri_path != path_) {
                write_response("404 Not Found", "Not Found\n", "text/plain");
                return;
            }

            write_response("200 OK", registry_.render(), "text/plain; version=0.0.4");
        });
}

}  // namespace toxtunnel::util
