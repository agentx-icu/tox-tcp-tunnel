#include "toxtunnel/core/tcp_listener.hpp"

#include <utility>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::core {

// ===========================================================================
// Construction
// ===========================================================================

TcpListener::TcpListener(asio::io_context& io, std::uint16_t port) : acceptor_(io), port_(port) {
    asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), port);
    setup_acceptor(endpoint);
}

TcpListener::TcpListener(asio::io_context& io, const std::string& address, std::uint16_t port)
    : acceptor_(io), port_(port) {
    asio::ip::tcp::endpoint endpoint(asio::ip::make_address(address), port);
    setup_acceptor(endpoint);
}

TcpListener::~TcpListener() {
    stop();
}

// ===========================================================================
// Accept loop
// ===========================================================================

void TcpListener::start_accept(AcceptHandler handler) {
    if (accepting_.load(std::memory_order_relaxed)) {
        return;
    }

    accept_handler_ = std::move(handler);
    accepting_.store(true, std::memory_order_relaxed);

    util::Logger::info("TcpListener: accepting connections on port {}", port_);

    do_accept();
}

void TcpListener::stop() {
    if (!accepting_.load(std::memory_order_relaxed) && !acceptor_.is_open()) {
        return;
    }

    accepting_.store(false, std::memory_order_relaxed);

    asio::error_code ec;
    acceptor_.close(ec);
    if (ec) {
        util::Logger::warn("TcpListener: error closing acceptor on port {}: {}", port_,
                           ec.message());
    } else {
        util::Logger::info("TcpListener: stopped listening on port {}", port_);
    }
}

// ===========================================================================
// Connection tracking
// ===========================================================================

void TcpListener::on_connection_closed() {
    std::size_t prev = connection_count_.load(std::memory_order_relaxed);
    while (prev > 0) {
        if (connection_count_.compare_exchange_weak(prev, prev - 1, std::memory_order_relaxed)) {
            util::Logger::debug("TcpListener: connection closed (active: {}/{})", prev - 1,
                                max_connections_.load(std::memory_order_relaxed));
            break;
        }
    }

    // If the accept loop was paused because we hit the connection limit,
    // resume it now that there is room for a new connection.
    // M-S-2 (2026-05-20 fix-storm review): on_connection_closed can be
    // invoked from any thread (TcpConnection's disconnect callback may
    // fire from an I/O worker that isn't the acceptor's executor). asio
    // acceptors are not thread-safe, so calling do_accept() directly
    // would race async_accept on the acceptor. post the resume onto
    // the acceptor's executor so it always runs on the right thread.
    if (accepting_.load(std::memory_order_relaxed) &&
        connection_count_.load(std::memory_order_relaxed) <
            max_connections_.load(std::memory_order_relaxed)) {
        auto self = shared_from_this();
        asio::post(acceptor_.get_executor(), [self]() { self->do_accept(); });
    }
}

void TcpListener::set_max_connections(std::size_t max) {
    max_connections_.store(max, std::memory_order_relaxed);

    util::Logger::debug("TcpListener: max connections set to {}", max);

    // If we now have room, resume accepting. Same strand-correctness
    // note as on_connection_closed above (M-S-2).
    if (accepting_.load(std::memory_order_relaxed) &&
        connection_count_.load(std::memory_order_relaxed) < max) {
        auto self = shared_from_this();
        asio::post(acceptor_.get_executor(), [self]() { self->do_accept(); });
    }
}

// ===========================================================================
// Accessors
// ===========================================================================

asio::ip::tcp::endpoint TcpListener::local_endpoint() const {
    asio::error_code ec;
    auto ep = acceptor_.local_endpoint(ec);
    if (ec) {
        return {};
    }
    return ep;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

void TcpListener::setup_acceptor(const asio::ip::tcp::endpoint& endpoint) {
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen(asio::socket_base::max_listen_connections);

    // Update the port in case 0 was specified (OS-assigned).
    port_ = acceptor_.local_endpoint().port();

    util::Logger::debug("TcpListener: bound to {}:{}", endpoint.address().to_string(), port_);
}

void TcpListener::do_accept() {
    if (!accepting_.load(std::memory_order_relaxed)) {
        return;
    }

    std::size_t max = max_connections_.load(std::memory_order_relaxed);
    std::size_t current = connection_count_.load(std::memory_order_relaxed);
    if (current >= max) {
        util::Logger::warn("TcpListener: connection limit reached ({}/{}), pausing accept loop",
                           current, max);
        return;
    }

    // Keep the listener alive across the in-flight async_accept (S19 in
    // the 2026-05-20 follow-up). The caller might erase its owning
    // shared_ptr (e.g. TunnelClient::reload removing a forward rule)
    // between submission and dispatch; the lambda's keep-alive copy
    // lets the current callback finish cleanly instead of UAF-ing.
    auto self = shared_from_this();
    acceptor_.async_accept([this, self](const asio::error_code& ec,
                                        asio::ip::tcp::socket peer_socket) {
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                // Acceptor was closed (stop() was called); do not continue.
                return;
            }
            util::Logger::error("TcpListener: accept failed on port {}: {}", port_, ec.message());
            // Transient error -- keep trying.
            do_accept();
            return;
        }

        std::size_t new_count = connection_count_.fetch_add(1, std::memory_order_relaxed) + 1;

        // Wrap the accepted socket in a TcpConnection.
        auto conn = std::make_shared<TcpConnection>(std::move(peer_socket));

        util::Logger::debug("TcpListener: accepted connection from {} (active: {}/{})",
                            conn->remote_endpoint().address().to_string(), new_count,
                            max_connections_.load(std::memory_order_relaxed));

        if (accept_handler_) {
            accept_handler_(std::move(conn));
        }

        // Continue the accept loop.
        do_accept();
    });
}

}  // namespace toxtunnel::core
