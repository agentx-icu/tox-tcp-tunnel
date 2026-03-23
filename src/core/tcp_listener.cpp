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
    if (accepting_) {
        return;
    }

    accept_handler_ = std::move(handler);
    accepting_ = true;

    util::Logger::info("TcpListener: accepting connections on port {}", port_);

    do_accept();
}

void TcpListener::stop() {
    if (!accepting_ && !acceptor_.is_open()) {
        return;
    }

    accepting_ = false;

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
    if (connection_count_ > 0) {
        --connection_count_;
        util::Logger::debug("TcpListener: connection closed (active: {}/{})", connection_count_,
                            max_connections_);
    }

    // If the accept loop was paused because we hit the connection limit,
    // resume it now that there is room for a new connection.
    if (accepting_ && connection_count_ < max_connections_) {
        do_accept();
    }
}

void TcpListener::set_max_connections(std::size_t max) {
    max_connections_ = max;

    util::Logger::debug("TcpListener: max connections set to {}", max_connections_);

    // If we now have room, resume accepting.
    if (accepting_ && connection_count_ < max_connections_) {
        do_accept();
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
    if (!accepting_) {
        return;
    }

    if (connection_count_ >= max_connections_) {
        util::Logger::warn("TcpListener: connection limit reached ({}/{}), pausing accept loop",
                           connection_count_, max_connections_);
        return;
    }

    acceptor_.async_accept([this](const asio::error_code& ec, asio::ip::tcp::socket peer_socket) {
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

        ++connection_count_;

        // Wrap the accepted socket in a TcpConnection.
        auto conn = std::make_shared<TcpConnection>(std::move(peer_socket));

        util::Logger::debug("TcpListener: accepted connection from {} (active: {}/{})",
                            conn->remote_endpoint().address().to_string(), connection_count_,
                            max_connections_);

        if (accept_handler_) {
            accept_handler_(std::move(conn));
        }

        // Continue the accept loop.
        do_accept();
    });
}

}  // namespace toxtunnel::core
