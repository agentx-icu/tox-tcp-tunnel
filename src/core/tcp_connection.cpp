#include "toxtunnel/core/tcp_connection.hpp"

#include <cassert>
#include <utility>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::core {

// ===========================================================================
// to_string
// ===========================================================================

std::string_view to_string(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::Disconnected:
            return "Disconnected";
        case ConnectionState::Connecting:
            return "Connecting";
        case ConnectionState::Connected:
            return "Connected";
        case ConnectionState::Disconnecting:
            return "Disconnecting";
    }
    return "Unknown";
}

// ===========================================================================
// Construction / Destruction
// ===========================================================================

TcpConnection::TcpConnection(asio::io_context& io_ctx)
    : socket_(io_ctx), read_buffer_(kDefaultReadBufferSize) {}

TcpConnection::TcpConnection(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)),
      state_(ConnectionState::Connected),
      read_buffer_(kDefaultReadBufferSize) {}

TcpConnection::~TcpConnection() {
    // Ensure the socket is closed if still open.
    std::error_code ignored;
    if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
    }
}

// ===========================================================================
// Configuration
// ===========================================================================

void TcpConnection::set_max_write_buffer_size(std::size_t bytes) noexcept {
    max_write_buffer_size_ = bytes;
}

std::size_t TcpConnection::max_write_buffer_size() const noexcept {
    return max_write_buffer_size_;
}

void TcpConnection::set_read_buffer_size(std::size_t bytes) {
    read_buffer_.resize(bytes);
}

std::size_t TcpConnection::read_buffer_size() const noexcept {
    return read_buffer_.size();
}

// ===========================================================================
// Callbacks
// ===========================================================================

void TcpConnection::set_on_connect(ConnectCallback cb) {
    on_connect_ = std::move(cb);
}

void TcpConnection::set_on_data(DataCallback cb) {
    on_data_ = std::move(cb);
}

void TcpConnection::set_on_disconnect(DisconnectCallback cb) {
    on_disconnect_ = std::move(cb);
}

void TcpConnection::set_on_error(ErrorCallback cb) {
    on_error_ = std::move(cb);
}

// ===========================================================================
// Connection lifecycle
// ===========================================================================

void TcpConnection::async_connect(const asio::ip::tcp::endpoint& endpoint, ConnectCallback cb) {
    if (state_ != ConnectionState::Disconnected) {
        util::Logger::warn("TcpConnection::async_connect called in state {}", to_string(state_));
        if (cb) {
            cb(asio::error::already_connected);
        }
        return;
    }

    set_state(ConnectionState::Connecting);

    auto self = shared_from_this();
    socket_.async_connect(endpoint, [this, self, cb = std::move(cb)](const std::error_code& ec) {
        if (ec) {
            util::Logger::debug("TcpConnection: connect failed: {}", ec.message());
            set_state(ConnectionState::Disconnected);
            if (cb) {
                cb(ec);
            }
            if (on_connect_) {
                on_connect_(ec);
            }
            notify_error(ec);
            return;
        }

        util::Logger::debug("TcpConnection: connected to {}:{}",
                            socket_.remote_endpoint().address().to_string(),
                            socket_.remote_endpoint().port());

        set_state(ConnectionState::Connected);
        if (cb) {
            cb(ec);
        }
        if (on_connect_) {
            on_connect_(ec);
        }
    });
}

void TcpConnection::start_read() {
    if (state_ != ConnectionState::Connected) {
        util::Logger::warn("TcpConnection::start_read called in state {}", to_string(state_));
        return;
    }
    do_read();
}

bool TcpConnection::write(const uint8_t* data, std::size_t length) {
    if (state_ != ConnectionState::Connected && state_ != ConnectionState::Disconnecting) {
        util::Logger::warn("TcpConnection::write called in state {}", to_string(state_));
        return false;
    }

    if (length == 0) {
        return true;
    }

    // Backpressure check: reject the write if the buffer is already over the limit.
    if (write_buffer_bytes_ + length > max_write_buffer_size_) {
        util::Logger::debug("TcpConnection: write rejected, buffer full ({} + {} > {})",
                            write_buffer_bytes_, length, max_write_buffer_size_);
        return false;
    }

    WriteBuffer buf;
    buf.data.assign(data, data + length);
    write_buffer_bytes_ += buf.data.size();
    write_queue_.push_back(std::move(buf));

    // Kick off the write chain if nothing is in flight.
    if (!write_in_progress_) {
        do_write();
    }

    return true;
}

bool TcpConnection::write(std::vector<uint8_t> data) {
    if (state_ != ConnectionState::Connected && state_ != ConnectionState::Disconnecting) {
        util::Logger::warn("TcpConnection::write called in state {}", to_string(state_));
        return false;
    }

    if (data.empty()) {
        return true;
    }

    if (write_buffer_bytes_ + data.size() > max_write_buffer_size_) {
        util::Logger::debug("TcpConnection: write rejected, buffer full ({} + {} > {})",
                            write_buffer_bytes_, data.size(), max_write_buffer_size_);
        return false;
    }

    std::size_t len = data.size();
    WriteBuffer buf;
    buf.data = std::move(data);
    write_buffer_bytes_ += len;
    write_queue_.push_back(std::move(buf));

    if (!write_in_progress_) {
        do_write();
    }

    return true;
}

void TcpConnection::close() {
    if (state_ == ConnectionState::Disconnected || state_ == ConnectionState::Disconnecting) {
        return;
    }

    util::Logger::debug("TcpConnection: initiating graceful close");

    set_state(ConnectionState::Disconnecting);

    // If there are pending writes, let the write completion handler handle
    // the final close.  Otherwise, close immediately.
    if (!write_in_progress_ && write_queue_.empty()) {
        do_close(std::error_code{});
    }
    // else: do_write completion will call do_close when the queue drains.
}

void TcpConnection::force_close() {
    if (state_ == ConnectionState::Disconnected) {
        return;
    }

    util::Logger::debug("TcpConnection: force close");

    // Discard pending writes.
    write_queue_.clear();
    write_buffer_bytes_ = 0;
    write_in_progress_ = false;

    do_close(asio::error::operation_aborted);
}

// ===========================================================================
// Accessors
// ===========================================================================

ConnectionState TcpConnection::state() const noexcept {
    return state_;
}

bool TcpConnection::is_connected() const noexcept {
    return state_ == ConnectionState::Connected;
}

std::size_t TcpConnection::write_buffer_size() const noexcept {
    return write_buffer_bytes_;
}

asio::ip::tcp::endpoint TcpConnection::remote_endpoint() const noexcept {
    std::error_code ec;
    auto ep = socket_.remote_endpoint(ec);
    if (ec) {
        return {};
    }
    return ep;
}

asio::ip::tcp::endpoint TcpConnection::local_endpoint() const noexcept {
    std::error_code ec;
    auto ep = socket_.local_endpoint(ec);
    if (ec) {
        return {};
    }
    return ep;
}

asio::ip::tcp::socket& TcpConnection::socket() noexcept {
    return socket_;
}

asio::any_io_executor TcpConnection::get_executor() noexcept {
    return socket_.get_executor();
}

// ===========================================================================
// Internal helpers
// ===========================================================================

void TcpConnection::do_read() {
    if (state_ != ConnectionState::Connected) {
        return;
    }

    auto self = shared_from_this();
    socket_.async_read_some(
        asio::buffer(read_buffer_),
        [this, self](const std::error_code& ec, std::size_t bytes_transferred) {
            if (ec) {
                if (ec == asio::error::eof || ec == asio::error::connection_reset ||
                    ec == asio::error::operation_aborted) {
                    // Normal close / cancellation -- not a reportable error.
                    util::Logger::debug("TcpConnection: read ended: {}", ec.message());
                } else {
                    util::Logger::debug("TcpConnection: read error: {}", ec.message());
                    notify_error(ec);
                }

                // If we are not already in a closing state, initiate close.
                if (state_ == ConnectionState::Connected) {
                    set_state(ConnectionState::Disconnecting);
                    do_close(ec);
                }
                return;
            }

            // Deliver data to the application.
            if (on_data_ && bytes_transferred > 0) {
                on_data_(read_buffer_.data(), bytes_transferred);
            }

            // Continue reading.
            do_read();
        });
}

void TcpConnection::do_write() {
    if (write_queue_.empty()) {
        write_in_progress_ = false;

        // If we are disconnecting and all writes have drained, close now.
        if (state_ == ConnectionState::Disconnecting) {
            do_close(std::error_code{});
        }
        return;
    }

    write_in_progress_ = true;

    // Take the front buffer.
    auto& front = write_queue_.front();

    auto self = shared_from_this();
    asio::async_write(socket_, asio::buffer(front.data),
                      [this, self](const std::error_code& ec, std::size_t bytes_transferred) {
                          if (ec) {
                              util::Logger::debug("TcpConnection: write error: {}", ec.message());
                              write_in_progress_ = false;
                              notify_error(ec);

                              // On write error, transition to disconnecting and close.
                              if (state_ == ConnectionState::Connected) {
                                  set_state(ConnectionState::Disconnecting);
                              }
                              do_close(ec);
                              return;
                          }

                          // Remove the completed buffer from the queue.
                          assert(!write_queue_.empty());
                          write_buffer_bytes_ -= write_queue_.front().data.size();
                          write_queue_.pop_front();

                          (void)bytes_transferred;  // Already accounted for via buffer size.

                          // Continue with the next queued buffer.
                          do_write();
                      });
}

void TcpConnection::do_close(const std::error_code& ec) {
    if (state_ == ConnectionState::Disconnected) {
        return;
    }

    // Shutdown the socket gracefully.
    std::error_code shutdown_ec;
    if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, shutdown_ec);
        socket_.close(shutdown_ec);
    }

    // Clear any remaining write state.
    write_queue_.clear();
    write_buffer_bytes_ = 0;
    write_in_progress_ = false;

    set_state(ConnectionState::Disconnected);

    if (on_disconnect_) {
        on_disconnect_(ec);
    }
}

void TcpConnection::notify_error(const std::error_code& ec) {
    if (on_error_ && ec) {
        on_error_(ec);
    }
}

void TcpConnection::set_state(ConnectionState new_state) {
    if (state_ != new_state) {
        util::Logger::trace("TcpConnection: {} -> {}", to_string(state_), to_string(new_state));
        state_ = new_state;
    }
}

}  // namespace toxtunnel::core
