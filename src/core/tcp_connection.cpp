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
    : socket_(io_ctx),
      strand_(asio::make_strand(io_ctx.get_executor())),
      read_buffer_(kDefaultReadBufferSize) {}

TcpConnection::TcpConnection(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)),
      strand_(asio::make_strand(socket_.get_executor())),
      state_(ConnectionState::Connected),
      read_buffer_(kDefaultReadBufferSize) {
    // SSH and other interactive workloads send tiny segments; Nagle's algorithm
    // (default) coalesces them into ~40ms windows on macOS, which shows up as
    // perceptible keyboard echo lag. Tunneled traffic is already buffered at
    // higher layers, so we always disable Nagle.
    std::error_code nodelay_ec;
    socket_.set_option(asio::ip::tcp::no_delay(true), nodelay_ec);
}

TcpConnection::~TcpConnection() {
    // No async ops can be in flight: each held a shared_ptr<TcpConnection>, so
    // we couldn't have reached the destructor unless they all completed. Close
    // the socket synchronously here — there is no strand contention to worry
    // about.
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
    // Atomically claim the state transition Disconnected -> Connecting. We
    // initiate socket_.async_connect synchronously rather than posting onto
    // strand_, so the kernel sees connects from this client in the same order
    // the caller issued them (important for tests/integrations that pair
    // accepted server sockets with clients by index). Asio permits initiating
    // an async op on a socket from any thread when no other op of the same
    // kind is in flight, which is guaranteed here by the CAS on state_.
    ConnectionState expected = ConnectionState::Disconnected;
    if (!state_.compare_exchange_strong(expected, ConnectionState::Connecting,
                                        std::memory_order_acq_rel)) {
        util::Logger::warn("TcpConnection::async_connect called in state {}", to_string(expected));
        if (cb) {
            cb(asio::error::already_connected);
        }
        return;
    }

    auto self = shared_from_this();
    socket_.async_connect(
        endpoint,
        asio::bind_executor(strand_, [this, self, cb = std::move(cb)](const std::error_code& ec) {
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

            // Disable Nagle on outbound sockets (see adopting-ctor for rationale).
            std::error_code nodelay_ec;
            socket_.set_option(asio::ip::tcp::no_delay(true), nodelay_ec);

            set_state(ConnectionState::Connected);
            if (cb) {
                cb(ec);
            }
            if (on_connect_) {
                on_connect_(ec);
            }
        }));
}

void TcpConnection::start_read() {
    // Initiate the first read directly. After this, do_read chains itself from
    // inside the strand-bound completion handler, so we only need to start it
    // once. Sync initiation also avoids reordering relative to peer state.
    if (state_.load(std::memory_order_acquire) != ConnectionState::Connected) {
        util::Logger::warn("TcpConnection::start_read called in state {}",
                           to_string(state_.load()));
        return;
    }
    do_read();
}

bool TcpConnection::write(const uint8_t* data, std::size_t length) {
    ConnectionState s = state_.load(std::memory_order_acquire);
    if (s != ConnectionState::Connected && s != ConnectionState::Disconnecting) {
        util::Logger::warn("TcpConnection::write called in state {}", to_string(s));
        return false;
    }
    if (length == 0) {
        return true;
    }

    // Snapshot check before paying the copy + post. Real enforcement still
    // happens inside the strand.
    if (write_buffer_bytes_.load(std::memory_order_relaxed) + length > max_write_buffer_size_) {
        util::Logger::debug("TcpConnection: write rejected, buffer full");
        return false;
    }

    std::vector<uint8_t> buf(data, data + length);
    auto self = shared_from_this();
    asio::post(strand_, [this, self, buf = std::move(buf)]() mutable {
        ConnectionState inner_s = state_.load(std::memory_order_acquire);
        if (inner_s != ConnectionState::Connected && inner_s != ConnectionState::Disconnecting) {
            return;
        }
        std::size_t len = buf.size();
        if (write_buffer_bytes_.load(std::memory_order_relaxed) + len > max_write_buffer_size_) {
            return;
        }
        WriteBuffer wb;
        wb.data = std::move(buf);
        write_buffer_bytes_.fetch_add(len, std::memory_order_relaxed);
        write_queue_.push_back(std::move(wb));
        if (!write_in_progress_) {
            do_write();
        }
    });
    return true;
}

bool TcpConnection::write(std::vector<uint8_t> data) {
    ConnectionState s = state_.load(std::memory_order_acquire);
    if (s != ConnectionState::Connected && s != ConnectionState::Disconnecting) {
        util::Logger::warn("TcpConnection::write called in state {}", to_string(s));
        return false;
    }
    if (data.empty()) {
        return true;
    }
    if (write_buffer_bytes_.load(std::memory_order_relaxed) + data.size() >
        max_write_buffer_size_) {
        util::Logger::debug("TcpConnection: write rejected, buffer full");
        return false;
    }

    auto self = shared_from_this();
    asio::post(strand_, [this, self, data = std::move(data)]() mutable {
        ConnectionState inner_s = state_.load(std::memory_order_acquire);
        if (inner_s != ConnectionState::Connected && inner_s != ConnectionState::Disconnecting) {
            return;
        }
        std::size_t len = data.size();
        if (write_buffer_bytes_.load(std::memory_order_relaxed) + len > max_write_buffer_size_) {
            return;
        }
        WriteBuffer wb;
        wb.data = std::move(data);
        write_buffer_bytes_.fetch_add(len, std::memory_order_relaxed);
        write_queue_.push_back(std::move(wb));
        if (!write_in_progress_) {
            do_write();
        }
    });
    return true;
}

void TcpConnection::close() {
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() {
        ConnectionState s = state_.load(std::memory_order_acquire);
        if (s == ConnectionState::Disconnected || s == ConnectionState::Disconnecting) {
            return;
        }
        util::Logger::debug("TcpConnection: initiating graceful close");
        set_state(ConnectionState::Disconnecting);

        // If there are pending writes, let the write completion handler handle
        // the final close. Otherwise, close immediately.
        if (!write_in_progress_ && write_queue_.empty()) {
            do_close(std::error_code{});
        }
        // else: do_write completion will call do_close when the queue drains.
    });
}

void TcpConnection::force_close() {
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() {
        if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnected) {
            return;
        }
        util::Logger::debug("TcpConnection: force close");

        // Discard pending writes.
        write_queue_.clear();
        write_buffer_bytes_.store(0, std::memory_order_relaxed);
        write_in_progress_ = false;

        do_close(asio::error::operation_aborted);
    });
}

// ===========================================================================
// Accessors
// ===========================================================================

ConnectionState TcpConnection::state() const noexcept {
    return state_.load(std::memory_order_acquire);
}

bool TcpConnection::is_connected() const noexcept {
    return state_.load(std::memory_order_acquire) == ConnectionState::Connected;
}

std::size_t TcpConnection::write_buffer_size() const noexcept {
    return write_buffer_bytes_.load(std::memory_order_relaxed);
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
// Internal helpers — all run inside strand_
// ===========================================================================

void TcpConnection::do_read() {
    if (state_.load(std::memory_order_acquire) != ConnectionState::Connected) {
        return;
    }

    auto self = shared_from_this();
    socket_.async_read_some(
        asio::buffer(read_buffer_),
        asio::bind_executor(
            strand_, [this, self](const std::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
                        ec == asio::error::operation_aborted) {
                        util::Logger::debug("TcpConnection: read ended: {}", ec.message());
                    } else {
                        util::Logger::debug("TcpConnection: read error: {}", ec.message());
                        notify_error(ec);
                    }

                    if (state_.load(std::memory_order_acquire) == ConnectionState::Connected) {
                        set_state(ConnectionState::Disconnecting);
                        do_close(ec);
                    }
                    return;
                }

                if (on_data_ && bytes_transferred > 0) {
                    on_data_(read_buffer_.data(), bytes_transferred);
                }

                do_read();
            }));
}

void TcpConnection::do_write() {
    if (write_queue_.empty()) {
        write_in_progress_ = false;

        // If we are disconnecting and all writes have drained, close now.
        if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnecting) {
            do_close(std::error_code{});
        }
        return;
    }

    write_in_progress_ = true;
    auto& front = write_queue_.front();

    auto self = shared_from_this();
    asio::async_write(
        socket_, asio::buffer(front.data),
        asio::bind_executor(
            strand_, [this, self](const std::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    util::Logger::debug("TcpConnection: write error: {}", ec.message());
                    write_in_progress_ = false;
                    notify_error(ec);
                    if (state_.load(std::memory_order_acquire) == ConnectionState::Connected) {
                        set_state(ConnectionState::Disconnecting);
                    }
                    do_close(ec);
                    return;
                }

                assert(!write_queue_.empty());
                write_buffer_bytes_.fetch_sub(write_queue_.front().data.size(),
                                              std::memory_order_relaxed);
                write_queue_.pop_front();

                (void)bytes_transferred;
                do_write();
            }));
}

void TcpConnection::do_close(const std::error_code& ec) {
    if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnected) {
        return;
    }

    std::error_code shutdown_ec;
    if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, shutdown_ec);
        socket_.close(shutdown_ec);
    }

    write_queue_.clear();
    write_buffer_bytes_.store(0, std::memory_order_relaxed);
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
    ConnectionState old = state_.exchange(new_state, std::memory_order_acq_rel);
    if (old != new_state) {
        util::Logger::trace("TcpConnection: {} -> {}", to_string(old), to_string(new_state));
    }
}

}  // namespace toxtunnel::core
