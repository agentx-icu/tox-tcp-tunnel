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

// NOLINTBEGIN(clang-analyzer-core.NullDereference)
// asio's any_executor type-erasure layer trips clang's path-sensitive
// null-pointer checker (object_fns_->target() can look null in the
// abstract domain even though it's always set by make_strand). The
// false positive is reproducible at every make_strand<any_io_executor>
// call site; suppress at the source.
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
// NOLINTEND(clang-analyzer-core.NullDereference)

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
    max_write_buffer_size_.store(bytes, std::memory_order_relaxed);
}

std::size_t TcpConnection::max_write_buffer_size() const noexcept {
    return max_write_buffer_size_.load(std::memory_order_relaxed);
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

void TcpConnection::set_on_read_eof(ReadEofCallback cb) {
    on_read_eof_ = std::move(cb);
}

void TcpConnection::set_on_disconnect(DisconnectCallback cb) {
    on_disconnect_ = std::move(cb);
}

void TcpConnection::set_on_closed(std::function<void()> cb) {
    on_closed_ = std::move(cb);
}

void TcpConnection::set_on_error(ErrorCallback cb) {
    on_error_ = std::move(cb);
}

void TcpConnection::set_on_writable(WritableCallback cb) {
    on_writable_ = std::move(cb);
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
        // Routine close race: the local socket dropped while peer frames were
        // still in flight. One line per late frame at warn level flooded the
        // log (2k+ lines/s when a bulk transfer is aborted mid-flight).
        util::Logger::debug("TcpConnection::write called in state {}", to_string(s));
        return false;
    }
    if (send_shutdown_requested_.load(std::memory_order_acquire)) {
        util::Logger::debug("TcpConnection::write called after send shutdown requested");
        return false;
    }
    if (length == 0) {
        return true;
    }

    // C-03 backpressure: when over the limit we still ENQUEUE (so tunnel egress
    // is never silently dropped — that truncates a lossless stream) but return
    // false so the caller defers TUNNEL_ACK. The queue is then bounded by the
    // peer's send window, which stops growing once ACKs are withheld.
    const bool over = write_buffer_bytes_.load(std::memory_order_relaxed) + length >
                      max_write_buffer_size_.load(std::memory_order_relaxed);

    std::vector<uint8_t> buf(data, data + length);
    auto self = shared_from_this();
    asio::post(strand_, [this, self, buf = std::move(buf)]() mutable {
        ConnectionState inner_s = state_.load(std::memory_order_acquire);
        if (inner_s != ConnectionState::Connected && inner_s != ConnectionState::Disconnecting) {
            return;
        }
        enqueue_write_locked(WriteBuffer{std::move(buf), {}});
    });
    return !over;
}

bool TcpConnection::write(std::vector<uint8_t> data) {
    ConnectionState s = state_.load(std::memory_order_acquire);
    if (s != ConnectionState::Connected && s != ConnectionState::Disconnecting) {
        // Routine close race — see write(const uint8_t*, size_t).
        util::Logger::debug("TcpConnection::write called in state {}", to_string(s));
        return false;
    }
    if (send_shutdown_requested_.load(std::memory_order_acquire)) {
        util::Logger::debug("TcpConnection::write called after send shutdown requested");
        return false;
    }
    if (data.empty()) {
        return true;
    }
    const bool over = write_buffer_bytes_.load(std::memory_order_relaxed) + data.size() >
                      max_write_buffer_size_.load(std::memory_order_relaxed);

    auto self = shared_from_this();
    asio::post(strand_, [this, self, data = std::move(data)]() mutable {
        ConnectionState inner_s = state_.load(std::memory_order_acquire);
        if (inner_s != ConnectionState::Connected && inner_s != ConnectionState::Disconnecting) {
            return;
        }
        enqueue_write_locked(WriteBuffer{std::move(data), {}});
    });
    return !over;
}

bool TcpConnection::write(OwnedBufferView buf) {
    ConnectionState s = state_.load(std::memory_order_acquire);
    if (s != ConnectionState::Connected && s != ConnectionState::Disconnecting) {
        // Routine close race — see write(const uint8_t*, size_t).
        util::Logger::debug("TcpConnection::write(view) called in state {}", to_string(s));
        return false;
    }
    if (send_shutdown_requested_.load(std::memory_order_acquire)) {
        util::Logger::debug("TcpConnection::write(view) called after send shutdown requested");
        return false;
    }
    if (buf.empty()) {
        return true;
    }
    const bool over = write_buffer_bytes_.load(std::memory_order_relaxed) + buf.size() >
                      max_write_buffer_size_.load(std::memory_order_relaxed);

    auto self = shared_from_this();
    asio::post(strand_, [this, self, buf = std::move(buf)]() mutable {
        ConnectionState inner_s = state_.load(std::memory_order_acquire);
        if (inner_s != ConnectionState::Connected && inner_s != ConnectionState::Disconnecting) {
            return;
        }
        enqueue_write_locked(WriteBuffer{{}, std::move(buf)});
    });
    return !over;
}

void TcpConnection::enqueue_write_locked(WriteBuffer&& wb) {
    const std::size_t len = wb.size();
    if (len == 0) {
        return;
    }
    const std::size_t total = write_buffer_bytes_.fetch_add(len, std::memory_order_relaxed) + len;
    if (total >= max_write_buffer_size_.load(std::memory_order_relaxed)) {
        // Crossed the backpressure limit; remember so the drain in do_write()
        // fires on_writable_ once the socket catches up (C-03).
        write_hit_watermark_ = true;
    }
    write_queue_.push_back(std::move(wb));
    if (!write_in_progress_) {
        do_write();
    }
}

void TcpConnection::close() {
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() {
        ConnectionState s = state_.load(std::memory_order_acquire);
        if (s == ConnectionState::Disconnected) {
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

void TcpConnection::shutdown_send() {
    send_shutdown_requested_.store(true, std::memory_order_release);
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() {
        if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnected) {
            return;
        }
        maybe_shutdown_send_locked();
    });
}

void TcpConnection::force_close() {
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() {
        if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnected) {
            return;
        }
        util::Logger::debug("TcpConnection: force close");

        // Discard pending writes. Subtract their bytes from the
        // accounting; do NOT touch the in-flight write — its completion
        // handler (which holds the buffer in a `shared_ptr<WriteBuffer>`)
        // will fire with `operation_aborted` and refund its own bytes.
        // The previous `store(0)` + `write_in_progress_ = false` racey
        // pair caused an underflow because the in-flight completion still
        // ran fetch_sub after store(0). (C-10 / H-13 in the 2026-05-20
        // review.)
        std::size_t pending = 0;
        for (auto& wb : write_queue_) {
            pending += wb.size();
        }
        if (pending > 0) {
            write_buffer_bytes_.fetch_sub(pending, std::memory_order_relaxed);
        }
        write_queue_.clear();
        // write_in_progress_ is intentionally left alone: the in-flight
        // completion lambda flips it back to false (or do_close handles
        // re-entry, since state_ is already Disconnected after do_close).

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

void TcpConnection::pause_read() {
    read_paused_.store(true, std::memory_order_release);
}

void TcpConnection::resume_read() {
    bool was_paused = read_paused_.exchange(false, std::memory_order_acq_rel);
    if (!was_paused) {
        return;
    }
    // Dispatch onto the strand and let do_read decide whether to actually
    // start a new async_read_some. Just posting do_read directly would
    // race with an in-flight read: if pause_read fired *after* do_read
    // had already submitted async_read_some, the completion would later
    // re-enter do_read and we'd end up with two concurrent reads on the
    // same socket (S16 in the 2026-05-20 follow-up). The `read_in_flight_`
    // guard inside do_read suppresses the second submission.
    auto self = shared_from_this();
    asio::post(strand_, [this, self]() { do_read(); });
}

void TcpConnection::do_read() {
    if (state_.load(std::memory_order_acquire) != ConnectionState::Connected) {
        return;
    }
    if (read_closed_) {
        return;
    }
    if (read_paused_.load(std::memory_order_acquire)) {
        // Backpressure: skip posting a new read. resume_read() will
        // re-arm the loop when downstream drains.
        return;
    }
    if (read_in_flight_) {
        // A previous async_read_some is still outstanding. Its completion
        // handler will call do_read() again — no need to submit a second
        // read on the same socket.
        return;
    }

    read_in_flight_ = true;
    auto self = shared_from_this();
    socket_.async_read_some(
        asio::buffer(read_buffer_),
        asio::bind_executor(strand_, [this, self](const std::error_code& ec,
                                                  std::size_t bytes_transferred) {
            read_in_flight_ = false;
            if (ec) {
                if (ec == asio::error::eof) {
                    util::Logger::debug("TcpConnection: read ended: {}", ec.message());
                    read_closed_ = true;
                    if (on_read_eof_) {
                        on_read_eof_();
                    } else if (state_.load(std::memory_order_acquire) ==
                               ConnectionState::Connected) {
                        set_state(ConnectionState::Disconnecting);
                        do_close(ec);
                    }
                    return;
                }

                if (ec == asio::error::connection_reset || ec == asio::error::operation_aborted) {
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

        maybe_shutdown_send_locked();

        // If we are disconnecting and all writes have drained, close now.
        if (state_.load(std::memory_order_acquire) == ConnectionState::Disconnecting) {
            do_close(std::error_code{});
        }
        return;
    }

    write_in_progress_ = true;

    // Move the front entry into the completion lambda's captures so the
    // backing bytes outlive asio's internal buffer reference even if
    // force_close() / clear() races with the in-flight write (C-10 in
    // the 2026-05-20 review). Previously the lambda only held a
    // shared_from_this(), and `front.bytes()` pointed into the deque
    // node — a force_close that cleared the deque while the kernel
    // had not yet drained the buffer would leave asio with a dangling
    // pointer.
    auto inflight = std::make_shared<WriteBuffer>(std::move(write_queue_.front()));
    write_queue_.pop_front();

    auto self = shared_from_this();
    const auto* data_ptr = inflight->bytes();
    const auto data_size = inflight->size();
    asio::async_write(
        socket_, asio::buffer(data_ptr, data_size),
        asio::bind_executor(strand_, [this, self, inflight](const std::error_code& ec,
                                                            std::size_t bytes_transferred) {
            if (ec) {
                util::Logger::debug("TcpConnection: write error: {}", ec.message());
                write_in_progress_ = false;
                // The buffer for the failed write was already moved out
                // of write_queue_ before async_write started — its
                // accounting was charged at enqueue time but never
                // refunded by the normal pop path. Refund it now so
                // write_buffer_bytes_ does not skew permanently.
                write_buffer_bytes_.fetch_sub(inflight->size(), std::memory_order_relaxed);
                notify_error(ec);
                if (state_.load(std::memory_order_acquire) == ConnectionState::Connected) {
                    set_state(ConnectionState::Disconnecting);
                }
                do_close(ec);
                return;
            }

            const std::size_t remaining =
                write_buffer_bytes_.fetch_sub(inflight->size(), std::memory_order_relaxed) -
                inflight->size();
            // `inflight` releases either the owned `vector` or the shared
            // buffer ref held by the `OwnedBufferView` exactly when this
            // completion lambda destructs — RAII keeps the bytes alive
            // for the full duration of asio's internal use.

            // C-03: once the queue drains back below half the limit after having
            // crossed it, let the tunnel layer flush its deferred TUNNEL_ACK so
            // the peer's send window reopens. Half-limit hysteresis avoids
            // ACK thrash right at the boundary.
            if (write_hit_watermark_ &&
                remaining <= max_write_buffer_size_.load(std::memory_order_relaxed) / 2) {
                // Clear the watermark only if the callback fully flushed its
                // deferred work. If it returns false (e.g. the ACK send is
                // itself backpressured), keep the watermark set so the next
                // drained frame calls again — otherwise a one-shot clear could
                // strand the deferred ACK and stall the peer's window forever.
                const bool flushed = on_writable_ ? on_writable_() : true;
                if (flushed) {
                    write_hit_watermark_ = false;
                }
            }

            (void)bytes_transferred;
            do_write();
        }));
}

void TcpConnection::maybe_shutdown_send_locked() {
    if (!send_shutdown_requested_.load(std::memory_order_acquire) || send_shutdown_done_ ||
        write_in_progress_ || !write_queue_.empty()) {
        return;
    }

    if (!socket_.is_open()) {
        return;
    }
    std::error_code shutdown_ec;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_send, shutdown_ec);
    if (!shutdown_ec || shutdown_ec == asio::error::not_connected) {
        send_shutdown_done_ = true;
        util::Logger::debug("TcpConnection: send half shut down");
    } else {
        util::Logger::debug("TcpConnection: send half shutdown failed: {}", shutdown_ec.message());
        notify_error(shutdown_ec);
    }
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

    // Symmetric with force_close: subtract only the queued bytes, not
    // the in-flight write's bytes. The in-flight completion lambda
    // holds its WriteBuffer in a shared_ptr and will refund itself when
    // operation_aborted fires.
    std::size_t pending = 0;
    for (auto& wb : write_queue_) {
        pending += wb.size();
    }
    if (pending > 0) {
        write_buffer_bytes_.fetch_sub(pending, std::memory_order_relaxed);
    }
    write_queue_.clear();
    write_in_progress_ = false;
    read_closed_ = true;
    send_shutdown_requested_.store(true, std::memory_order_release);
    send_shutdown_done_ = true;

    set_state(ConnectionState::Disconnected);

    if (on_disconnect_) {
        on_disconnect_(ec);
    }
    // Owner/lifecycle hook (e.g. TcpListener's active-connection decrement).
    // Fired after on_disconnect_ and, like it, exactly once per connection
    // because do_close() short-circuits once state is Disconnected.
    if (on_closed_) {
        on_closed_();
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
