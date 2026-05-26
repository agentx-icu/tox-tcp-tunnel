#pragma once

#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "toxtunnel/core/owned_buffer.hpp"

namespace toxtunnel::core {

/// Connection lifecycle states.
///
/// The valid transitions are:
///   Disconnected -> Connecting -> Connected -> Disconnecting -> Disconnected
/// An error may also cause a direct transition from any state to Disconnected.
enum class ConnectionState : std::uint8_t {
    Disconnected,   ///< Socket is closed; no I/O in progress.
    Connecting,     ///< An async connect is in progress.
    Connected,      ///< Socket is open and ready for read/write.
    Disconnecting,  ///< Graceful shutdown initiated; draining writes.
};

/// Return a human-readable label for a connection state.
std::string_view to_string(ConnectionState state) noexcept;

// ---------------------------------------------------------------------------
// Callback signatures
// ---------------------------------------------------------------------------

/// Called when an async connect completes (success or failure).
using ConnectCallback = std::function<void(const std::error_code&)>;

/// Called when data has been received.  The span is valid only for the
/// duration of the callback.
using DataCallback = std::function<void(const uint8_t* data, std::size_t length)>;

/// Called when the connection has been fully closed.
using DisconnectCallback = std::function<void(const std::error_code&)>;

/// Called when an error occurs during an async operation.
using ErrorCallback = std::function<void(const std::error_code&)>;

/// Called (on the strand) when the write queue drains back below the
/// low-water mark after having crossed the backpressure limit. Lets the
/// tunnel layer flush a deferred TUNNEL_ACK so the peer's send window
/// reopens once the local socket has caught up (C-03 receiver flow control).
///
/// Returns true if the deferred work was fully flushed, false if it still has
/// pending work (e.g. the ACK send itself backpressured). On false the
/// TcpConnection keeps the watermark armed so the next drain step calls again,
/// instead of clearing it one-shot and stranding the deferred ACK.
using WritableCallback = std::function<bool()>;

// ---------------------------------------------------------------------------
// TcpConnection
// ---------------------------------------------------------------------------

/// Async TCP socket wrapper with state management and backpressure control.
///
/// TcpConnection wraps an `asio::ip::tcp::socket` and provides:
/// - Lifecycle state tracking (Connecting -> Connected -> Disconnecting -> Disconnected)
/// - Async connect / read / write operations
/// - Write-side backpressure via a configurable write-buffer byte limit
/// - Graceful shutdown that drains the write queue before closing
/// - Event callbacks for connect, data-received, disconnect, and error
///
/// Public operations may be invoked from any thread. All internal access
/// to the socket and queue state is serialized through an internal
/// asio::strand so the TCP I/O thread pool and the Tox iteration thread
/// can both call write()/close() safely. Callbacks fire on the strand,
/// which is bound to one of the io_context worker threads.
///
/// Typical usage:
/// @code
///   auto conn = std::make_shared<TcpConnection>(io_ctx);
///   conn->set_on_data([](const uint8_t* d, size_t n) { ... });
///   conn->set_on_disconnect([](auto ec) { ... });
///   conn->async_connect(endpoint, [](auto ec) { ... });
/// @endcode
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
   public:
    /// Default maximum bytes allowed to be queued for writing before
    /// backpressure kicks in.
    static constexpr std::size_t kDefaultMaxWriteBufferSize = 1024 * 1024;  // 1 MiB

    /// Default read buffer size per async_read_some call.
    static constexpr std::size_t kDefaultReadBufferSize = 8192;  // 8 KiB

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct from an io_context.  A new socket is created internally.
    explicit TcpConnection(asio::io_context& io_ctx);

    /// Construct by adopting an already-connected socket (e.g. from an
    /// acceptor).  The connection state is set to Connected.
    explicit TcpConnection(asio::ip::tcp::socket socket);

    /// Non-copyable, non-movable. Atomic state members preclude default moves,
    /// and the class is always handled via shared_ptr (acceptor hand-off
    /// passes the socket by value, then constructs a fresh TcpConnection in
    /// place via make_shared).
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&&) = delete;
    TcpConnection& operator=(TcpConnection&&) = delete;

    ~TcpConnection();

    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    /// Set the maximum number of bytes that may be queued for writing
    /// before `write()` starts returning `false` (backpressure signal).
    void set_max_write_buffer_size(std::size_t bytes) noexcept;

    /// Return the current write-buffer byte limit.
    [[nodiscard]] std::size_t max_write_buffer_size() const noexcept;

    /// Set the size of the internal read buffer (per read call).
    void set_read_buffer_size(std::size_t bytes);

    /// Return the current read buffer size.
    [[nodiscard]] std::size_t read_buffer_size() const noexcept;

    // -----------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------

    // NOTE (thread-safety contract, H-10): set_on_connect / set_on_data /
    // set_on_disconnect / set_on_error / set_on_writable / set_read_buffer_size
    // are NOT internally synchronized and must be called during setup — before
    // start_read() / async_connect() begin delivering — never concurrently with
    // live I/O. The write-buffer limit (set_max_write_buffer_size) IS atomic and
    // may be changed at any time. Public I/O operations (write/close/pause/
    // resume) remain safe from any thread.
    void set_on_connect(ConnectCallback cb);
    void set_on_data(DataCallback cb);
    void set_on_disconnect(DisconnectCallback cb);
    void set_on_error(ErrorCallback cb);

    /// Set the low-water-mark callback (see WritableCallback). Fired on the
    /// strand once the write queue drains back below half the configured limit
    /// after having crossed it. Configure before start_read().
    void set_on_writable(WritableCallback cb);

    // -----------------------------------------------------------------
    // Connection lifecycle
    // -----------------------------------------------------------------

    /// Initiate an asynchronous connect to the given endpoint.
    ///
    /// The on_connect callback (and the optional @p cb parameter) are
    /// invoked when the operation completes.
    ///
    /// @pre state() == Disconnected
    void async_connect(const asio::ip::tcp::endpoint& endpoint, ConnectCallback cb = nullptr);

    /// Begin reading from the socket.  Received data is delivered via
    /// the on_data callback.  Reading continues until the connection is
    /// closed or an error occurs.
    ///
    /// @pre state() == Connected
    void start_read();

    /// Pause / resume the async read loop without closing the socket.
    /// Used by the tunnel layer to propagate downstream backpressure
    /// (when the Tox send window is full) back to the TCP peer: pausing
    /// stops posting new `async_read_some` calls, which lets the kernel
    /// receive buffer fill up and the TCP receive window collapse — the
    /// remote peer then naturally throttles. `resume_read` re-posts the
    /// read once downstream has drained. Both are safe to call from any
    /// thread and idempotent. T5/C-18 in the 2026-05-20 review.
    void pause_read();
    void resume_read();

    /// True if the read loop is currently paused (paused_read_ flag).
    [[nodiscard]] bool is_read_paused() const noexcept {
        return read_paused_.load(std::memory_order_acquire);
    }

    /// Queue data for asynchronous writing.
    ///
    /// @return `true` if the data was accepted; `false` if the write buffer
    ///         has exceeded the backpressure limit and the caller should
    ///         stop sending until the buffer drains.
    bool write(const uint8_t* data, std::size_t length);

    /// Convenience overload accepting a vector.
    bool write(std::vector<uint8_t> data);

    /// Zero-copy overload: enqueue a view onto an already-allocated buffer
    /// whose lifetime is managed by a `shared_ptr`. The buffer is held alive
    /// until `asio::async_write` completes; no payload copy occurs at this
    /// boundary. This is the entry point for the inbound TUNNEL_DATA path:
    /// bytes deserialized on the strand are forwarded straight through to
    /// the TCP socket without an intermediate `vector<uint8_t>` copy.
    ///
    /// @return `true` if the buffer was accepted; `false` if the connection
    ///         is not writable or the write buffer would exceed the
    ///         backpressure limit.
    bool write(OwnedBufferView buf);

    /// Initiate a graceful shutdown.  Any data already queued for writing
    /// will be flushed before the socket is closed.  The on_disconnect
    /// callback fires once the shutdown is complete.
    void close();

    /// Immediately close the socket, discarding pending writes.
    void force_close();

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the current connection state.
    [[nodiscard]] ConnectionState state() const noexcept;

    /// Return true when the connection is in the Connected state.
    [[nodiscard]] bool is_connected() const noexcept;

    /// Return the number of bytes currently queued for writing.
    [[nodiscard]] std::size_t write_buffer_size() const noexcept;

    /// Return the remote endpoint, or a default-constructed endpoint if
    /// the socket is not connected.
    [[nodiscard]] asio::ip::tcp::endpoint remote_endpoint() const noexcept;

    /// Return the local endpoint, or a default-constructed endpoint if
    /// the socket is not bound.
    [[nodiscard]] asio::ip::tcp::endpoint local_endpoint() const noexcept;

    /// Return a reference to the underlying socket.
    [[nodiscard]] asio::ip::tcp::socket& socket() noexcept;

    /// Return the executor associated with this connection.
    [[nodiscard]] asio::any_io_executor get_executor() noexcept;

   private:
    // Forward declaration; full definition lives in the data-members section.
    struct WriteBuffer;

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Post the next async_read_some if reading is active.
    void do_read();

    /// Append an already-built WriteBuffer to the queue, update accounting,
    /// arm the backpressure watermark, and kick do_write() if idle. Must run
    /// on the strand. Pre-checked by callers for connection state.
    void enqueue_write_locked(WriteBuffer&& wb);

    /// If a write is not already in flight, dequeue the next buffer and
    /// start an async_write.
    void do_write();

    /// Perform the final socket close and invoke the disconnect callback.
    void do_close(const std::error_code& ec);

    /// Notify the error callback, if set.
    void notify_error(const std::error_code& ec);

    /// Transition to a new state.
    void set_state(ConnectionState new_state);

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    asio::ip::tcp::socket socket_;

    /// Strand serializing all socket ops + queue mutations. Bound to one of
    /// the io_context's worker threads; public methods may be called from any
    /// thread and post their work here.
    asio::strand<asio::any_io_executor> strand_;

    /// Atomic so external threads (e.g. is_connected() probe from the Tox
    /// thread) can read it without taking a lock. All transitions happen
    /// inside the strand.
    std::atomic<ConnectionState> state_{ConnectionState::Disconnected};

    // Read state — touched only inside the strand.
    std::vector<uint8_t> read_buffer_;

    // Write state — touched only inside the strand.
    //
    // Each queued buffer can carry either an owned `vector<uint8_t>` (the
    // legacy path used by outbound TCP writes and write-coalesced frames)
    // OR an `OwnedBufferView` referring to an externally-allocated buffer
    // (the zero-copy inbound TUNNEL_DATA path). At most one of `data` or
    // `view` is meaningful per entry: when `view` is non-empty, it wins.
    struct WriteBuffer {
        std::vector<uint8_t> data;
        OwnedBufferView view;

        [[nodiscard]] std::size_t size() const noexcept {
            return !view.empty() ? view.size() : data.size();
        }

        [[nodiscard]] const uint8_t* bytes() const noexcept {
            return !view.empty() ? view.data().data() : data.data();
        }
    };
    std::deque<WriteBuffer> write_queue_;
    /// Atomic so write() can do a fast pre-check before posting onto the
    /// strand. Updated only from inside the strand.
    std::atomic<std::size_t> write_buffer_bytes_{0};
    bool write_in_progress_ = false;

    /// Read-loop pause flag. When true, `do_read()` returns early without
    /// posting another async_read_some. Flipped by `pause_read` /
    /// `resume_read` from arbitrary threads (atomic).
    std::atomic<bool> read_paused_{false};

    /// True between async_read_some submission and its completion. Plain
    /// bool because all reads/writes happen on `strand_`. Guards against
    /// `resume_read` posting a second concurrent read while the previous
    /// one is still in flight (S16 in the 2026-05-20 follow-up).
    bool read_in_flight_{false};

    /// True once a write enqueue pushed the queue at/above the backpressure
    /// limit; reset (and on_writable_ fired) when the queue drains back below
    /// half the limit. Strand-only. Drives the receiver-side TUNNEL_ACK
    /// deferral (C-03): write() keeps accepting tunnel egress so no bytes are
    /// dropped, but signals the caller to withhold ACKs until the socket
    /// catches up, bounding the queue by the peer's send window.
    bool write_hit_watermark_{false};

    // Limits. Atomic so write()'s fast-path pre-check can read it from any
    // thread while set_max_write_buffer_size() runs concurrently (H-10).
    std::atomic<std::size_t> max_write_buffer_size_{kDefaultMaxWriteBufferSize};

    // Callbacks
    ConnectCallback on_connect_;
    DataCallback on_data_;
    DisconnectCallback on_disconnect_;
    ErrorCallback on_error_;
    WritableCallback on_writable_;
};

}  // namespace toxtunnel::core
