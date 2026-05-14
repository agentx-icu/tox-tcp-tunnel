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

    void set_on_connect(ConnectCallback cb);
    void set_on_data(DataCallback cb);
    void set_on_disconnect(DisconnectCallback cb);
    void set_on_error(ErrorCallback cb);

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

    /// Queue data for asynchronous writing.
    ///
    /// @return `true` if the data was accepted; `false` if the write buffer
    ///         has exceeded the backpressure limit and the caller should
    ///         stop sending until the buffer drains.
    bool write(const uint8_t* data, std::size_t length);

    /// Convenience overload accepting a vector.
    bool write(std::vector<uint8_t> data);

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
    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Post the next async_read_some if reading is active.
    void do_read();

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
    struct WriteBuffer {
        std::vector<uint8_t> data;
    };
    std::deque<WriteBuffer> write_queue_;
    /// Atomic so write() can do a fast pre-check before posting onto the
    /// strand. Updated only from inside the strand.
    std::atomic<std::size_t> write_buffer_bytes_{0};
    bool write_in_progress_ = false;

    // Limits
    std::size_t max_write_buffer_size_ = kDefaultMaxWriteBufferSize;

    // Callbacks
    ConnectCallback on_connect_;
    DataCallback on_data_;
    DisconnectCallback on_disconnect_;
    ErrorCallback on_error_;
};

}  // namespace toxtunnel::core
