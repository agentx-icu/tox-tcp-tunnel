#pragma once

#include <asio.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "tcp_connection.hpp"

namespace toxtunnel::core {

/// Asynchronous TCP listener (acceptor) with connection limiting.
///
/// TcpListener wraps an `asio::ip::tcp::acceptor` and provides:
/// - Binding to a local address and port
/// - An asynchronous accept loop that hands off accepted sockets as
///   `std::shared_ptr<TcpConnection>` instances
/// - A configurable maximum connection limit; when the limit is reached
///   the accept loop pauses and resumes automatically when
///   `on_connection_closed()` is called to decrement the count
/// - Graceful stop/close methods
///
/// All operations must be invoked from threads running the associated
/// io_context.  The accept callback is dispatched on the io_context's
/// executor.
///
/// Typical usage:
/// @code
///   asio::io_context io;
///   TcpListener listener(io, 8080);
///   listener.set_max_connections(100);
///   listener.start_accept([](std::shared_ptr<TcpConnection> conn) {
///       // handle new connection ...
///   });
///   io.run();
/// @endcode
class TcpListener {
   public:
    /// Callback invoked for each accepted connection.
    using AcceptHandler = std::function<void(std::shared_ptr<TcpConnection>)>;

    /// Default maximum number of concurrent connections.
    static constexpr std::size_t kDefaultMaxConnections = 1000;

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct a listener bound to all interfaces on the given port.
    ///
    /// The underlying acceptor is opened, bound, and set to listen
    /// immediately.  The `SO_REUSEADDR` option is enabled.
    ///
    /// @param io   The io_context to use for async operations.
    /// @param port TCP port number to listen on.
    TcpListener(asio::io_context& io, std::uint16_t port);

    /// Construct a listener bound to a specific address and port.
    ///
    /// @param io       The io_context to use for async operations.
    /// @param address  IP address to bind to (e.g. "127.0.0.1", "0.0.0.0").
    /// @param port     TCP port number to listen on.
    TcpListener(asio::io_context& io, const std::string& address, std::uint16_t port);

    /// Non-copyable.
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    /// Non-movable (acceptor and internal state are tightly coupled).
    TcpListener(TcpListener&&) = delete;
    TcpListener& operator=(TcpListener&&) = delete;

    /// Destructor.  Stops accepting and closes the acceptor.
    ~TcpListener();

    // -----------------------------------------------------------------
    // Accept loop
    // -----------------------------------------------------------------

    /// Begin the asynchronous accept loop.
    ///
    /// Each successfully accepted connection is wrapped in a
    /// `TcpConnection` (in the Connected state) and passed to @p handler.
    /// The loop continues until `stop()` is called.
    ///
    /// If the current number of active connections has reached the
    /// maximum, the loop pauses automatically and resumes when
    /// `on_connection_closed()` is called.
    ///
    /// Calling start_accept() while already accepting is a no-op.
    ///
    /// @param handler  Callback to receive each new connection.
    void start_accept(AcceptHandler handler);

    /// Stop the accept loop and close the underlying acceptor.
    ///
    /// Outstanding async_accept operations are cancelled.  Already
    /// accepted connections are not affected.
    void stop();

    // -----------------------------------------------------------------
    // Connection tracking
    // -----------------------------------------------------------------

    /// Notify the listener that one previously accepted connection has
    /// been closed.  This decrements the active connection count and may
    /// resume the accept loop if it was paused due to the connection
    /// limit.
    void on_connection_closed();

    /// Set the maximum number of concurrent connections.
    ///
    /// If the new limit is lower than the current connection count the
    /// accept loop will pause until enough connections are closed.
    void set_max_connections(std::size_t max);

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the port the listener is bound to.
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

    /// Return the current number of active connections accepted by this
    /// listener (as tracked via `on_connection_closed()`).
    [[nodiscard]] std::size_t connection_count() const noexcept {
        return connection_count_.load(std::memory_order_relaxed);
    }

    /// Return the configured maximum number of connections.
    [[nodiscard]] std::size_t max_connections() const noexcept { return max_connections_; }

    /// Return true if the accept loop is currently active.
    [[nodiscard]] bool is_accepting() const noexcept { return accepting_; }

    /// Return the local endpoint the acceptor is bound to.
    [[nodiscard]] asio::ip::tcp::endpoint local_endpoint() const;

   private:
    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Set up the acceptor: open, set options, bind, and listen.
    void setup_acceptor(const asio::ip::tcp::endpoint& endpoint);

    /// Post the next async_accept if the accept loop is active and the
    /// connection limit has not been reached.
    void do_accept();

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    asio::ip::tcp::acceptor acceptor_;
    AcceptHandler accept_handler_;

    std::uint16_t port_;
    /// Incremented from the IO thread on accept completion and decremented
    /// from arbitrary threads via `on_connection_closed()`. Atomic ensures
    /// the increment/decrement and the `connection_count()` accessor are
    /// race-free.
    std::atomic<std::size_t> connection_count_{0};
    std::size_t max_connections_{kDefaultMaxConnections};
    bool accepting_{false};
};

}  // namespace toxtunnel::core
