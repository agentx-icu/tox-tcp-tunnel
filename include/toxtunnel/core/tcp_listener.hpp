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
/// **MUST be held via `std::shared_ptr`** — never stack-allocated,
/// never `std::unique_ptr`. The implementation relies on
/// `enable_shared_from_this` for two paths:
///   - `do_accept` keeps a shared_ptr alive across the in-flight
///     `async_accept` callback (S19, 2026-05-20 follow-up).
///   - `on_connection_closed` / `set_max_connections` post the
///     accept-resume onto the acceptor's executor (M-S-2).
/// All of these call `shared_from_this()`. A listener held by raw
/// storage (stack / `unique_ptr`) throws `std::bad_weak_ptr` the
/// moment any of those code paths runs — this is the "obvious"
/// example from older docs that user-reported Finding-2 (2026-05-21)
/// flagged.
///
/// Typical usage:
/// @code
///   asio::io_context io;
///   auto listener = std::make_shared<TcpListener>(io, 8080);
///   listener->set_max_connections(100);
///   listener->start_accept([](std::shared_ptr<TcpConnection> conn) {
///       // handle new connection ...
///   });
///   io.run();
/// @endcode
class TcpListener : public std::enable_shared_from_this<TcpListener> {
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

    /// Decrement the active connection count and, if the accept loop was
    /// paused at the limit, resume it.
    ///
    /// Wired automatically: `do_accept` installs this on each accepted
    /// connection's `TcpConnection::set_on_closed` hook, so it fires exactly
    /// once when that connection closes. Do NOT also call it externally — a
    /// second decrement per connection would under-count and over-admit.
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
    [[nodiscard]] std::size_t max_connections() const noexcept {
        return max_connections_.load(std::memory_order_relaxed);
    }

    /// Return true if the accept loop is currently active.
    [[nodiscard]] bool is_accepting() const noexcept {
        return accepting_.load(std::memory_order_relaxed);
    }

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
    /// Read from arbitrary threads via `max_connections()`, written from the
    /// io thread (`set_max_connections`) and read in `do_accept` /
    /// `on_connection_closed`. Atomic prevents data races.
    std::atomic<std::size_t> max_connections_{kDefaultMaxConnections};
    /// Same rationale as `max_connections_`: read from arbitrary threads via
    /// `is_accepting()` and toggled from io thread (`start`/`stop`).
    std::atomic<bool> accepting_{false};
    /// Guards against more than one outstanding `async_accept`. Both
    /// `on_connection_closed()` and `set_max_connections()` post `do_accept()`,
    /// and the accept handler re-arms — without this, concurrent/queued resumes
    /// could stack multiple in-flight accepts and over-admit past
    /// `max_connections_`. CAS-acquired in `do_accept`, released at the top of
    /// the accept handler.
    std::atomic<bool> accept_in_flight_{false};
};

}  // namespace toxtunnel::core
