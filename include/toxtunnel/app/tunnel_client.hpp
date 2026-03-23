#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "toxtunnel/app/stdio_pipe_bridge.hpp"
#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/config.hpp"

namespace toxtunnel::app {

/// Client-side application that listens on local TCP ports and forwards
/// traffic through Tox tunnels to the server.
///
/// TunnelClient orchestrates all components:
/// - A core::IoContext thread pool for async I/O
/// - A tox::ToxAdapter for Tox network communication
/// - A tunnel::TunnelManager for managing active tunnels
/// - One core::TcpListener per forwarding rule
///
/// Typical usage:
/// @code
///   auto config = Config::from_file("config.yaml").value();
///   TunnelClient client;
///   auto result = client.initialize(config);
///   if (!result) { /* handle error */ }
///   client.start();
///   // ... run until shutdown ...
///   client.stop();
/// @endcode
class TunnelClient {
   public:
    TunnelClient();
    ~TunnelClient();

    // Non-copyable, non-movable.
    TunnelClient(const TunnelClient&) = delete;
    TunnelClient& operator=(const TunnelClient&) = delete;
    TunnelClient(TunnelClient&&) = delete;
    TunnelClient& operator=(TunnelClient&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Initialize the client with the given configuration.
    ///
    /// Sets up the ToxAdapter, adds the server as a friend, and
    /// creates TcpListeners for each forwarding rule.
    ///
    /// @param config  The application configuration (must be in Client mode).
    /// @return An empty Expected on success, or an error description string.
    [[nodiscard]] util::Expected<void, std::string> initialize(const Config& config);

    /// Start all components: IoContext, ToxAdapter, bootstrap DHT,
    /// and begin accepting TCP connections on all listeners.
    void start();

    /// Stop all components gracefully.
    void stop();

    /// Return true if the client is currently running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Block until stop() has completed.
    void wait_until_stopped();

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return this node's Tox address as an uppercase hex string.
    [[nodiscard]] std::string get_tox_address() const;

   private:
    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Set up ToxAdapter callbacks (friend connection, lossless packet, etc.).
    void setup_tox_callbacks();

    /// Set up the TunnelManager send handler.
    void setup_tunnel_manager();

    /// Create TcpListeners for each forwarding rule.
    void create_listeners(const std::vector<ForwardRule>& forwards);

    /// Handle a new TCP connection accepted on a given local port.
    void on_tcp_connection_accepted(std::shared_ptr<core::TcpConnection> conn,
                                    const ForwardRule& rule);

    /// Return true if the client is configured for stdio pipe mode.
    [[nodiscard]] bool is_pipe_mode() const noexcept;

    /// Open the single stdio-backed tunnel used by pipe mode.
    void start_pipe_mode();

    /// Stop the client from a callback without blocking the current thread.
    void request_stop();

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// Thread pool for async I/O.
    std::unique_ptr<core::IoContext> io_ctx_;

    /// High-level Tox API.
    std::unique_ptr<tox::ToxAdapter> tox_adapter_;

    /// Manages active tunnels for the server friend.
    std::unique_ptr<tunnel::TunnelManager> tunnel_mgr_;

    /// One TCP listener per forwarding rule.
    std::vector<std::unique_ptr<core::TcpListener>> listeners_;

    /// Optional stdio bridge used in pipe mode.
    std::unique_ptr<StdioPipeBridge> pipe_bridge_;

    /// Forwarding rules from configuration (parallel with listeners_).
    std::vector<ForwardRule> forward_rules_;

    /// Friend number of the server peer (set after add_friend).
    uint32_t server_friend_number_{0};

    /// Whether the server friend is currently online.
    std::atomic<bool> server_online_{false};

    /// Whether the client is running.
    std::atomic<bool> running_{false};

    /// Whether the pipe-mode tunnel has already been started.
    std::atomic<bool> pipe_mode_started_{false};

    mutable std::mutex stop_mutex_;
    std::condition_variable stop_cv_;

    /// Stored configuration.
    Config config_;
};

}  // namespace toxtunnel::app
