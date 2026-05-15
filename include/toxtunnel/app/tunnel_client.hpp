#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/app/known_servers.hpp"
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

    /// Hot-reload the reloadable subset of the configuration. Currently:
    ///   - `client.forwards` — diff against active listeners, stop removed,
    ///     start added, leave unchanged ones alone. Existing tunnels through
    ///     a removed listener drain naturally (the listener stops accepting,
    ///     but already-accepted connections finish on their own).
    ///   - `logging.level` (forwarded to `spdlog::set_level`)
    ///
    /// Non-reloadable fields are rejected via `util::check_reloadable`. On
    /// any error the running client keeps its previous state.
    [[nodiscard]] util::Expected<void, std::string> reload(const Config& new_config);

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

    /// Serializes inbound lossless-packet dispatch on top of io_ctx_'s pool.
    /// Without this, ACK and DATA frames that arrive back-to-back from Tox
    /// can be picked up by different worker threads and processed out of
    /// order — a DATA frame can land while the tunnel is still in Connecting
    /// state and get silently dropped. The strand preserves arrival order
    /// while still letting the pool parallelise other work.
    std::optional<asio::strand<asio::any_io_executor>> inbound_strand_;

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

    /// Server's full Tox ID (uppercase 76-hex). Used as the persistent
    /// identity in `known_servers_`. Captured during initialize().
    std::string server_tox_id_hex_;

    /// Persistent registry of servers this client has connected to. Backed by
    /// `<config.data_dir>/known_servers.yaml`. Lazily initialised once we
    /// know data_dir.
    std::unique_ptr<KnownServersStore> known_servers_;

    /// Whether we have already sent an INFO_REQUEST in the current online
    /// session. Reset when the friend goes offline. Prevents repeat probes
    /// inside one connection.
    std::atomic<bool> info_request_sent_{false};

    /// Send an INFO_REQUEST control frame to the server. Safe to call
    /// multiple times; the `info_request_sent_` guard avoids spam.
    void send_info_request();

    /// Re-arm the periodic INFO_REQUEST refresh timer so the registry's
    /// `info` block stays fresh when the server's `disclose.*` policy
    /// changes during a long online session. Default cadence: 1 hour.
    /// No-op if the io_context is gone or the client is shutting down.
    void schedule_info_refresh();

    /// Background timer that re-issues INFO_REQUEST every kInfoRefreshInterval.
    /// Owned by io_ctx_; cancelled on stop().
    std::unique_ptr<asio::steady_timer> info_refresh_timer_;

    /// How often to re-poll the server for system info while online.
    static constexpr std::chrono::hours kInfoRefreshInterval{1};

    /// Persist the latest connection metadata (last_connected_at, transport)
    /// for this server into the known_servers registry. Called when the
    /// friend transitions to online.
    void record_server_connection();

    /// Update the server's disclosed system info from an INFO_REPLY payload
    /// (UTF-8 YAML bytes) and persist.
    void record_server_info(std::string_view yaml_payload);

    /// Local IPC server backing `toxtunnel inspect`. Owned here so its
    /// lifetime is tied to the io_context — the inspect server posts onto
    /// the IO pool, so it must shut down before io_ctx_ does.
    std::unique_ptr<InspectServer> inspect_server_;
};

}  // namespace toxtunnel::app
