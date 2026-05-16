#pragma once

#include <asio.hpp>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/app/rules_engine.hpp"
#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::app {

/// Server application that accepts Tox friend connections and tunnels
/// their traffic to local TCP targets based on access control rules.
///
/// TunnelServer orchestrates all components: IoContext for async I/O,
/// ToxAdapter for Tox network communication, RulesEngine for access
/// control, and per-friend TunnelManagers for tunnel lifecycle.
///
/// Typical usage:
/// @code
///   Config config = Config::default_server();
///   TunnelServer server;
///   auto result = server.initialize(config);
///   if (!result) { /* handle error */ }
///   server.start();
///   // ... server runs until stop() is called ...
///   server.stop();
/// @endcode
class TunnelServer {
   public:
    TunnelServer();
    ~TunnelServer();

    // Non-copyable, non-movable.
    TunnelServer(const TunnelServer&) = delete;
    TunnelServer& operator=(const TunnelServer&) = delete;
    TunnelServer(TunnelServer&&) = delete;
    TunnelServer& operator=(TunnelServer&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Initialize the server with the given configuration.
    ///
    /// Loads access rules, configures and initializes the ToxAdapter.
    ///
    /// @param config  Server configuration.
    /// @return An empty Expected on success, or an error description.
    [[nodiscard]] util::Expected<void, std::string> initialize(const Config& config);

    /// Start the server: run the IoContext, start the ToxAdapter,
    /// bootstrap DHT, and log the Tox ID.
    void start();

    /// Stop the server: close all tunnel managers, stop the ToxAdapter,
    /// and stop the IoContext.
    void stop();

    /// Return true if the server is currently running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Hot-reload the reloadable subset of the configuration. Currently:
    ///   - `server.rules_file` contents (re-read + atomic RulesEngine swap)
    ///   - `logging.level` (forwarded to `spdlog::set_level`)
    ///
    /// Non-reloadable fields are rejected via `util::check_reloadable`. The
    /// caller is expected to have already re-read and validated the new
    /// `Config` from disk. On any error the running server keeps its previous
    /// state — this is a strict no-op-on-failure contract so SIGHUP cannot
    /// brick the daemon.
    ///
    /// Thread-safe: safe to call from a signal handler thread; rules are
    /// swapped under a writer lock that briefly blocks concurrent
    /// `RulesEngine::evaluate()` callers on the IO pool.
    [[nodiscard]] util::Expected<void, std::string> reload(const Config& new_config);

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the Tox ID as a hex string.
    ///
    /// @pre initialize() has been called successfully.
    [[nodiscard]] std::string get_tox_address() const;

   private:
    // -----------------------------------------------------------------
    // Callback handlers
    // -----------------------------------------------------------------

    /// Handle incoming friend requests by auto-accepting them.
    void on_friend_request(const tox::PublicKeyArray& public_key, std::string_view message);

    /// Handle friend connection status changes.
    /// Creates a TunnelManager when a friend comes online,
    /// destroys it when the friend goes offline.
    void on_friend_connection(uint32_t friend_number, bool connected);

    /// Handle incoming lossless packets.
    /// Deserializes the ProtocolFrame and routes it to the
    /// friend's TunnelManager.
    void on_lossless_packet(uint32_t friend_number, const uint8_t* data, std::size_t length);

    /// Handle self connection status changes (DHT connectivity).
    void on_self_connection(bool connected);

    /// Apply the v0.4 adaptive coalescer mode + BDP flow control config to a
    /// freshly-built server-side tunnel.
    void apply_coalesce_and_flow_control(tunnel::TunnelImpl& tunnel);

    /// Push the rules engine's rate-limit configuration (defaults + per-
    /// friend specs) into the process-wide RateLimiter. Idempotent; called
    /// after every rules load / reload.
    void sync_rate_limiter();

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Set up a TunnelManager for a newly connected friend.
    void setup_tunnel_manager(uint32_t friend_number);

    /// Tear down the TunnelManager for a disconnected friend.
    void teardown_tunnel_manager(uint32_t friend_number);

    /// Handle a TUNNEL_OPEN request: check access rules,
    /// create TcpConnection, and wire data flow.
    void handle_tunnel_open(uint32_t friend_number, const tunnel::ProtocolFrame& frame);

    /// Wire a TCP connection to a tunnel for bidirectional data flow.
    void wire_tcp_to_tunnel(uint32_t friend_number, uint16_t tunnel_id,
                            std::shared_ptr<core::TcpConnection> tcp_conn);

    /// Get the hex public key string for a friend number.
    [[nodiscard]] std::string get_friend_pk_hex(uint32_t friend_number) const;

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// Configuration snapshot.
    Config config_;

    /// Async I/O thread pool.
    std::unique_ptr<core::IoContext> io_context_;

    /// Serializes inbound lossless-packet dispatch on top of io_context_'s
    /// pool. Without this, frames a friend sends back-to-back (e.g. ACK
    /// then DATA, or several DATA chunks) can be picked up by different
    /// worker threads and processed out of order — DATA arriving before
    /// the receiver has transitioned the tunnel into Connected is silently
    /// dropped. The strand preserves arrival order while keeping the rest
    /// of the IO pool parallel.
    std::optional<asio::strand<asio::any_io_executor>> inbound_strand_;

    /// Tox network adapter.
    std::unique_ptr<tox::ToxAdapter> tox_adapter_;

    /// Access control engine. Reads (`evaluate()`) take a shared lock,
    /// SIGHUP reload (`reload()`) takes a unique lock to swap the engine in
    /// place. Without the shared_mutex, a concurrent IO-thread read during
    /// reload would race with the move-assignment.
    RulesEngine rules_engine_;
    mutable std::shared_mutex rules_mutex_;

    /// Map of friend_number -> TunnelManager.
    std::unordered_map<uint32_t, std::unique_ptr<tunnel::TunnelManager>> managers_;

    /// Protects managers_ map. Recursive to avoid self-deadlock when
    /// callbacks (e.g., on_disconnect) re-enter while the lock is held.
    mutable std::recursive_mutex managers_mutex_;

    /// Whether the server is running.
    std::atomic<bool> running_{false};

    /// Local IPC server backing `toxtunnel inspect`.
    std::unique_ptr<InspectServer> inspect_server_;

    /// Optional Prometheus /metrics HTTP server (only when config.metrics.enabled).
    std::unique_ptr<util::MetricsServer> metrics_server_;
};

}  // namespace toxtunnel::app
