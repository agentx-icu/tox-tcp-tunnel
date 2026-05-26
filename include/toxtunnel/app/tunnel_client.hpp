#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/app/known_servers.hpp"
#include "toxtunnel/app/socks5_listener.hpp"
#include "toxtunnel/app/stdio_pipe_bridge.hpp"
#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::app {

/// One configured server endpoint. The client adds every endpoint as a Tox
/// friend at startup; the failover state machine tracks which one is currently
/// the "active" tunnel route.
struct ClientServerEndpoint {
    /// 76-char uppercase hex Tox ID (post alias-resolution).
    std::string tox_id_hex;
    /// Friend number returned by ToxAdapter::add_friend / add_friend_norequest.
    uint32_t friend_number = 0;
    /// Most recently reported online/offline state from toxcore.
    bool online = false;
    /// Timestamp (steady_clock) of the most recent online->offline transition
    /// (or the initial seed at construction). Zero for never observed.
    std::chrono::steady_clock::time_point offline_since{};
    /// Timestamp (steady_clock) of the most recent offline->online transition.
    /// Used by the primary-prefer switchback grace window.
    std::chrono::steady_clock::time_point online_since{};
};

/// Pure decision function for the failover state machine. Returns the index
/// of the endpoint that should become active, or std::nullopt if the current
/// active endpoint should remain active.
///
/// Decision logic, in order:
///   1. If `endpoints[active_index]` has been offline for at least
///      `failover.timeout_seconds`, and a non-active endpoint is online,
///      promote the lowest-index online candidate.
///   2. Otherwise, if `active_index != 0` and the primary (index 0) has been
///      continuously online for at least `failover.prefer_primary_grace_seconds`,
///      switch back to the primary.
///   3. Otherwise, return std::nullopt.
///
/// Pure — no I/O, no logging, no toxcore. Extracted from TunnelClient so the
/// state machine is unit-testable in isolation.
[[nodiscard]] std::optional<std::size_t> decide_failover_switch(
    const std::vector<ClientServerEndpoint>& endpoints, std::size_t active_index,
    const FailoverConfig& failover, std::chrono::steady_clock::time_point now);

namespace detail {

using LosslessPacketSendFn = std::function<bool(uint32_t, const uint8_t*, std::size_t)>;

/// Build a tunnel send callback pinned to one friend_number for the tunnel's
/// full lifetime. This prevents failover from rerouting an already-open tunnel's
/// late TUNNEL_DATA / TUNNEL_CLOSE frames onto the newly-active server.
[[nodiscard]] tunnel::TunnelImpl::SendToToxCallback make_fixed_friend_lossless_sender(
    LosslessPacketSendFn send_lossless, uint32_t friend_number);

/// Zero-copy variant of make_fixed_friend_lossless_sender().
[[nodiscard]] tunnel::TunnelImpl::SendOwnedToToxCallback make_fixed_friend_lossless_owned_sender(
    LosslessPacketSendFn send_lossless, uint32_t friend_number);

}  // namespace detail

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

    /// Apply the v0.4 adaptive coalescer mode + BDP flow control config to a
    /// freshly-built tunnel. Centralised so all three tunnel-open paths
    /// (forward rule, pipe mode, SOCKS5) stay in sync.
    void apply_coalesce_and_flow_control(tunnel::TunnelImpl& tunnel);

    /// Open the single stdio-backed tunnel used by pipe mode.
    void start_pipe_mode();

    /// Stop the client from a callback without blocking the current thread.
    void request_stop();

    /// H-07 resume: after the active server reconnects, send a
    /// TUNNEL_RESUME_REQUEST for every still-Connected tunnel so the server can
    /// reattach the held tunnel and reconcile byte offsets. A no-op on the
    /// first connect (no tunnels exist yet) and when resume is disabled.
    void send_resume_requests();

    /// Handle an inbound TUNNEL_RESUME_ACK: on Ok the tunnel continues; on any
    /// decline status the local tunnel is closed so its TCP peer is reset.
    void handle_resume_ack(const tunnel::TunnelResumeAckPayload& ack);

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
    // shared_ptr (not unique_ptr): on_close lambdas registered by pipe-
    // mode and SOCKS5 tunnels need to call tunnel_mgr_->remove_tunnel
    // *after* the tunnel's lifetime crossed an async boundary. The
    // previous bare `tunnel_mgr_.get()` capture (H-S-2/H-S-4 in the
    // fix-storm review) would UAF if request_stop() destroyed the
    // owning TunnelClient before the lambda fired. shared_ptr capture
    // in the lambda keeps the manager alive for as long as the lambda
    // needs it.
    std::shared_ptr<tunnel::TunnelManager> tunnel_mgr_;

    /// One TCP listener per forwarding rule.
    // shared_ptr (not unique_ptr): TcpListener now inherits
    // enable_shared_from_this so its async_accept callback can keep
    // itself alive across the in-flight read even if reload() removes
    // the listener from this vector. The vector + reload mutations
    // themselves are serialised onto io_ctx_ (see TunnelClient::reload).
    std::vector<std::shared_ptr<core::TcpListener>> listeners_;

    /// Optional stdio bridge used in pipe mode.
    // shared_ptr + pipe_mutex_ (H-04): the bridge is touched from several
    // tunnel callbacks (data/state/close, which run on io-worker / inbound-
    // strand threads) AND from stop() (a non-worker thread). The previous
    // unsynchronized unique_ptr could be reset under one thread while another
    // dereferenced it. Callers snapshot a local shared_ptr under pipe_mutex_
    // and operate on the copy, so a concurrent reset can't pull the object out
    // from under an in-flight use.
    std::shared_ptr<StdioPipeBridge> pipe_bridge_;
    mutable std::mutex pipe_mutex_;

    /// Forwarding rules from configuration (parallel with listeners_).
    std::vector<ForwardRule> forward_rules_;

    /// Friend number of the currently-active server peer (updated on failover).
    /// Kept as an atomic so callbacks racing with a switchover read a coherent
    /// value; the integer itself never spans a word.
    std::atomic<uint32_t> server_friend_number_{0};

    /// Whether the currently-active server friend is online. Mirrors the
    /// `online` flag of `endpoints_[active_index_]` and is updated under
    /// `endpoints_mutex_`.
    std::atomic<bool> server_online_{false};

    /// All configured server endpoints (primary at index 0, then fallbacks in
    /// the order given). Mutated only under `endpoints_mutex_`.
    std::vector<ClientServerEndpoint> endpoints_;

    /// Index into `endpoints_` of the currently-active server. Always
    /// 0 <= active_index_ < endpoints_.size() after initialize() succeeds.
    std::size_t active_index_{0};

    /// Guards `endpoints_`, `active_index_` and the failover bookkeeping.
    mutable std::mutex endpoints_mutex_;

    /// Background timer driving the failover state machine.
    std::unique_ptr<asio::steady_timer> failover_timer_;

    /// Tick interval for the failover state machine. Coarse enough that we
    /// don't burn CPU but fine enough that the configured timeouts are
    /// honoured within a couple of seconds.
    static constexpr std::chrono::seconds kFailoverTickInterval{1};

    /// Re-arm the periodic failover state machine tick. No-op if the
    /// io_context is gone or the client is shutting down.
    void schedule_failover_tick();

    /// Run one pass of the failover state machine. Inspects per-endpoint
    /// online/offline timestamps against `client.failover.*` thresholds and
    /// promotes a new active endpoint when warranted.
    void run_failover_tick();

    /// Switch the active endpoint to `new_index`. Logs the transition, tears
    /// down existing tunnels (TUNNEL_CLOSE), and updates server_friend_number_
    /// + the known-servers registry.
    /// MUST be called from within the io_ctx_ executor; takes endpoints_mutex_
    /// internally for short critical sections.
    void switch_active_endpoint(std::size_t new_index);

    /// Return the index of an online endpoint (excluding the current active),
    /// or std::nullopt. Prefers lower indices (i.e. closer to primary).
    [[nodiscard]] std::optional<std::size_t> pick_next_online_locked() const;

    /// Whether the client is running.
    std::atomic<bool> running_{false};

    /// Whether the pipe-mode tunnel has already been started.
    std::atomic<bool> pipe_mode_started_{false};

    mutable std::mutex stop_mutex_;
    std::condition_variable stop_cv_;

    /// Set by request_stop() (called from Tox-iterate / io-worker callbacks)
    /// to ask the thread blocked in wait_until_stopped() to perform the actual
    /// teardown. Driving stop() — which joins the io_context worker pool — from
    /// a worker thread would self-join and deadlock (C-01). Guarded by
    /// stop_mutex_ for the cv wait.
    bool stop_requested_{false};

    /// Single-entry guard so stop() runs its teardown exactly once even when
    /// the signal thread (SIGINT/SIGTERM) and the wait_until_stopped() thread
    /// race to call it.
    std::atomic<bool> stop_started_{false};

    /// Stored configuration.
    Config config_;

    /// Server's full Tox ID (uppercase 76-hex). Used as the persistent
    /// identity in `known_servers_`. Written from `initialize()` and
    /// `switch_active_endpoint()` under `endpoints_mutex_`; all reads
    /// from non-init paths must also take `endpoints_mutex_` to avoid
    /// data races (inspect-provider lambda, INFO callbacks). Helper
    /// `server_tox_id_snapshot()` does the lock+copy.
    std::string server_tox_id_hex_;

    /// Thread-safe snapshot of `server_tox_id_hex_` for any-thread reads.
    [[nodiscard]] std::string server_tox_id_snapshot() const;

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

    /// Optional Prometheus /metrics HTTP server (only started when
    /// config.metrics.enabled is true).
    std::unique_ptr<util::MetricsServer> metrics_server_;

    /// How often to re-poll the server for system info while online.
    static constexpr std::chrono::hours kInfoRefreshInterval{1};

    /// Persist the latest connection metadata (last_connected_at, transport)
    /// for the given `tox_id` (uppercase 76-hex) into the known_servers
    /// registry. `friend_number` identifies which peer's transport state
    /// to record. Callers MUST pass the tox_id captured atomically with
    /// the friend_number at the moment the event was observed, so a
    /// concurrent failover cannot misattribute the record to the new
    /// active server (S15 in the 2026-05-20 review).
    void record_server_connection(std::string_view tox_id, std::uint32_t friend_number);

    /// Update `tox_id`'s disclosed system info from an INFO_REPLY payload
    /// (UTF-8 YAML bytes) and persist. Same atomicity requirement as
    /// `record_server_connection`.
    void record_server_info(std::string_view tox_id, std::string_view yaml_payload);

    /// Local IPC server backing `toxtunnel inspect`. Owned here so its
    /// lifetime is tied to the io_context — the inspect server posts onto
    /// the IO pool, so it must shut down before io_ctx_ does.
    std::unique_ptr<InspectServer> inspect_server_;

    /// Optional SOCKS5 / HTTP CONNECT listener for dynamic destinations.
    // shared_ptr (M-09): Socks5Listener uses enable_shared_from_this so its
    // accept loop can capture a weak_ptr to itself.
    std::shared_ptr<Socks5Listener> socks5_listener_;

    /// Open a brand-new tunnel for a SOCKS5-supplied destination. Wires up
    /// the same TCP-to-tunnel plumbing as `on_tcp_connection_accepted`, but
    /// defers the success reply to the listener via `on_tunnel_state`.
    /// `initial_payload` carries bytes the listener buffered past the
    /// SOCKS/CONNECT handshake (e.g. a pipelined TLS ClientHello). They are
    /// pushed upstream as the first tunnel write once Connected.
    void open_socks5_tunnel(std::shared_ptr<core::TcpConnection> conn, std::string host,
                            uint16_t port, std::vector<uint8_t> initial_payload,
                            std::function<void(bool)> on_tunnel_state);
};

}  // namespace toxtunnel::app
