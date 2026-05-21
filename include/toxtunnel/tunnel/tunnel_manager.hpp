#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "toxtunnel/tunnel/tunnel.hpp"

namespace toxtunnel::tunnel {

// Forward declarations
class ProtocolFrame;

/// Read-only snapshot of one Tunnel's state, safe to render off-thread.
/// Plain values only — no pointers into live Tunnel state.
struct TunnelSnapshot {
    uint16_t id{0};
    std::string target_host;
    uint16_t target_port{0};
    std::string state;  ///< Human-readable Tunnel::State.
    std::size_t bytes_in{0};
    std::size_t bytes_out{0};
    std::chrono::seconds idle_seconds{0};
};

/// Read-only snapshot of a TunnelManager, suitable for IPC inspection.
struct ManagerSnapshot {
    std::size_t bytes_in{0};
    std::size_t bytes_out{0};
    std::size_t frames_in{0};
    std::size_t frames_out{0};
    std::vector<TunnelSnapshot> tunnels;
};

/// Callback type for sending frames to the Tox peer.
using SendHandler = std::function<bool(const std::vector<uint8_t>&)>;

/// Callback type for tunnel creation notifications.
using TunnelCreatedCallback = std::function<void(uint16_t tunnel_id)>;

/// Callback type for tunnel closure notifications.
using TunnelClosedCallback = std::function<void(uint16_t tunnel_id)>;

/// Orchestrates multiple Tunnel instances for a single friend connection.
///
/// TunnelManager is responsible for:
/// - Creating and tracking Tunnel instances by tunnel_id
/// - Routing incoming ProtocolFrames to the correct Tunnel
/// - Managing tunnel lifecycle (creation, destruction)
/// - Allocating tunnel IDs (1-65535, 0 is reserved for control frames)
/// - Tracking per-tunnel buffer levels for backpressure
/// - Interfacing with ToxConnection for sending frames
///
/// Thread safety: All public methods are safe to call from any thread.
/// Internal state is protected by a shared_mutex (reader-writer lock).
///
/// Typical usage:
/// @code
///   TunnelManager manager(io_ctx);
///   manager.set_send_handler([&](const auto& data) {
///       return tox_connection.queue_data(data.data(), data.size());
///   });
///
///   // Create a tunnel on behalf of the remote peer
///   auto frame = ProtocolFrame::make_tunnel_open(100, "example.com", 443);
///   manager.handle_incoming_open(frame);
///
///   // Route incoming data
///   manager.route_frame(incoming_data_frame);
///
///   // Create a local-initiated tunnel
///   auto id = manager.create_tunnel("internal.local", 8080);
/// @endcode
class TunnelManager {
   public:
    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct a TunnelManager.
    ///
    /// @param io_ctx   The io_context for async operations.
    explicit TunnelManager(asio::io_context& io_ctx);

    /// Non-copyable, non-movable.
    TunnelManager(const TunnelManager&) = delete;
    TunnelManager& operator=(const TunnelManager&) = delete;
    TunnelManager(TunnelManager&&) = delete;
    TunnelManager& operator=(TunnelManager&&) = delete;

    ~TunnelManager();

    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    /// Set the handler for sending frames to the Tox peer.
    ///
    /// The handler should queue the data for sending and return true
    /// on success, false if the send buffer is full (backpressure).
    void set_send_handler(SendHandler handler);

    /// Set the callback invoked when a new tunnel is created.
    void set_on_tunnel_created(TunnelCreatedCallback cb);

    /// Set the callback invoked when a tunnel is closed.
    void set_on_tunnel_closed(TunnelClosedCallback cb);

    /// Set the maximum number of concurrent tunnels (default: 100).
    void set_max_tunnels(std::size_t max);

    /// Set the backpressure threshold in bytes (default: 64 KiB).
    void set_backpressure_threshold(std::size_t bytes);

    // -----------------------------------------------------------------
    // Idle-tunnel reaper
    // -----------------------------------------------------------------

    /// Enable the idle-tunnel reaper.
    ///
    /// Schedules a periodic scan over all tunnels that closes any whose
    /// last TUNNEL_DATA activity is older than `idle_timeout_seconds`.
    /// Tunnels still in the Connecting state are skipped so a slow
    /// open-handshake never gets reaped mid-flight. Calling this with
    /// `idle_timeout_seconds == 0` (or `tick_seconds == 0`) is a no-op
    /// and leaves any previously scheduled reaper running; use
    /// `disable_reaper()` to stop it.
    void enable_reaper(uint32_t idle_timeout_seconds, uint32_t tick_seconds);

    /// Cancel the reaper timer if one is scheduled.
    ///
    /// Idempotent and safe to call from the destructor.
    void disable_reaper();

    /// Run one reaper pass synchronously, regardless of timer state.
    ///
    /// Exposed for tests; in production the timer drives it.
    /// Returns the number of tunnels closed during this pass.
    std::size_t reap_idle_tunnels_once();

    // -----------------------------------------------------------------
    // Tunnel ID allocation
    // -----------------------------------------------------------------

    /// Allocate a new, unique tunnel ID.
    ///
    /// IDs are allocated sequentially starting from 1, wrapping around
    /// at 65535. IDs that are currently in use are skipped.
    ///
    /// @return A unique tunnel ID in the range [1, 65535].
    [[nodiscard]] uint16_t allocate_tunnel_id();

    /// Release a tunnel ID back to the pool.
    ///
    /// Called automatically when a tunnel is removed.
    void release_tunnel_id(uint16_t tunnel_id);

    /// Set the next tunnel ID to allocate (for testing).
    void set_next_tunnel_id(uint16_t next_id);

    // -----------------------------------------------------------------
    // Tunnel lifecycle
    // -----------------------------------------------------------------

    /// Add a tunnel to the manager.
    ///
    /// Takes shared ownership of the tunnel. If a tunnel with the same ID
    /// already exists, it is replaced. Callers may keep their own
    /// `shared_ptr<Tunnel>` after calling this — useful for capturing the
    /// tunnel into async callbacks where teardown ordering would otherwise
    /// leave a dangling pointer (TCP strand vs Tox strand).
    ///
    /// @param tunnel_id  The tunnel identifier.
    /// @param tunnel     The tunnel instance to add.
    void add_tunnel(uint16_t tunnel_id, std::shared_ptr<Tunnel> tunnel);

    /// Remove and destroy a tunnel.
    ///
    /// Calls close() on the tunnel before erasing the manager's shared_ptr
    /// reference. If any external callbacks still hold a shared_ptr to the
    /// tunnel (the recommended pattern for TCP-strand callbacks), the
    /// underlying Tunnel object survives until those callbacks release it.
    ///
    /// @param tunnel_id  The tunnel to remove.
    void remove_tunnel(uint16_t tunnel_id);

    /// Get a shared_ptr to a tunnel by ID.
    ///
    /// Returning a shared_ptr (rather than a raw pointer) lets the caller
    /// safely keep the tunnel alive across a strand boundary even if
    /// remove_tunnel() races with the caller's use of the returned handle.
    ///
    /// @return shared_ptr to the tunnel, or nullptr if not found.
    [[nodiscard]] std::shared_ptr<Tunnel> get_tunnel(uint16_t tunnel_id);

    /// Get a const shared_ptr to a tunnel by ID.
    ///
    /// @return shared_ptr to the tunnel, or nullptr if not found.
    [[nodiscard]] std::shared_ptr<const Tunnel> get_tunnel(uint16_t tunnel_id) const;

    /// Check if a tunnel with the given ID exists.
    [[nodiscard]] bool has_tunnel(uint16_t tunnel_id) const;

    /// Create a new tunnel connecting to the specified host:port.
    ///
    /// Allocates an ID, creates the tunnel, and adds it to the manager.
    ///
    /// @param host  Target hostname or IP address.
    /// @param port  Target TCP port.
    /// @return      The allocated tunnel ID, or 0 on failure.
    [[nodiscard]] uint16_t create_tunnel(const std::string& host, uint16_t port);

    /// Close all tunnels and clear the manager.
    void close_all();

    // -----------------------------------------------------------------
    // Frame routing
    // -----------------------------------------------------------------

    /// Route an incoming frame to the appropriate tunnel.
    ///
    /// For frames with tunnel_id == 0 (PING/PONG), the manager handles
    /// them directly. All other frames are routed to the corresponding
    /// tunnel if it exists.
    ///
    /// @param frame  The frame to route.
    void route_frame(const ProtocolFrame& frame);

    /// Handle an incoming TUNNEL_OPEN request.
    ///
    /// Creates a new tunnel if:
    /// - The tunnel ID is not already in use
    /// - We haven't exceeded max_tunnels
    ///
    /// @param frame  The TUNNEL_OPEN frame.
    /// @return       true if the tunnel was created, false otherwise.
    bool handle_incoming_open(const ProtocolFrame& frame);

    /// Send a frame to the Tox peer via the registered send handler.
    ///
    /// @param frame  The frame to send.
    /// @return       true if the frame was queued for sending.
    bool send_frame(const ProtocolFrame& frame);

    // -----------------------------------------------------------------
    // Backpressure tracking
    // -----------------------------------------------------------------

    /// Get the total buffer level across all tunnels.
    ///
    /// This is the sum of all tunnel buffer_level() values.
    [[nodiscard]] std::size_t total_buffer_level() const;

    /// Check if any tunnel is experiencing backpressure.
    ///
    /// Returns true if total_buffer_level() >= backpressure_threshold().
    [[nodiscard]] bool has_backpressure() const;

    /// Get the current backpressure threshold.
    [[nodiscard]] std::size_t backpressure_threshold() const noexcept;

    // -----------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------

    /// Record bytes sent (for statistics tracking).
    void record_bytes_sent(std::size_t bytes);

    /// Record bytes received (for statistics tracking).
    void record_bytes_received(std::size_t bytes);

    /// Record a frame being sent.
    void record_frame_sent();

    /// Record a frame being received.
    void record_frame_received();

    /// Get total bytes sent.
    [[nodiscard]] std::size_t total_bytes_sent() const noexcept;

    /// Get total bytes received.
    [[nodiscard]] std::size_t total_bytes_received() const noexcept;

    /// Get total frames sent.
    [[nodiscard]] std::size_t frames_sent() const noexcept;

    /// Get total frames received.
    [[nodiscard]] std::size_t frames_received() const noexcept;

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Get the number of active tunnels.
    [[nodiscard]] std::size_t tunnel_count() const;

    /// Check if the manager has no tunnels.
    [[nodiscard]] bool empty() const;

    /// Get a list of all tunnel IDs.
    [[nodiscard]] std::vector<uint16_t> get_tunnel_ids() const;

    /// Capture a point-in-time read-only snapshot of all tunnels.
    ///
    /// Holds the internal shared lock only while copying primitive fields
    /// out of each tunnel — the returned ManagerSnapshot contains no
    /// references to live state and is safe to serialize off-thread.
    [[nodiscard]] ManagerSnapshot snapshot() const;

    /// Iterate over all tunnels.
    ///
    /// @param fn  Function to call for each tunnel: fn(tunnel_id, tunnel_ptr)
    template <typename Fn>
    void for_each_tunnel(Fn&& fn) {
        std::shared_lock lock(mutex_);
        for (auto& [id, tunnel] : tunnels_) {
            fn(id, tunnel.get());
        }
    }

   private:
    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Handle a PING frame (tunnel_id == 0).
    void handle_ping_frame(const ProtocolFrame& frame);

    /// Handle a PONG frame (tunnel_id == 0).
    void handle_pong_frame(const ProtocolFrame& frame);

    /// Find the next available tunnel ID.
    [[nodiscard]] uint16_t find_available_id();

    /// Arm `reaper_timer_` to fire `reaper_tick_` from now.
    void schedule_reaper_tick();

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// Reference to the io_context for async operations.
    asio::io_context& io_ctx_;

    /// Map of tunnel_id -> Tunnel.
    /// Stored as shared_ptr so that external callbacks (TCP strand etc.)
    /// can keep the tunnel alive past `remove_tunnel`. See add_tunnel().
    std::map<uint16_t, std::shared_ptr<Tunnel>> tunnels_;

    /// Set of IDs currently in use (for fast lookup during allocation).
    std::vector<bool> used_ids_;

    /// Next tunnel ID to allocate.
    uint16_t next_tunnel_id_{1};

    /// Maximum number of tunnels.
    std::size_t max_tunnels_{100};

    /// Backpressure threshold in bytes. Read via `backpressure_threshold()`
    /// without taking `mutex_` (hot path), set via `set_backpressure_threshold()`
    /// from arbitrary threads. Atomic prevents data races.
    std::atomic<std::size_t> backpressure_threshold_{64 * 1024};

    /// Handler for sending frames. Guarded by handler_mutex_ rather than the
    /// general mutex_ so the (low-frequency) control-frame send path doesn't
    /// contend with the (high-frequency) tunnels_ lookups in route_frame.
    /// The hot TUNNEL_DATA outbound path doesn't pass through this handler at
    /// all — it goes via Tunnel::on_send_to_tox directly into ToxAdapter.
    SendHandler send_handler_;
    mutable std::mutex handler_mutex_;

    /// Callback when a tunnel is created.
    TunnelCreatedCallback on_tunnel_created_;

    /// Callback when a tunnel is closed.
    TunnelClosedCallback on_tunnel_closed_;

    /// Statistics: total bytes sent.
    std::atomic<std::size_t> total_bytes_sent_{0};

    /// Statistics: total bytes received.
    std::atomic<std::size_t> total_bytes_received_{0};

    /// Statistics: frames sent.
    std::atomic<std::size_t> frames_sent_{0};

    /// Statistics: frames received.
    std::atomic<std::size_t> frames_received_{0};

    /// Protects tunnels_, used_ids_, next_tunnel_id_.
    mutable std::shared_mutex mutex_;

    /// Reaper timer; default-constructed but only armed when the reaper
    /// is enabled. Cancelled in disable_reaper() and the destructor.
    asio::steady_timer reaper_timer_;

    /// Idle threshold in nanoseconds. 0 means the reaper is disabled.
    std::atomic<int64_t> reaper_idle_timeout_ns_{0};

    /// Configured tick interval (seconds). Read on the io_ctx thread.
    std::chrono::seconds reaper_tick_{0};

    /// Set to true while a reaper tick is scheduled; flipped back to
    /// false from the timer's completion handler. Lets disable_reaper()
    /// distinguish "armed" from "idle" without racing the io_ctx thread.
    std::atomic<bool> reaper_active_{false};
};

}  // namespace toxtunnel::tunnel
