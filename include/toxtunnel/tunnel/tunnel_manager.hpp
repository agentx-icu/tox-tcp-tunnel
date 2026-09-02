#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

#include "toxtunnel/tunnel/tunnel.hpp"

namespace toxtunnel::tunnel {

// `SendOutcome` — the transport verdict every send path here reports — lives in
// tunnel.hpp (included above) because the per-tunnel send callbacks need it
// too. It mirrors `tox::ToxAdapter::LosslessSendOutcome` so this public header
// need not pull in the toxcore C header; the values stay in sync by
// construction in the per-tunnel callbacks (`tunnel_client.cpp` /
// `tunnel_server.cpp`).

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
/// Callback that hands an *unprefixed* protocol frame to the transport.
/// Returns `Sent` on success, `SendqFull` on transient backpressure (the
/// manager will park the frame and retry on its drain timer), and
/// `PermanentFail` on any other error (the manager drops the frame and
/// surfaces the failure to the original caller — for `TUNNEL_OPEN` that
/// means `TunnelImpl::open()` rolls back to `None`). The handler itself
/// prepends the 0xA0 lossless prefix before calling toxcore.
using SendHandler = std::function<SendOutcome(const std::vector<uint8_t>&)>;

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
/// Owned via shared_ptr (TunnelServer.managers_ stores
/// shared_ptr<TunnelManager>). `enable_shared_from_this` lets the
/// reaper timer's async_wait handler capture a weak_ptr instead of
/// `this`, so a teardown that races a not-yet-dispatched timer firing
/// doesn't UAF the manager (S17 in the 2026-05-20 follow-up).
class TunnelManager : public std::enable_shared_from_this<TunnelManager> {
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

    /// Enable the half-close linger cap.
    ///
    /// Shares the same maintenance scan/timer as the idle reaper, but is a
    /// distinct, on-by-default policy: it force-closes any tunnel stuck in the
    /// Disconnecting state (local half-close sent, peer's reciprocal
    /// TUNNEL_CLOSE never received) once it has seen no TUNNEL_DATA in either
    /// direction for `half_close_timeout_seconds`. This bounds the half-open
    /// TCP fd a wedged peer would otherwise pin forever. Enabling this does
    /// NOT enable the general idle reaper (that stays gated on
    /// `enable_reaper`). Calling with `half_close_timeout_seconds == 0` (or
    /// `tick_seconds == 0`) is a no-op.
    void enable_half_close_reaper(uint32_t half_close_timeout_seconds, uint32_t tick_seconds);

    /// Cancel the maintenance timer (idle reaper + half-close cap) if scheduled.
    ///
    /// Idempotent and safe to call from the destructor.
    void disable_reaper();

    /// Run one reaper pass synchronously, regardless of timer state.
    ///
    /// Exposed for tests; in production the timer drives it.
    /// Returns the number of tunnels closed during this pass.
    /// @param epoch the reaper generation this pass belongs to. Re-checked
    ///        before every individual close: the generation gate at the top of
    ///        the tick is unlocked, so a retired handler can pass it, be
    ///        preempted across a disable+enable (the resume pause/resurrect
    ///        sequence), and resume with a live-looking timeout. Checking per
    ///        close bounds that to at most one tunnel instead of a whole pass.
    /// Defaults to `kAnyReaperEpoch`, which disables the per-close generation
    /// check — for tests and any caller driving a single pass synchronously,
    /// where there is no timer generation to be retired.
    std::size_t reap_idle_tunnels_once(std::uint64_t epoch = kAnyReaperEpoch);

    /// Perform the maintenance tick's post-work re-arm on behalf of generation
    /// @p epoch: re-check the generation and arm the next tick, atomically.
    ///
    /// This IS the timer handler's last step — not a test-only shim. It is
    /// public because the interleaving it guards against (a stale handler
    /// resuming after `disable_reaper()` + `enable_reaper()` have already
    /// installed a new chain) cannot be produced from the outside any other
    /// way: the preemption point is inside an asio completion handler.
    void rearm_reaper_after_tick(std::uint64_t epoch);

    /// Current maintenance-timer generation. Pair with
    /// `rearm_reaper_after_tick()` to drive the transition directly.
    [[nodiscard]] std::uint64_t reaper_epoch() const noexcept;

    // -----------------------------------------------------------------
    // Application-level keepalive (PING/PONG liveness) — M-02
    // -----------------------------------------------------------------

    /// Enable periodic PING keepalive. Every `interval_seconds` a PING control
    /// frame is sent to the peer; if no PONG arrives for `timeout_seconds`, the
    /// peer is declared dead and the `on_peer_dead` callback (if set) fires
    /// once. `interval_seconds == 0` is a no-op. Re-enabling resets the
    /// liveness baseline (use this on every reconnect).
    void enable_keepalive(uint32_t interval_seconds, uint32_t timeout_seconds);

    /// Cancel the keepalive timer. Idempotent; safe from the destructor.
    void disable_keepalive();

    /// Set the callback fired once when the peer is declared dead by the
    /// keepalive check. Invoked on an io_context thread.
    void set_on_peer_dead(std::function<void()> cb);

    /// Record a PONG (or any liveness signal) — refreshes the keepalive
    /// deadline. Exposed for tests; production calls it from handle_pong_frame.
    void note_pong();

    /// Keepalive counterpart of `rearm_reaper_after_tick()`.
    void rearm_keepalive_after_tick(std::uint64_t epoch);

    /// Current keepalive generation.
    [[nodiscard]] std::uint64_t keepalive_epoch() const noexcept;

    // -----------------------------------------------------------------
    // Tunnel ID allocation
    // -----------------------------------------------------------------

    /// Allocate a new, unique tunnel ID.
    ///
    /// IDs are allocated sequentially starting from 1, wrapping around
    /// at 65535. IDs that are currently in use are skipped. ID 0 is reserved
    /// for control frames (PING/PONG) and is never allocated.
    ///
    /// @return A unique tunnel ID in [1, 65535], or std::nullopt if every ID
    ///         is currently in use. Callers MUST handle exhaustion — returning
    ///         0 as a sentinel (the old behaviour) collided with the
    ///         control-plane tunnel id and produced undefined routing (C-07).
    [[nodiscard]] std::optional<uint16_t> allocate_tunnel_id();

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
    /// @return true if the tunnel was added; false if the manager is at its
    ///         max-tunnel limit (or @p tunnel is null). Callers must handle
    ///         false by tearing down the half-built tunnel and releasing its
    ///         id, rather than assuming the manager registered it (H-05).
    bool add_tunnel(uint16_t tunnel_id, std::shared_ptr<Tunnel> tunnel);

    /// Remove and destroy a tunnel.
    ///
    /// Calls close() on the tunnel before erasing the manager's shared_ptr
    /// reference. If any external callbacks still hold a shared_ptr to the
    /// tunnel (the recommended pattern for TCP-strand callbacks), the
    /// underlying Tunnel object survives until those callbacks release it.
    ///
    /// @param tunnel_id  The tunnel to remove.
    void remove_tunnel(uint16_t tunnel_id);

    /// Remove @p tunnel_id, but only while it is still @p expected.
    ///
    /// Tunnel ids are recycled per friend, so a deferred cleanup that names only
    /// an id can tear down whichever tunnel inherited it. Every teardown posted
    /// from a tunnel's own callbacks must therefore say *which* tunnel it means.
    ///
    /// `expected == nullptr` removes NOTHING — the same contract as
    /// `close_tunnel_if()`. A caller reaches that case when its `weak_ptr` has
    /// lapsed, and a destroyed tunnel cannot still be registered, so whatever
    /// holds the id belongs to someone else. `remove_tunnel()` is the way to say
    /// "whatever is registered".
    ///
    /// ID-RELEASE RULE. The teardown a removal triggers runs unlocked (close
    /// paths re-enter application callbacks) and can emit the tunnel's
    /// TUNNEL_CLOSE. The id is therefore NOT returned to the allocator when the
    /// map entry is erased — it stays reserved until that teardown resolves, so
    /// no replacement can take the id while the previous owner is still
    /// speaking for it. Both id sources honour the reservation:
    /// `allocate_tunnel_id()` scans it, and `handle_incoming_open()` rejects a
    /// peer-chosen id that is still reserved.
    ///
    /// RESIDUAL: `add_tunnel()` with an id that went through neither of those
    /// gates bypasses the rule. No production caller does that — the server
    /// reserves via `handle_incoming_open()` and the client via
    /// `allocate_tunnel_id()` — but a test (or a future caller) that invents an
    /// id can still collide with a teardown in flight.
    ///
    /// @return true if this call removed @p expected.
    bool remove_tunnel_if(uint16_t tunnel_id, const Tunnel* expected);

    /// Gracefully close @p tunnel_id, but only while it is still @p expected.
    ///
    /// The `get_tunnel(id)` + unlocked `close()` pattern this replaces let a
    /// replacement land in between, so the old object emitted a TUNNEL_CLOSE
    /// carrying the new tunnel's id. The lookup and the identity check happen
    /// under one lock here; the close itself still runs unlocked (it invokes
    /// send and close callbacks, which must never hold a manager lock — H-01).
    /// The remaining window is bounded by the id-release rule documented on
    /// `remove_tunnel_if()`: an id is not returned to the allocator until the
    /// previous owner's teardown — including its TUNNEL_CLOSE — has completed,
    /// so `allocate_tunnel_id()` cannot hand it out underneath this close. See
    /// that comment for the one case that is NOT covered.
    ///
    /// Passing nullptr closes nothing.
    /// @return true if @p expected was found and closed.
    bool close_tunnel_if(uint16_t tunnel_id, const Tunnel* expected);

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

    /// Allocate a tunnel id and announce it to the peer with a TUNNEL_OPEN.
    ///
    /// Succeeds only when toxcore actually accepted the frame. This entry point
    /// registers no `Tunnel` object, so there is no driver to retain and retry a
    /// backpressured OPEN the way `TunnelImpl::open()` does; a `SendqFull` here
    /// therefore releases the id and reports failure rather than handing back an
    /// id the peer has never heard of. `SendqFull` is transient, so the caller
    /// may simply try again.
    ///
    /// @param host  Target hostname or IP address.
    /// @param port  Target TCP port.
    /// @return      The allocated tunnel ID, or 0 if nothing was sent.
    [[nodiscard]] uint16_t create_tunnel(const std::string& host, uint16_t port);

    /// Close all tunnels and clear the manager.
    void close_all();

    /// Abandon this manager's session locally: stop authorising sends, then
    /// release local state.
    ///
    /// For a manager whose peer has already moved on to a new session — a held
    /// manager that lost a race to a freshly created one — `close_all()` is
    /// actively harmful: tunnel ids are per-friend and recycled, so the
    /// TUNNEL_CLOSE frames this session would emit can close the *winner's*
    /// identically-numbered tunnels on the peer. This suppresses those frames
    /// and only releases local state (target TCP sockets, tunnel ids).
    ///
    /// The mute is a **manager-level, one-way latch** (`outbound_muted()`), not
    /// a per-tunnel callback swap: every outbound path — `send_frame()`,
    /// `create_tunnel()`, `queue_outbound_for_retry()` and the
    /// `pending_outbound_` drain, including a drain already running that still
    /// holds a copy of the old send handler — checks it and discards. The
    /// manager's own timers (keepalive PING, maintenance reaper) are stopped
    /// first so they cannot generate new traffic mid-teardown. Once latched, no
    /// outbound path will authorise another frame; the manager exists only to
    /// be destroyed.
    ///
    /// The gate is raised in the SAME critical section that hands out
    /// `SendSnapshot`s and copies the callback. That closes the check-to-call
    /// seam: no caller can *acquire* a callback snapshot after the relevant
    /// gate closes. Note "after the gate closes", not "after this call begins" —
    /// the manager gate is raised in step 3 and the per-tunnel gates in step 4,
    /// so a snapshot taken in the interim is still valid.
    ///
    /// Be precise about what that buys, because it is less than it sounds.
    /// The gate stops new callback **snapshots**, not new callback
    /// **invocations**. A sender that took its snapshot microseconds before the
    /// latch can be descheduled between the snapshot and the call, and run its
    /// send after this function has returned. So the post-condition is:
    ///
    /// > **After the gate closes, no new callback snapshot can be acquired;
    /// > sends already authorised by a pre-gate snapshot may still start and
    /// > land.**
    ///
    /// That admits several concurrent sends, and `TUNNEL_DATA` among them —
    /// not merely a CLOSE/ERROR callback already entered.
    ///
    /// What this deliberately does NOT do is wait for those sends. An earlier
    /// version blocked until every pre-gate snapshot was released, aiming for
    /// "nothing of this session is on the wire when we return". That was
    /// unreachable from here: a send callback that tears its own tunnel down
    /// re-enters `force_close()` → `flush_pending_writes()` → the emission
    /// driver, which cannot *wait* for the in-flight send it was called from
    /// (the driver no longer holds `coalesce_mutex_` across a send since slice
    /// 2, so this is no longer a deadlock — but the wait is still meaningless).
    /// Because this
    /// runs on the strand that also carries inbound frames, the cure was worse
    /// than the disease: an indefinite data stall traded for one stale frame on
    /// an opt-in code path. (That re-entrant route is separately defused —
    /// `force_close()` skips the flush once the gate is closed — but the wait
    /// remains the wrong tool.)
    ///
    /// The send path no longer holds a lock across the Tox call (slice 2
    /// removed that), so the old deadlock is gone; the residual that remains is
    /// a *pre-gate snapshot* one — a sender that copied the callback
    /// microseconds before the gate closed can still land its frame. The
    /// consequence is a stale frame from an abandoned session, which the peer
    /// may map onto a recycled tunnel id. This is reachable only on the
    /// default-off resume path's loser-manager race, and closing it needs the
    /// session-generation machinery tracked separately (issue #30), not a
    /// patch here.
    void close_all_local();

    /// True once `close_all_local()` has abandoned this manager. Frames handed
    /// to an outbound path after that point are discarded rather than sent. A
    /// frame already authorised by a pre-gate snapshot is not covered — see
    /// `close_all_local()`.
    [[nodiscard]] bool outbound_muted() const noexcept;

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
    /// On toxcore SENDQ-full the frame is PARKED in `pending_outbound_` and
    /// this still returns true — "queued for sending", not "on the wire". That
    /// is safe only for frames whose identity does not matter if they are
    /// delivered late; see send_frame_typed() for the ones where it does.
    ///
    /// @param frame  The frame to send.
    /// @return       true if the frame was queued for sending.
    bool send_frame(const ProtocolFrame& frame);

    /// Send a frame and report the real transport verdict, WITHOUT parking it.
    ///
    /// `send_frame()`'s bool cannot distinguish "toxcore took it" from "we put
    /// it in a retry queue", and for an identity-carrying handshake frame that
    /// difference is a correctness bug rather than a fidelity one: the caller
    /// reads parked-as-delivered, resolves the tunnel, releases the id, the id
    /// is recycled, and the drain timer then delivers the stale frame against
    /// the new tunnel. `pending_outbound_` holds bare wire bytes with no tunnel
    /// identity and no generation, so the drain cannot detect this itself.
    ///
    /// A caller that gets `SendqFull` from here still owns the frame and is
    /// expected to retry it (see tunnel/sendq_retry.hpp for the cadence). This
    /// also reports `SendqFull` when the retry queue is merely non-empty:
    /// sending past parked frames would reorder the stream, so the caller waits
    /// its turn.
    [[nodiscard]] SendOutcome send_frame_typed(const ProtocolFrame& frame);

    /// Park an already-serialized frame in the outbound retry queue.
    /// Use this for a manager-owned control frame (PING/PONG, INFO_*,
    /// RESUME_*, or a manager-originated ERROR) that hit toxcore SENDQ-full
    /// and wants the same drain timer that `send_frame` uses to re-send it.
    /// The identity-bearing per-tunnel frames (OPEN/ACK/DATA and, since issue
    /// #24 slice 3, CLOSE/ERROR) are NOT parked here — they are retained and
    /// retried by their own driver. The bytes are the *unprefixed*
    /// frame (matching `send_handler_`'s contract) — the handler prepends
    /// the 0xA0 lossless byte before handing to toxcore.
    ///
    /// @return true ONLY when this queue took ownership of the bytes and will
    ///         retry them. false means the caller still owns the frame and it
    ///         will never be sent from here — either the outbound gate is
    ///         closed, or the queue was at its cap and the frame was dropped
    ///         (see logs / pending_dropped_total_).
    ///
    /// The doc previously said a cap-drop returned true. It does not, and the
    /// implementation is the one that is right: "true" has to mean "ownership
    /// transferred", because a caller that treats a dropped frame as sent will
    /// happily tear down state that the frame was supposed to announce.
    bool queue_outbound_for_retry(std::vector<uint8_t> wire);

    /// Drop every frame currently parked in `pending_outbound_`. Used when
    /// the queued frames are no longer addressable: failover swapped the
    /// active server out from under us, or the friend disconnected. Without
    /// this, the drain timer would eventually deliver stale frames to the
    /// *new* server (creating ghost tunnels) or wait indefinitely for a
    /// peer that has already gone away.
    void clear_pending_outbound();

    /// True while this manager holds an outbound frame that has not yet reached
    /// toxcore — either parked in `pending_outbound_` or popped by the drain and
    /// still inside the transport call.
    ///
    /// This is the FIFO barrier for senders that do NOT go through
    /// `send_frame()`. The per-tunnel callbacks hand their frames to toxcore
    /// directly (they must: they carry manager byte/frame accounting and the
    /// zero-copy owned path), so `send_frame_impl()`'s internal check cannot see
    /// them. Without consulting this first, the design's central failure would
    /// be live for any still-parked frame — historically CLOSE, before issue
    /// #24 slice 3 moved CLOSE/ERROR to driver ownership:
    ///
    ///     parked-frame(id=7) -> SendqFull -> parked, reported Sent
    ///       -> tunnel resolves -> id 7 released -> id 7 recycled
    ///     OPEN(id=7) -> sent DIRECTLY, accepted
    ///     drain timer -> stale parked-frame(id=7) -> disturbs the NEW tunnel 7
    ///
    /// Consulting it orders the new OPEN after the parked frame, which is the
    /// order the peer needs.
    ///
    /// Best-effort, and deliberately so: the caller releases this mutex before
    /// calling toxcore, so a frame parked by another thread in that gap is still
    /// overtaken. That residual is *concurrent*, while the hazard above is
    /// *causal* — the parked frame is queued before the id is released, so any
    /// later OPEN for the recycled id is ordered after it and sees a non-empty
    /// queue. Closing the concurrent residual as well needs a single outbound
    /// owner, which is the driver; CLOSE/ERROR already have it, and the frame
    /// types still on this queue (PING/PONG/INFO/RESUME) are the remaining
    /// scope.
    [[nodiscard]] bool outbound_queue_busy() const;

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
    // Outbound send-handler snapshot — see close_all_local()
    // -----------------------------------------------------------------

    /// An authorisation to call `send_handler_`, plus the handler copy itself.
    ///
    /// This tracks nothing and owns no resource. Nothing can enumerate the
    /// outstanding ones, and nothing can wait on them — that capability was
    /// removed along with the teardown drain (see close_all_local()). It was
    /// once called `SendLease`, and the name kept inviting the withdrawn
    /// "in-flight / drain / RAII" reading back into the docs.
    ///
    /// Construction takes `handler_mutex_` once and atomically tests the
    /// outbound gate and copies the handler. The handler itself is then called
    /// with NO lock held (it re-enters ToxAdapter and, on a permanent failure,
    /// the owning server — H-01 forbids doing that under one of this class's
    /// locks). Testing and copying together is the only thing this promises: it
    /// removes the check-to-call seam, so no caller can *acquire* a handler copy
    /// after the gate closed. A caller that acquired one microseconds BEFORE the
    /// gate closed still holds it and may still call it — see close_all_local()
    /// for that residual and for why waiting on it deadlocks.
    class SendSnapshot {
       public:
        explicit SendSnapshot(TunnelManager& manager);

        SendSnapshot(const SendSnapshot&) = delete;
        SendSnapshot& operator=(const SendSnapshot&) = delete;
        SendSnapshot(SendSnapshot&&) = delete;
        SendSnapshot& operator=(SendSnapshot&&) = delete;

        /// True when the gate was already closed and no snapshot was taken.
        [[nodiscard]] bool gate_closed() const noexcept { return gate_closed_; }

        /// The handler snapshot; empty when none was registered.
        [[nodiscard]] const SendHandler& handler() const noexcept { return handler_; }

       private:
        bool gate_closed_{false};
        SendHandler handler_;
    };

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Handle a PING frame (tunnel_id == 0).
    void handle_ping_frame(const ProtocolFrame& frame);

    /// Handle a PONG frame (tunnel_id == 0).
    void handle_pong_frame(const ProtocolFrame& frame);

    /// Find the next available tunnel ID, or std::nullopt if all are in use.
    /// Caller must hold the unique lock on mutex_.
    [[nodiscard]] std::optional<uint16_t> find_available_id();

    /// Arm `reaper_timer_` to fire `reaper_tick_ns_` from now, on behalf of
    /// generation @p epoch. **The caller must hold `timer_mutex_`** — that is
    /// what makes "the generation is still live" and "the timer is armed" a
    /// single indivisible step, and it is also the only thing that keeps
    /// concurrent `expires_after` / `cancel` / `async_wait` calls off the same
    /// asio timer object (asio explicitly does not allow that).
    void schedule_reaper_tick_locked(std::uint64_t epoch);

    /// Arm `keepalive_timer_` to fire `keepalive_interval_ns_` from now, on
    /// behalf of generation @p epoch. See `schedule_reaper_tick_locked`.
    void schedule_keepalive_tick_locked(std::uint64_t epoch);

    /// True while @p epoch is still the live keepalive generation.
    ///
    /// `asio::steady_timer::cancel()` only aborts waits that have not yet been
    /// dispatched; a handler already queued on (or running in) the io_context
    /// runs to completion regardless. Without this gate such a handler would
    /// PING a peer we have given up on and then call
    /// `schedule_keepalive_tick()`, which sets `keepalive_active_` back to true
    /// — silently undoing `disable_keepalive()`.
    [[nodiscard]] bool keepalive_epoch_current(std::uint64_t epoch) const noexcept;

    /// True while @p epoch is still the live maintenance-timer generation.
    [[nodiscard]] bool reaper_epoch_current(std::uint64_t epoch) const noexcept;

   public:
    /// Sentinel epoch meaning "not driven by a timer generation"; see
    /// reap_idle_tunnels_once().
    static constexpr std::uint64_t kAnyReaperEpoch = 0;

   private:
    /// Drain pending_outbound_ via send_handler_, FIFO. Re-arms the drain
    /// timer when send_handler_ reports SENDQ-full so control frames
    /// (OPEN, OPEN_ACK, CLOSE, ACK, PING) survive a burst-induced toxcore
    /// queue-full instead of being silently dropped. Public surface stays
    /// just `send_frame` — this is the recovery path it kicks off.
    void drain_pending_outbound();

    /// Shared body of `remove_tunnel()` and `remove_tunnel_if()`.
    ///
    /// @param expected     The tunnel the caller means, or nullptr.
    /// @param match_any    When true (`remove_tunnel()`), @p expected is ignored
    ///                     and whatever is registered is removed. When false
    ///                     (`remove_tunnel_if()`), a null or mismatched
    ///                     @p expected removes nothing.
    bool remove_tunnel_impl(uint16_t tunnel_id, const Tunnel* expected, bool match_any);

    /// Shared body of `send_frame()` and `send_frame_typed()`.
    ///
    /// @param park_on_backpressure  When true (the `send_frame` contract), a
    ///        SENDQ-full frame is parked in `pending_outbound_` and reported as
    ///        `Sent` — i.e. "this queue owns it now", which is exactly what
    ///        `send_frame`'s historical `true` meant. When false (the
    ///        `send_frame_typed` contract) nothing is parked and `SendqFull` is
    ///        returned to the caller, who still owns the frame.
    SendOutcome send_frame_impl(const ProtocolFrame& frame, bool park_on_backpressure);

    /// Arm `pending_drain_timer_` to fire after a short delay; idempotent
    /// while a drain is already pending. Caller must hold `pending_mutex_`.
    void arm_pending_drain_timer_locked();

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

    // ---- Outbound fence (see close_all_local / SendSnapshot) --------------
    /// One-way latch, always written under `handler_mutex_` in the same
    /// critical section that nulls `send_handler_`, so no snapshot can be taken
    /// after `close_all_local()` has closed the gate. Snapshots taken *before*
    /// it are unaffected and may still call their copy.
    bool send_gate_closed_{false};

    /// Serialises every state transition of `reaper_timer_` and
    /// `keepalive_timer_`.
    ///
    /// Two jobs, both required:
    ///  1. It makes "check the generation" and "arm / cancel the timer" one
    ///     indivisible step. Before it, a stale tick handler could pass its
    ///     final epoch check, get preempted by disable_*() + enable_*() (the
    ///     resume pause/resurrect sequence), then overwrite the freshly armed
    ///     wait with its own retired one — leaving ZERO live chains: the new
    ///     wait had been cancelled and the old one is refused at the entry gate.
    ///  2. asio does not permit concurrent operations on a single timer object.
    ///     `enable_*()` runs on the caller's thread while the completion handler
    ///     runs on an io_context thread, and both call `expires_after` /
    ///     `cancel` / `async_wait` on the same object. This mutex is the only
    ///     thing serialising them.
    ///
    /// Discipline: it is a LEAF. Nothing that can re-enter this class (a send,
    /// a reap, an application callback) may run while it is held; the tick
    /// handler therefore does its work unlocked and only takes it for the entry
    /// check and the re-arm. `steady_timer::cancel()` never invokes handlers
    /// inline (asio posts them), so cancelling under it is safe.
    mutable std::mutex timer_mutex_;

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

    /// Idle threshold in nanoseconds. 0 means the idle reaper is disabled.
    std::atomic<int64_t> reaper_idle_timeout_ns_{0};

    /// Half-close linger threshold in nanoseconds. 0 means the cap is
    /// disabled. Applies only to tunnels in the Disconnecting state. Shares
    /// `reaper_timer_` / the maintenance scan with `reaper_idle_timeout_ns_`.
    std::atomic<int64_t> reaper_half_close_timeout_ns_{0};

    /// Configured tick interval, in nanoseconds. Written by enable_reaper() /
    /// enable_half_close_reaper() from arbitrary threads and read by the timer
    /// handler on an io_ctx thread, so it must be atomic (it was a plain
    /// `std::chrono::seconds` — a genuine data race, benign in practice only
    /// because both writers store the same value at startup).
    std::atomic<int64_t> reaper_tick_ns_{0};

    /// Set to true while a reaper tick is scheduled; flipped back to
    /// false from the timer's completion handler. Lets disable_reaper()
    /// distinguish "armed" from "idle" without racing the io_ctx thread.
    std::atomic<bool> reaper_active_{false};

    /// Maintenance-timer generation. Bumped by every enable_*/disable_reaper()
    /// so an already-dispatched tick handler can tell that it belongs to a
    /// retired generation and must neither reap nor re-arm.
    std::atomic<std::uint64_t> reaper_epoch_{0};

    // ---- Pending outbound retry (toxcore SENDQ-full recovery) ------------
    /// Control frames (OPEN, OPEN_ACK, CLOSE, ACK, PING/PONG) routed through
    /// send_frame() that fail with toxcore SENDQ-full are parked here in FIFO
    /// order and retried on `pending_drain_timer_`. Without this queue, the
    /// silent OPEN_ACK drop wedges the peer in `Connecting` indefinitely under
    /// a burst of concurrent tunnel opens. Capped by `kMaxPendingOutbound`
    /// to bound memory under sustained backpressure.
    std::deque<std::vector<uint8_t>> pending_outbound_;
    mutable std::mutex pending_mutex_;
    asio::steady_timer pending_drain_timer_;
    bool pending_drain_armed_{false};
    /// True while `drain_pending_outbound()` has popped an entry and is inside
    /// the transport call with `pending_mutex_` released.
    ///
    /// Without it the FIFO barrier has a hole exactly one frame wide: the
    /// drained frame is no longer in `pending_outbound_`, so a concurrent
    /// `send_frame()` / `send_frame_typed()` sees an empty queue and sends
    /// directly, overtaking a frame that is still on its way to toxcore. The
    /// in-flight entry is therefore part of the queue for barrier purposes even
    /// though it is not in the deque. Guarded by `pending_mutex_`.
    bool pending_drain_in_flight_{false};
    /// Counter for diagnostics / metrics: total frames that hit the retry path.
    std::atomic<std::uint64_t> pending_enqueued_total_{0};
    /// Counter for diagnostics / metrics: frames dropped because the queue
    /// hit its cap (genuine loss — caller's send_frame returned false).
    std::atomic<std::uint64_t> pending_dropped_total_{0};

    /// One-way latch set by close_all_local(). Every outbound path checks it
    /// and discards instead of sending. Stored/loaded under `pending_mutex_`
    /// on the paths that also touch `pending_outbound_`, so "muted" and
    /// "queue emptied" are never observed apart; elsewhere it is a plain
    /// acquire/release load. See close_all_local().
    std::atomic<bool> outbound_muted_{false};

    // ---- Keepalive (M-02) ------------------------------------------------
    /// Keepalive timer; armed only while keepalive is enabled.
    asio::steady_timer keepalive_timer_;
    /// steady_clock ns of the most recent PONG / liveness signal. 0 = none yet.
    std::atomic<int64_t> last_pong_ns_{0};
    /// Interval / liveness deadline in nanoseconds. Atomic for the same reason
    /// as reaper_tick_ns_: enable_keepalive() runs on the caller's thread while
    /// the tick handler reads them on an io_ctx thread.
    std::atomic<int64_t> keepalive_interval_ns_{0};
    std::atomic<int64_t> keepalive_timeout_ns_{0};
    /// True while a keepalive tick is scheduled (mirrors reaper_active_).
    std::atomic<bool> keepalive_active_{false};
    /// Keepalive generation; see reaper_epoch_ and keepalive_epoch_current().
    std::atomic<std::uint64_t> keepalive_epoch_{0};
    /// Latches the peer-dead transition so on_peer_dead_ fires at most once.
    std::atomic<bool> peer_dead_latched_{false};
    /// Fired once when the peer is declared dead. Guarded by handler_mutex_.
    std::function<void()> on_peer_dead_;
};

/// Decide what a per-tunnel `SendToToxCallback` reports — and whether it parks
/// anything — when toxcore refuses @p wire with SENDQ-full.
///
/// @param wire  The *unprefixed* frame; the type byte is at offset 0.
///
/// The routing is per frame type because ownership of the retry differs:
///
///  * TUNNEL_OPEN / TUNNEL_ACK — returned as `SendqFull`, NOT parked. These are
///    the identity-carrying handshake frames, and their drivers (TunnelImpl's
///    OPEN retry, TunnelServer's OPEN_ACK gate) retain and re-send them
///    themselves. Parking them is precisely the bug: `pending_outbound_` holds
///    bare wire bytes with no tunnel identity and no generation, the caller
///    reads the park as a delivery, resolves the tunnel and releases the id,
///    and the drain timer later delivers the stale frame against whatever
///    tunnel recycled that id.
///
///  * TUNNEL_DATA, TUNNEL_CLOSE, TUNNEL_ERROR — returned as `SendqFull`, NOT
///    parked. Each is driver-owned (issue #24 slice 3): the per-tunnel
///    emission driver retains and retries DATA (coalesce buffer), CLOSE
///    (`CloseFrameState` + close-retry timer) and ERROR (terminal-ERROR slot +
///    its own retry timer). Parking their raw bytes would strip the tunnel
///    identity off them and let a parked CLOSE drain after a directly-accepted
///    ERROR — wire order ERROR,CLOSE, the very hazard the single driver exists
///    to prevent.
///
///  * Everything else (INFO 0x06/0x07, RESUME 0x08/0x09, PING 0x10, PONG
///    0x11) — parked in the manager retry queue and reported as `Sent`. A
///    queue at its cap reports `PermanentFail`, since nothing took ownership of
///    the frame.
///
///    KNOWN AND DELIBERATE: those remaining frame types still carry the
///    stale-frame-onto-a-recycled-id hazard described above. Fixing them means
///    moving each to driver ownership the way OPEN, OPEN_ACK, CLOSE and ERROR
///    now are, which is a separate change.
///
///    This is *policy* preservation, not behaviour preservation. Parked frames
///    now coexist with driver-retained ones, which is a new arrangement: the
///    two classes retry on different clocks and against different owners, so
///    their relative order is no longer whatever the single queue imposed.
///    `TunnelManager::send_frame_typed()` keeps the barrier honest in the one
///    direction that matters — a driver-owned frame never overtakes a parked or
///    mid-drain one — but the converse is not claimed, and a parked frame can
///    still be delivered after a driver-owned frame that was issued later.
[[nodiscard]] SendOutcome route_sendq_full(TunnelManager& manager,
                                           std::span<const std::uint8_t> wire);

/// True for the frame types that must consult `TunnelManager::outbound_queue_busy()`
/// before being handed to toxcore on the direct per-tunnel path.
///
/// Only TUNNEL_OPEN and TUNNEL_ACK — see the definition for why TUNNEL_DATA is
/// covered transitively and why the still-parked control frames are not covered
/// at all.
[[nodiscard]] bool frame_must_respect_outbound_barrier(FrameType type) noexcept;

}  // namespace toxtunnel::tunnel
