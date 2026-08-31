#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/bdp_flow_control.hpp"
#include "toxtunnel/tunnel/owned_frame_buffer.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/sendq_retry.hpp"
#include "toxtunnel/tunnel/write_coalescer.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::tunnel {

/// Smallest coalesce delay this platform can actually honour.
///
/// asio's timer resolution follows the OS. Linux and macOS deliver a 200 us
/// steady_timer within tens of microseconds; Windows rides the system tick, and
/// on a Windows 11 ARM64 VM a 200 us timer measured 68 ms mean / 139 ms worst.
/// Holding data for 68 ms when the operator asked for 200 us breaks the setting's
/// contract far worse than not batching at all, so a sub-floor delay is treated
/// as 0 (emit immediately) — see clamp_coalesce_delay_to_platform in tunnel.cpp.
#if defined(_WIN32)
inline constexpr std::uint32_t kMinHonouredCoalesceDelayUs = 15'600;  // classic Windows tick
#else
inline constexpr std::uint32_t kMinHonouredCoalesceDelayUs = 1;
#endif

}  // namespace toxtunnel::tunnel

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// Transport outcome
// ---------------------------------------------------------------------------

/// Result of one attempt to hand a frame to the toxcore lossless send path.
///
/// This is deliberately NOT a bool. toxcore distinguishes "the send queue is
/// momentarily full, try again" from "this will never work", and collapsing
/// the two costs correctness rather than just fidelity: a caller that reads a
/// backpressured control frame as delivered goes on to release the tunnel id,
/// and the id is then recycled while the original frame is still queued to be
/// sent. A stale TUNNEL_CLOSE landing on a recycled id kills the wrong tunnel.
///
/// Lives here rather than in tunnel_manager.hpp because the per-tunnel send
/// callbacks need it and tunnel_manager.hpp already includes this header.
enum class SendOutcome : std::uint8_t {
    Sent,           ///< Accepted by toxcore.
    SendqFull,      ///< Transient backpressure — the caller still owns the frame.
    PermanentFail,  ///< Will not succeed. Roll back; peer gone, frame malformed.
};

/// Outcome of a request to the outbound emission driver (slice 2 of
/// docs/design/outbound-send-driver.md, tracked as issue #24).
///
/// `DeferredToActiveEmitter` must NEVER be read as satisfied: another thread
/// owns the drain and this request's bytes (or its flush intent) have merely
/// been queued behind it. A close path that treats "deferred" as "drained"
/// emits its CLOSE while DATA is still in flight and the CLOSE overtakes the
/// DATA — the exact bug the design doc records as its first rejected draft.
///
/// `RequestSatisfied` for a full-frames-only request is compatible with a
/// sub-MTU remainder still buffered — it is named for what it means, not
/// "Drained".
enum class EmitOutcome : std::uint8_t {
    RequestSatisfied,         ///< The drain this caller asked for was performed.
    DeferredToActiveEmitter,  ///< Another thread is the emitter; it will pick this up.
    Backpressured,            ///< toxcore SENDQ full; bytes retained, retry timer armed.
};

/// What a drain request asks of the emission driver.
enum class DrainPolicy : std::uint8_t {
    FullFramesOnly,  ///< Emit whole `cap`-sized frames; a sub-cap remainder stays.
    FlushAll,        ///< Emit everything, including a sub-cap final frame.
};

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

class ProtocolFrame;

// ---------------------------------------------------------------------------
// Tunnel State Machine - Abstract Interface
// ---------------------------------------------------------------------------

/// Abstract base class for a single tunnel connection.
///
/// A Tunnel represents one end of a bidirectional data pipe between
/// a local TCP connection and a remote peer via Tox. The TunnelManager
/// owns and orchestrates multiple Tunnel instances.
///
/// Concrete implementations handle the specific connection logic and state machine.
///
/// Tunnels are always held via shared_ptr (the manager stores
/// shared_ptr<Tunnel>; TCP/Tox callbacks capture them by value).
/// `enable_shared_from_this` lets timer handlers (coalesce / future
/// per-tunnel timers) capture a weak_ptr instead of `this`, so a
/// destructor that races a not-yet-dispatched timer firing doesn't
/// UAF (S17 in the 2026-05-20 follow-up).
class Tunnel : public std::enable_shared_from_this<Tunnel> {
   public:
    // -----------------------------------------------------------------
    // State enum
    // -----------------------------------------------------------------

    /// Lifecycle states for a tunnel.
    enum class State : uint8_t {
        None,           ///< Initial state; no connection attempted.
        Connecting,     ///< TUNNEL_OPEN sent, awaiting response.
        Connected,      ///< Tunnel is active and data can flow.
        Disconnecting,  ///< TUNNEL_CLOSE sent, awaiting drain.
        Closed,         ///< Tunnel is fully closed.
        Error,          ///< Tunnel encountered an error.
    };

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct a tunnel with the given identifier.
    explicit Tunnel(uint16_t tunnel_id, asio::io_context& io_ctx)
        : tunnel_id_(tunnel_id), io_ctx_(io_ctx) {}

    /// Virtual destructor for proper cleanup.
    virtual ~Tunnel() = default;

    /// Non-copyable, non-movable.
    Tunnel(const Tunnel&) = delete;
    Tunnel& operator=(const Tunnel&) = delete;
    Tunnel(Tunnel&&) = delete;
    Tunnel& operator=(Tunnel&&) = delete;

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the tunnel identifier.
    [[nodiscard]] uint16_t tunnel_id() const noexcept { return tunnel_id_; }

    /// Return the current state.
    [[nodiscard]] virtual State state() const noexcept = 0;

    /// Return true if the tunnel is active (connected and operational).
    [[nodiscard]] virtual bool is_active() const = 0;

    /// Return the current buffer level (bytes queued for sending).
    [[nodiscard]] virtual std::size_t buffer_level() const = 0;

    // -----------------------------------------------------------------
    // Frame handling
    // -----------------------------------------------------------------

    /// Handle an incoming protocol frame.
    ///
    /// Called by TunnelManager when a frame addressed to this tunnel
    /// is received.
    virtual void handle_frame(const ProtocolFrame& frame) = 0;

    // -----------------------------------------------------------------
    // Tunnel lifecycle
    // -----------------------------------------------------------------

    /// Close the tunnel gracefully.
    ///
    /// Should flush any pending data and notify the remote peer
    /// with a TUNNEL_CLOSE frame.
    virtual void close() = 0;

   protected:
    /// The tunnel identifier.
    uint16_t tunnel_id_;

    /// Reference to the io_context for async operations.
    asio::io_context& io_ctx_;
};

/// Return a human-readable label for a Tunnel state.
[[nodiscard]] const char* to_string(Tunnel::State state) noexcept;

// ---------------------------------------------------------------------------
// Concrete Tunnel Implementation
// ---------------------------------------------------------------------------

/// Concrete implementation of a tunnel with full state machine.
///
/// TunnelImpl manages:
/// - State transitions: None -> Connecting -> Connected -> Disconnecting -> Closed
/// - Bidirectional data flow between TCP and Tox
/// - Flow control with ACK frames
/// - Keep-alive with PING/PONG frames
/// - Per-tunnel statistics and error handling
///
/// Thread safety: All public methods are safe to call from any thread.
/// Internal state is protected by a mutex.
class TunnelImpl : public Tunnel {
   public:
    // -----------------------------------------------------------------
    // Callback signatures
    // -----------------------------------------------------------------

    /// Called when a frame should be sent to the Tox peer.
    ///
    /// Returns the typed `SendOutcome` rather than a bool, and the distinction
    /// is load-bearing for identity-carrying control frames. `SendqFull` means
    /// the frame was NOT handed to toxcore and the tunnel still owns it: the
    /// tunnel retries it itself rather than letting the manager park raw wire
    /// bytes that carry no tunnel identity. `Sent` is the only outcome that
    /// may advance a handshake or release an id. `PermanentFail` rolls back.
    ///
    /// The caller also uses this to refund per-tunnel send-window accounting;
    /// without it a transient drop would leak window bytes forever (S27 in the
    /// 2026-05-20 follow-up).
    using SendToToxCallback = std::function<SendOutcome(std::span<const uint8_t> data)>;

    /// Zero-copy outbound (Wave B): called when a fully-framed TUNNEL_DATA
    /// frame should be sent to the Tox peer. The supplied `OwnedFrameBuffer`
    /// already carries the lossless prefix byte plus the 5-byte tunnel header
    /// in its reserved prefix; the callee only needs to hand `wire_view()` to
    /// `ToxAdapter::send_lossless_packet` and keep the buffer alive until that
    /// returns. When this callback is set on a tunnel, it takes precedence
    /// over `SendToToxCallback` for TUNNEL_DATA frames produced by
    /// `send_data_to_tox`; non-DATA control frames continue to take the
    /// span-based callback for simplicity (their payloads are tiny and the
    /// extra copy is not measurable).
    ///
    /// Same typed contract as `SendToToxCallback`: only `Sent` counts as
    /// delivered; `SendqFull` leaves the frame with the tunnel to retry, and
    /// `PermanentFail` refunds the window.
    using SendOwnedToToxCallback = std::function<SendOutcome(OwnedFrameBuffer buf)>;

    /// Called when data should be written to the TCP connection.
    ///
    /// Returns true if the local TCP side accepted the bytes (queued for
    /// sending), false if it is backpressured. The tunnel uses the result to
    /// decide whether to ACK the peer: it only ACKs accepted bytes, so a slow
    /// local socket throttles the peer's send window instead of silently
    /// dropping inbound data (C-03). The bytes themselves are NOT lost on
    /// false — TcpConnection still enqueues them; false is purely the
    /// "withhold ACK" signal.
    using SendToTcpCallback = std::function<bool(std::span<const uint8_t> data)>;

    /// Zero-copy variant: called when an owned (shared_ptr-backed) buffer
    /// should be written to the TCP connection. The callee can hand the
    /// view straight to `TcpConnection::write(OwnedBufferView)` without
    /// any payload copy. When this callback is set on a tunnel, it takes
    /// precedence over `SendToTcpCallback` for inbound TUNNEL_DATA frames.
    ///
    /// Same return contract as SendToTcpCallback: true = accepted, false =
    /// backpressured (withhold ACK, bytes still enqueued — C-03).
    using SendToTcpOwnedCallback = std::function<bool(core::OwnedBufferView buf)>;

    /// Called when the tunnel state changes.
    using StateChangedCallback = std::function<void(State new_state)>;

    /// Called when an error frame is received.
    using ErrorCallback = std::function<void(const TunnelErrorPayload& error)>;

    /// Called when the tunnel is closed.
    using CloseCallback = std::function<void()>;

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    /// Default send window size (256 KiB).
    static constexpr std::size_t kDefaultSendWindowSize = 256 * 1024;

    /// Default ACK threshold (16 KiB).
    static constexpr std::size_t kDefaultAckThreshold = 16 * 1024;

    /// Default coalescing flush delay (microseconds). Mirrors the
    /// `TunnelConfig.coalesce_max_delay_us` schema default.
    static constexpr std::uint32_t kDefaultCoalesceMaxDelayUs = 200;

    /// Default per-frame coalescing payload cap. Mirrors the
    /// `TunnelConfig.coalesce_max_bytes` schema default and stays below the
    /// 1367-byte ceiling imposed by Tox lossless framing.
    static constexpr std::uint32_t kDefaultCoalesceMaxBytes = 1362;

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct a TunnelImpl.
    ///
    /// @param io_ctx         The io_context for async operations.
    /// @param tunnel_id      Unique tunnel identifier within the friend context.
    /// @param friend_number  The toxcore friend number.
    /// @param send_window    Maximum bytes in-flight before backpressure.
    TunnelImpl(asio::io_context& io_ctx, uint16_t tunnel_id, uint32_t friend_number,
               std::size_t send_window = kDefaultSendWindowSize);

    ~TunnelImpl() override;

    // -----------------------------------------------------------------
    // Tunnel interface implementation
    // -----------------------------------------------------------------

    [[nodiscard]] State state() const noexcept override {
        return state_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool is_active() const override {
        return state_.load(std::memory_order_acquire) == State::Connected;
    }

    [[nodiscard]] std::size_t buffer_level() const override {
        return send_window_used_.load(std::memory_order_relaxed);
    }

    void handle_frame(const ProtocolFrame& frame) override;

    void close() override;

    // -----------------------------------------------------------------
    // Extended accessors
    // -----------------------------------------------------------------

    /// Return the friend number.
    [[nodiscard]] uint32_t friend_number() const noexcept { return friend_number_; }

    /// Return true if the tunnel is in the Connected state.
    [[nodiscard]] bool is_connected() const noexcept {
        return state_.load(std::memory_order_acquire) == State::Connected;
    }

    /// Return the target hostname (only valid after open()).
    [[nodiscard]] std::string target_host() const;

    /// Return the target port (only valid after open()).
    [[nodiscard]] uint16_t target_port() const noexcept;

    /// Return the time of last activity.
    [[nodiscard]] std::chrono::steady_clock::time_point last_activity() const;

    /// Return nanoseconds elapsed since the tunnel last saw TUNNEL_DATA activity.
    ///
    /// "Activity" is defined narrowly: only TUNNEL_DATA frames in either
    /// direction reset the timer. PING/PONG keep-alives, ACKs, and control
    /// frames are NOT activity for the reaper's purposes.
    [[nodiscard]] int64_t IdleNanos() const noexcept;

    /// Close this tunnel because a maintenance timer reaped it (idle reaper or
    /// half-close linger cap), as opposed to the application closing it.
    ///
    /// Two things differ from close():
    ///  * the close is accounted as `CloseReason::Timeout` rather than `Local`,
    ///    so `toxtunnel_tunnels_closed_total{reason="timeout"}` is no longer a
    ///    permanently-zero label and reaper activity is distinguishable from
    ///    ordinary application disconnects;
    ///  * a tunnel already in `Disconnecting` (we sent our half-close, the peer
    ///    never reciprocated — exactly the case the linger cap exists for) is
    ///    NOT silently dropped. close() is a no-op in that state, so the peer
    ///    would keep its own tunnel in `Connected` with the target fd open
    ///    forever: the cap would "fix" a local fd leak by handing the peer a
    ///    permanent one. Instead we send TUNNEL_ERROR so the peer tears down
    ///    too.
    void close_for_timeout();

   private:
    /// Local (we-initiated) closes are booked as Local, unless a maintenance
    /// timer is the one closing us — see close_for_timeout().
    [[nodiscard]] util::MetricsRegistry::CloseReason local_close_reason() const noexcept;

   public:
    // -----------------------------------------------------------------
    // TCP connection management
    // -----------------------------------------------------------------

    /// Set the TCP connection for this tunnel.
    void set_tcp_connection(std::shared_ptr<core::TcpConnection> tcp_conn);

    /// Get the TCP connection (may be null).
    [[nodiscard]] std::shared_ptr<core::TcpConnection> tcp_connection() const;

    /// Server-side: record the resolved target host/port so `inspect tunnels`
    /// can render `target` instead of the bare `":0"` placeholder. The client
    /// side populates these via `open()`; the server constructs the tunnel
    /// outside the TunnelImpl::handle_tunnel_open_frame path (intentionally —
    /// the server-role open handshake lives in TunnelServer), so it needs an
    /// explicit setter. Safe to call at any time; the value is only consumed
    /// by getters.
    void set_target(const std::string& host, std::uint16_t port);

    // -----------------------------------------------------------------
    // State management
    // -----------------------------------------------------------------

    /// Manually set the state (use with caution).
    void set_state(State new_state);

    // -----------------------------------------------------------------
    // Tunnel lifecycle
    // -----------------------------------------------------------------

    /// Initiate tunnel opening.
    ///
    /// Sends a TUNNEL_OPEN frame and transitions to Connecting state.
    ///
    /// The tunnel — not TunnelManager's retry queue — owns the TUNNEL_OPEN
    /// until toxcore accepts it. On `SendOutcome::SendqFull` the frame is
    /// RETAINED and re-attempted on this tunnel's own SENDQ backoff timer
    /// (sendq_retry.hpp) while the state stays `Connecting`; the id is not
    /// released and the open is not reported as delivered. That matters
    /// because the manager queue parks bare wire bytes with no tunnel identity
    /// and no generation, so a frame parked there and reported as sent lets the
    /// caller resolve the tunnel, release the id, and have the drain timer
    /// deliver the stale frame onto whatever tunnel recycled it.
    ///
    /// Only `PermanentFail` rolls back to `None`.
    ///
    /// @param host  Target hostname or IP address.
    /// @param port  Target TCP port.
    /// @return      True if the open was initiated (sent, or retained for
    ///              retry), false if the state was wrong, the host is
    ///              unrepresentable, or the transport failed permanently.
    [[nodiscard]] bool open(const std::string& host, uint16_t port);

    /// True once a TUNNEL_OPEN for this tunnel was actually accepted by
    /// toxcore, as opposed to merely attempted.
    ///
    /// This is the predicate for "is a TUNNEL_CLOSE required?". A tunnel
    /// resolved locally while its OPEN is still backpressured must NOT emit
    /// one: the peer has never heard of this id, so the CLOSE either names
    /// nothing or — ids being recycled per friend — tears down an unrelated
    /// tunnel once this id is reused. Once the OPEN is on the wire the peer
    /// owns half a tunnel and the CLOSE becomes mandatory.
    [[nodiscard]] bool open_sent() const noexcept;

    /// Number of TUNNEL_OPEN send attempts made so far (the initial one plus
    /// every retry). Exposed for tests that assert the retry cadence does not
    /// degenerate into a spin.
    [[nodiscard]] unsigned open_attempts() const noexcept {
        return open_attempts_.load(std::memory_order_relaxed);
    }

    /// Immediately close the tunnel without graceful shutdown.
    void force_close();

    /// Publish this tunnel as `Connected`, but only from the unpublished
    /// `None` state, and report whether THIS call was the one that did it.
    ///
    /// The server's OPEN_ACK gate leaves a tunnel in `None` until its ACK is on
    /// the wire, so publication races every teardown path. Asking the manager
    /// "do you still own this tunnel?" and then publishing is check-then-act:
    /// the manager releases its lock before the answer can be used. This
    /// compare-exchange is the actual claim, and it works because the teardown
    /// side goes through the same state word — `TunnelManager::remove_tunnel()`
    /// force-closes a tunnel that is still `None` rather than calling `close()`,
    /// which would no-op there and leave nothing for this to lose against.
    [[nodiscard]] bool try_publish_connected();

    // -----------------------------------------------------------------
    // Data handling
    // -----------------------------------------------------------------

    /// Called when TCP data is received.
    ///
    /// Creates and queues a TUNNEL_DATA frame for sending to Tox.
    void on_tcp_data_received(const uint8_t* data, std::size_t length);

    /// Called when the local TCP peer half-closes its send side. Emits a
    /// TUNNEL_CLOSE for the local->remote direction after accepted outbound
    /// bytes drain, but keeps the remote->local direction alive until the peer
    /// closes too.
    void on_tcp_read_eof();

    /// Send data through the tunnel to the Tox peer.
    ///
    /// @param data  Data to send.
    /// @return      True if the data was accepted, false if window is full
    ///              or tunnel is not connected.
    [[nodiscard]] bool send_data_to_tox(std::span<const uint8_t> data);

    /// Convenience overload accepting a vector.
    [[nodiscard]] bool send_data_to_tox(const std::vector<uint8_t>& data);

    // -----------------------------------------------------------------
    // Write-side coalescing
    // -----------------------------------------------------------------

    /// Configure the per-tunnel write coalescer.
    ///
    /// @param max_delay_us  Maximum time a byte is held before being flushed.
    ///                      Zero disables coalescing (every write emits its
    ///                      own TUNNEL_DATA frames immediately).
    /// @param max_bytes     Maximum payload size per emitted TUNNEL_DATA
    ///                      frame. Hard-capped to the Tox-MTU ceiling.
    void configure_coalesce(std::uint32_t max_delay_us, std::uint32_t max_bytes);

    /// Set the operator-selected coalesce mode. The state machine in the
    /// per-tunnel `WriteCoalescer` runs on every `send_data_to_tox` and
    /// picks the active `CoalescePolicy` (Bypass/Drain/Batch). Default is
    /// `Fixed` which always uses `Batch`.
    void set_coalesce_mode(CoalesceMode mode);

    /// Read-only access to the active coalescer (metrics, inspect).
    [[nodiscard]] const WriteCoalescer& write_coalescer() const noexcept { return coalescer_; }

    /// Configure the BDP-aware flow-control window. Replaces the constructor
    /// fixed-window argument. When `mode: bdp` is selected, RTT and bandwidth
    /// observations from `observe_rtt_us`/`observe_bandwidth_bps` (driven by
    /// the existing PING/PONG and ACK paths) resize the window in place.
    void configure_flow_control(const BdpFlowControl::Config& cfg);

    /// Observation hooks for the BDP estimator. Wired from the PING/PONG and
    /// TUNNEL_ACK paths. Calling these has no effect when flow control is in
    /// fixed mode (the EWMA is still updated for telemetry).
    void observe_rtt_us(std::int64_t rtt_us);
    void observe_bandwidth_bps(std::int64_t bps);

    /// Current target window — exposed for metrics + inspect.
    [[nodiscard]] std::int64_t target_window_bytes() const noexcept {
        return flow_control_.target_window_bytes();
    }

    /// Current EWMA RTT in microseconds.
    [[nodiscard]] std::int64_t rtt_us() const noexcept { return flow_control_.rtt_us(); }

    /// Current EWMA bandwidth estimate (bytes/sec).
    [[nodiscard]] std::int64_t bandwidth_bps() const noexcept {
        return flow_control_.bandwidth_bps();
    }

    /// Flush any buffered coalesced bytes immediately as one frame.
    /// Used by close() / force_close() and exposed for tests.
    void flush_pending_writes();

    /// Called (on the TcpConnection strand) when the local TCP write queue has
    /// drained back below its low-water mark. Flushes any TUNNEL_ACK that was
    /// withheld while the socket was backpressured, reopening the peer's send
    /// window so inbound data resumes (C-03 receiver-side flow control).
    ///
    /// Returns true if the ACK was fully flushed (nothing left pending), false
    /// if the ACK send itself backpressured — the TcpConnection keeps its
    /// watermark armed and calls again on the next drained frame.
    bool notify_tcp_writable();

    // -----------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------

    /// Send the single terminal TUNNEL_ERROR and transition to Error state.
    ///
    /// Slice-3 ordering (issue #24): atomically seals admission and abandons
    /// undelivered DATA (`publish_abort_locked`), claims the one terminal
    /// ERROR, and only then — with no lock held — sends the frame and fires
    /// the state/close callbacks (which may re-enter admission; the seal is
    /// already published, so they are refused instead of racing the
    /// abandonment). A second call is a suppressed duplicate: one tunnel,
    /// one terminal ERROR.
    void send_error(uint8_t error_code, const std::string& description);

    // -----------------------------------------------------------------
    // Flow control
    // -----------------------------------------------------------------

    /// Return the number of bytes currently in the send window.
    [[nodiscard]] std::size_t send_window_used() const noexcept {
        return send_window_used_.load(std::memory_order_relaxed);
    }

    /// Return the send window size.
    [[nodiscard]] std::size_t send_window_size() const noexcept { return send_window_size_; }

    /// Return the number of bytes received (for ACK generation).
    [[nodiscard]] std::size_t bytes_received() const noexcept {
        return total_bytes_received_.load(std::memory_order_relaxed);
    }

    /// Return the number of bytes accepted from the local TCP side (charged to
    /// the send window at accept time). NOTE: this counts bytes that may still
    /// be buffered in the coalescer and not yet on the wire — use
    /// `bytes_emitted()` for "what the peer could have received".
    [[nodiscard]] std::size_t bytes_sent() const noexcept {
        return total_bytes_sent_.load(std::memory_order_relaxed);
    }

    /// Return the number of payload bytes actually handed to toxcore (emitted
    /// on the wire). This is <= bytes_sent() whenever data is buffered under
    /// backpressure. Used as the resume "send offset" so buffered-but-unsent
    /// bytes are not mistaken for a transmission gap.
    [[nodiscard]] std::uint64_t bytes_emitted() const noexcept {
        return total_bytes_emitted_.load(std::memory_order_acquire);
    }

    /// Set the ACK threshold (bytes received before sending ACK).
    void set_ack_threshold(std::size_t threshold) noexcept;

    // -----------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------

    /// Reset all statistics counters.
    void reset_statistics();

    // -----------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------

    /// Set callback for sending data to Tox.
    void set_on_send_to_tox(SendToToxCallback cb);

    /// Set the zero-copy callback for outbound TUNNEL_DATA frames. When set,
    /// `send_data_to_tox` builds an `OwnedFrameBuffer` (header reserved in
    /// the same allocation) and hands it to this callback instead of going
    /// through the span-based callback. Control frames continue to take the
    /// span path. Setting this to a null callback disables the zero-copy
    /// outbound path.
    void set_on_send_to_tox_owned(SendOwnedToToxCallback cb);

    /// Set callback for sending data to TCP.
    void set_on_data_for_tcp(SendToTcpCallback cb);

    /// Set the zero-copy callback for owned buffers. When both this and the
    /// span-based callback are set, the owned callback wins for TUNNEL_DATA
    /// frames; non-DATA paths fall back to the span-based callback.
    void set_on_data_for_tcp_owned(SendToTcpOwnedCallback cb);

    /// Set callback for state changes.
    void set_on_state_change(StateChangedCallback cb);

    /// Set callback for error frames.
    void set_on_error(ErrorCallback cb);

    /// Set callback for tunnel close.
    void set_on_close(CloseCallback cb);

    // -----------------------------------------------------------------
    // Outbound gate — "no further send is authorised" (H-2, 3rd review)
    // -----------------------------------------------------------------

    /// Close this tunnel's outbound gate.
    ///
    /// Swapping the send callbacks was NOT enough to silence a tunnel: every
    /// send path copies the callback out from under `mutex_` and invokes it
    /// after the lock is dropped (it must — a Tox send re-enters the manager,
    /// so holding a tunnel lock across it deadlocks; H-01). A sender that had
    /// already taken its copy therefore still delivered its frame *after* the
    /// swap, and one stale TUNNEL_CLOSE / TUNNEL_ERROR is enough to kill the
    /// winning session's identically-numbered tunnel (ids are recycled per
    /// friend).
    ///
    /// The gate replaces the copy-then-call race: a sender tests the gate and
    /// copies its callbacks in ONE critical section, and this call closes the
    /// gate in that same critical section. After it returns, no send that had
    /// not already copied its callback can reach one.
    ///
    /// Sends authorised by a **pre-gate snapshot** are NOT waited for, and note
    /// that is broader than "already inside their callback": a sender can copy
    /// the callbacks, be descheduled, and start its send after this returns. So
    /// the guarantee is about snapshot acquisition, not invocation — several
    /// frames, TUNNEL_DATA among them, may still land. See
    /// TunnelManager::close_all_local() for the full residual and for why
    /// waiting deadlocks against `coalesce_mutex_`.
    ///
    /// This also collapses the old two-setter mute (`set_on_send_to_tox_owned`
    /// followed by `set_on_send_to_tox`) into a single atomic step, closing the
    /// window where DATA was muted but control frames were not.
    ///
    /// Gated sends report **success**, not failure: a failed send makes the
    /// tunnel refund send-window bytes and park the frame for a retry that
    /// keeps the object alive waiting to re-emit it.
    void close_outbound_gate();

    /// Install a one-shot callback fired when this tunnel can no longer put any
    /// frame on the wire naming its id — either its TUNNEL_CLOSE is already on
    /// the transport, or it is terminal and owes none.
    ///
    /// This is what an owner must wait for before letting the id be reused.
    /// `Tunnel::close()` returning is NOT that moment: it can return with the
    /// CLOSE still owed, either deferred behind a backpressured coalesce buffer
    /// or handed to a send that is still inside the transport. Releasing the id
    /// then lets a replacement take it before the old CLOSE goes out, and that
    /// CLOSE then names the replacement.
    ///
    /// If the condition already holds, the callback runs immediately on the
    /// calling thread. The destructor fires it as a backstop, so an owner can
    /// never be left waiting on a tunnel that has gone away.
    void set_on_id_releasable(std::function<void()> cb);

    /// True when this tunnel no longer owns an emission for its id, so its
    /// owner may hand that id to a new tunnel.
    ///
    /// Scoped to THIS OBJECT — see `CloseFrameState::Resolved` for why that is
    /// not the same as "no frame naming the id can appear on the wire".
    ///
    /// Test observability. Production code acts through
    /// `set_on_id_releasable()`, which is edge-triggered; this is the level.
    [[nodiscard]] bool id_releasable() const;

    /// Non-blocking result of asking whether the id is releasable.
    enum class IdReleasableProbe : std::uint8_t {
        /// Somebody holds `close_frame_mutex_`, so the answer is mid-update and
        /// cannot be read. This is itself the observation that matters: a
        /// resolver that cannot even look is a resolver that cannot act on a
        /// half-published claim.
        Blocked,
        Releasable,
        NotReleasable,
    };

    /// `id_releasable()` without waiting for the lock.
    ///
    /// Test observability. `id_releasable()` blocks, which makes it useless for
    /// proving that a claim is atomic: an observer that blocks is indistinguish-
    /// able from one that was simply descheduled, so a test built on it can pass
    /// against broken code purely by being late. Probing without blocking turns
    /// "I could not read it" into a positive observation.
    [[nodiscard]] IdReleasableProbe probe_id_releasable() const;

    /// True once `close_outbound_gate()` has run on this tunnel.
    [[nodiscard]] bool outbound_gate_closed() const noexcept {
        return outbound_gate_closed_.load(std::memory_order_acquire);
    }

    /// Error code from the last TUNNEL_ERROR this tunnel received (0 = none).
    ///
    /// WIRE CONTRACT (v0.4.12+) — three disjoint categories, so a client can
    /// act on the number alone rather than parsing the description:
    ///
    ///   1 — policy-denied open: rules denial, rate limit, concurrent-tunnel
    ///       cap. Anything the *server operator's* configuration refused.
    ///   2 — general non-policy open failure: DNS failure, any connect failure
    ///       that is not a refusal, "Tunnel ID in use", target lost before the
    ///       tunnel was established, half-close linger timeout. This is the
    ///       whole non-policy bucket, not specifically "cannot reach target";
    ///       new failure modes belong here unless they fit 1 or 3.
    ///   3 — the target actively refused the TCP connection, and nothing else.
    ///
    /// Up to v0.4.11 code 3 conflated policy denials, connect failures and
    /// teardowns, so a rate-limited open reached a SOCKS5 client as 0x04 "host
    /// unreachable". `app::tunnel_open_outcome_for()` maps these onto the
    /// RFC 1928 reply byte and carries the compatibility shim for old servers.
    [[nodiscard]] std::uint8_t last_error_code() const noexcept {
        return last_error_code_.load(std::memory_order_acquire);
    }

    /// Description carried by that last TUNNEL_ERROR ("" when none).
    [[nodiscard]] std::string last_error_description() const {
        std::lock_guard lock(last_error_mutex_);
        return last_error_description_;
    }

   private:
    // -----------------------------------------------------------------
    // Outbound send-callback snapshot — see close_outbound_gate()
    // -----------------------------------------------------------------

    /// A scoped copy of the send callbacks, taken under an open gate.
    ///
    /// Construction takes `mutex_` once and does two things atomically: test
    /// the outbound gate and copy the send callbacks. The actual Tox call then
    /// happens with NO lock held — that is the whole point (H-01 forbids
    /// re-entering the manager under a tunnel lock), and it is why the gate has
    /// to be tested in the same breath as the copy rather than re-checked
    /// afterwards.
    ///
    /// It owns nothing and is registered nowhere: nothing enumerates the
    /// outstanding ones and nothing waits on them. It was once `OutboundLease`,
    /// which kept inviting the withdrawn "in-flight / drain" reading; the gate
    /// bounds snapshot *acquisition* only, so a snapshot taken just before the
    /// gate closed may still deliver its frame. See
    /// TunnelManager::close_all_local() for that residual.
    class OutboundSnapshot {
       public:
        explicit OutboundSnapshot(TunnelImpl& tunnel);

        OutboundSnapshot(const OutboundSnapshot&) = delete;
        OutboundSnapshot& operator=(const OutboundSnapshot&) = delete;
        OutboundSnapshot(OutboundSnapshot&&) = delete;
        OutboundSnapshot& operator=(OutboundSnapshot&&) = delete;

        /// True when the gate was already closed, i.e. no snapshot was taken
        /// and the caller must discard its frame.
        [[nodiscard]] bool gate_closed() const noexcept { return gate_closed_; }

        [[nodiscard]] const SendToToxCallback& span_callback() const noexcept { return span_cb_; }
        [[nodiscard]] const SendOwnedToToxCallback& owned_callback() const noexcept {
            return owned_cb_;
        }

       private:
        bool gate_closed_{false};
        SendToToxCallback span_cb_;
        SendOwnedToToxCallback owned_cb_;
    };

    // -----------------------------------------------------------------
    // Internal frame handlers
    // -----------------------------------------------------------------

    void handle_tunnel_open_frame(const ProtocolFrame& frame);
    void handle_tunnel_data_frame(const ProtocolFrame& frame);
    void handle_tunnel_close_frame(const ProtocolFrame& frame);
    void handle_tunnel_ack_frame(const ProtocolFrame& frame);
    void handle_tunnel_error_frame(const ProtocolFrame& frame);
    void handle_ping_frame(const ProtocolFrame& frame);
    void handle_pong_frame(const ProtocolFrame& frame);

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Send a frame to the Tox peer via the callback, reporting the full
    /// transport outcome.
    ///
    /// A closed outbound gate reports `Sent`: a failure there would refund the
    /// send window and park the frame for a retry that keeps this tunnel alive
    /// waiting to re-emit it (see close_outbound_gate()).
    [[nodiscard]] SendOutcome send_frame_to_tox_typed(const ProtocolFrame& frame);

    /// Boolean view of send_frame_to_tox_typed for the paths that only need
    /// "did this reach the wire?" — the DATA emit path (which retains
    /// backpressured bytes in the coalesce buffer) and the ACK path (which
    /// retains unacked bytes and re-arms its own timer). Both already treat
    /// false as retryable backpressure, so collapsing SendqFull and
    /// PermanentFail into false loses nothing for them.
    bool send_frame_to_tox(const ProtocolFrame& frame);

    /// Outcome of one TUNNEL_OPEN send attempt, plus who owns what follows.
    struct OpenAttemptResult {
        /// nullopt when no attempt was made at all, because the OPEN had
        /// already been resolved by someone else.
        std::optional<SendOutcome> outcome;

        /// True only when this attempt is entitled to drive the tunnel's
        /// terminal state. It is false whenever a close ran while the send was
        /// in flight: that close has already published (or is publishing) a
        /// terminal state, and a second writer here would overwrite it —
        /// `Closed -> None` from the initial attempt, or `Closed -> Error`
        /// plus a duplicate `tunnels_closed` sample from a retry. Deciding
        /// this in the same critical section that records the phase is what
        /// makes the two writers mutually exclusive.
        bool owns_resolution{false};

        /// True when a close arrived while this attempt was inside the
        /// transport and the OPEN was nevertheless accepted. The caller emits
        /// the TUNNEL_CLOSE — after the OPEN, which is the whole point.
        bool close_owed{false};
    };

    /// One attempt to put this tunnel's TUNNEL_OPEN on the wire, arming the
    /// SENDQ retry timer if toxcore backpressures.
    [[nodiscard]] OpenAttemptResult attempt_open_send(unsigned attempt);

    /// Timer handler body for retry number @p attempt.
    void retry_open_send(unsigned attempt);

    /// Arm the SENDQ retry timer for retry number @p attempt.
    void arm_open_retry_timer(unsigned attempt);

    /// Who, if anyone, owes the peer a TUNNEL_CLOSE for this tunnel.
    enum class CloseObligation : std::uint8_t {
        /// The OPEN never reached toxcore and never will. The peer has no idea
        /// this id exists, so a CLOSE would name nothing — or, after the id is
        /// recycled, somebody else.
        None,
        /// The OPEN is already on the wire. The caller must emit the CLOSE.
        Immediate,
        /// A send is inside the transport RIGHT NOW, so whether the OPEN lands
        /// is not yet knowable. The caller must NOT emit: a CLOSE sent from
        /// here would reach the peer *before* the OPEN it is meant to retract,
        /// leaving the OPEN unmatched — the same failure in reverse. The
        /// sending thread emits it instead, after its transport call returns
        /// and only if the OPEN was actually accepted.
        DeferredToSender,
    };

    /// Abandon any outstanding TUNNEL_OPEN and report who owes the peer a
    /// TUNNEL_CLOSE.
    ///
    /// The answer has to be produced in the same critical section that stops
    /// the retry, otherwise a retry running concurrently on an io thread could
    /// deliver the OPEN just after close() decided not to announce a close,
    /// leaving the peer holding half a tunnel until its own reaper notices.
    [[nodiscard]] CloseObligation cancel_open_retry();

    /// `cancel_open_retry()`'s body. Caller must already hold
    /// `close_frame_mutex_`; this acquires `open_retry_mutex_` under it.
    ///
    /// LOCK ORDER, project-wide: `close_frame_mutex_` is acquired BEFORE
    /// `open_retry_mutex_`, never after. That order exists so the terminal
    /// state claim and the CLOSE obligation can be published together — see
    /// claim_terminal().
    [[nodiscard]] CloseObligation cancel_open_retry_locked();

    /// `note_close_owed()`'s body. Caller must hold `close_frame_mutex_`.
    void note_close_owed_locked();

    /// `id_releasable()`'s body. Caller must hold `close_frame_mutex_`, which is
    /// also where `state_` is read — the two have to be sampled together or the
    /// terminal-but-not-yet-owed instant becomes observable.
    [[nodiscard]] bool id_releasable_locked() const;

    /// Outcome of claiming a tunnel's terminal state.
    struct TerminalClaim {
        bool claimed{false};          ///< This call won the transition to Closed.
        State previous{State::None};  ///< What the state was before it.
        bool must_announce{false};    ///< This caller owes the peer a TUNNEL_CLOSE.
    };

    /// Claim `Closed` AND decide-and-publish the CLOSE obligation as ONE step.
    ///
    /// These were two steps — a compare-exchange on `state_`, then
    /// `note_close_owed()` — living in different synchronization domains, and
    /// the gap between them was observable as exactly the state that means "the
    /// id is free":
    ///
    ///   1. thread A wins Connected -> Closed, and is preempted;
    ///   2. a resolver (another force_close, or the manager's id-releasable hook
    ///      during removal) observes terminal + CloseFrameState::NotOwed;
    ///   3. it releases the id, which is then recycled;
    ///   4. A resumes, records Owed, and emits its CLOSE against the new tunnel.
    ///
    /// Reordering the resource latch does not help: A can be preempted the
    /// instruction after the CAS, before recording anything at all. The fix is
    /// that both writes happen under `close_frame_mutex_` — the same lock every
    /// releasability decision takes, and which `maybe_notify_id_releasable()`
    /// also reads `state_` under. A resolver therefore either takes the lock
    /// before this and sees a non-terminal state, or after it and sees `Owed`.
    /// There is no third observation.
    [[nodiscard]] TerminalClaim claim_terminal();

   public:
    /// Test seam: run @p hook inside `claim_terminal()`, immediately after the
    /// terminal compare-exchange and while `close_frame_mutex_` is still held.
    ///
    /// It exists because the atomicity of that pair is otherwise unobservable —
    /// which is the point of the fix, but also makes it untestable without a way
    /// to hold the claimant still. Pausing here widens SCHEDULING, not the
    /// atomicity boundary: a concurrent `id_releasable()` observer blocks on the
    /// mutex for the duration and so still cannot sample the intermediate. Move
    /// the claim back outside the lock and the same hook lets the observer sample
    /// it immediately, which is what makes the test discriminate.
    ///
    /// Null in production; no call site sets it outside tests.
    void set_terminal_claim_test_hook(std::function<void()> hook);

   private:
    /// Put this tunnel's one and only TUNNEL_CLOSE on the wire.
    ///
    /// Single-shot across every path that can emit one — the graceful close,
    /// the TCP half-close, the handshake close and force_close() — because
    /// those paths can race each other and a second CLOSE names an id that may
    /// by then belong to a different tunnel.
    ///
    /// @return true if this call OWNS the emission — it built the frame and
    ///         handed it to the transport, or retained it for retry. False
    ///         means somebody else already owns it. The close is booked on a
    ///         true return, not on delivery, which matches every other close
    ///         path (they all book before knowing the transport's answer).
    bool emit_close_frame_once();

    /// Re-attempt a TUNNEL_CLOSE that toxcore refused with SENDQ-full.
    ///
    /// Same cadence as the OPEN retry (sendq_retry.hpp) and for the same reason:
    /// the coalesce delay is legally 0 and would spin.
    ///
    /// NOT ON THE PRODUCTION CLOSE PATH YET. `route_sendq_full()` excludes
    /// TUNNEL_CLOSE from driver-owned retry: production senders park a
    /// backpressured CLOSE in `TunnelManager`'s queue and report `Sent`, so this
    /// timer never arms for them today. What is being put in place here is the
    /// CONTRACT — retain and retry, never drop — for the later slice that moves
    /// CLOSE off the manager queue. It is live now only for a callback that
    /// returns `SendqFull` for a CLOSE, which is legal and which the seam must
    /// therefore handle.
    ///
    /// OWNERSHIP: the handler holds a STRONG self-reference, so the retry owner
    /// keeps itself alive until the frame is sent, permanently fails, or is
    /// abandoned. A weak capture was memory-safe but not semantically safe:
    /// removal drops the manager's reference first, and the resulting
    /// destruction cancelled the timer and abandoned the obligation, so a
    /// backpressured CLOSE was silently dropped instead of retried — the very
    /// thing retention+retry replaced manager-parking to avoid. The self-
    /// reference is released as soon as the state leaves `Owed`.
    void arm_close_retry_timer(unsigned attempt);

   public:
    /// Stop retrying a backpressured TUNNEL_CLOSE and give the obligation up.
    ///
    /// The explicit shutdown path for the strong self-reference above, so a
    /// retry cannot outlive session teardown. Called when the outbound gate
    /// closes — at that point every send is a no-op anyway, so retrying could
    /// only spin. (Process teardown is covered separately: destroying the
    /// io_context destroys pending handlers, which releases the self-reference.)
    void cancel_close_retry();

   private:
    /// Record that a TUNNEL_CLOSE is owed but has not been handed to the
    /// transport yet — a graceful close deferred behind a backpressured
    /// coalesce buffer, a `DeferredToSender` handshake close, or a
    /// force_close() that has claimed the state and is about to announce.
    void note_close_owed();

    /// Give up an owed TUNNEL_CLOSE because it turned out not to be owed (the
    /// OPEN it would have retracted never reached the peer).
    void abandon_close_obligation();

    /// Fire `on_id_releasable_` if this tunnel can no longer put any frame on
    /// the wire naming its id. Idempotent; the callback runs at most once.
    void maybe_notify_id_releasable();

    /// Send a fully-framed TUNNEL_DATA OwnedFrameBuffer to the Tox peer via
    /// the zero-copy callback if it is set; otherwise fall back to the
    /// span-based callback. Same accept/drop return semantics as
    /// `send_frame_to_tox`.
    bool send_owned_data_to_tox(OwnedFrameBuffer buf);

    /// One entry of the outbound cohort FIFO: bytes admitted under one frame
    /// cap. Caps cannot be merged (a merged cap breaks either the buffered or
    /// the bypass framing contract — see the design doc), so adjacent appends
    /// coalesce only when their caps are equal, and a cohort keeps its cap
    /// across backpressure and retry. Consumed via a front cursor with lazy
    /// compaction so draining stays amortized O(n).
    struct OutboundCohort {
        std::size_t cap;
        std::vector<std::uint8_t> bytes;
        std::size_t consumed{0};
        [[nodiscard]] std::size_t pending() const noexcept { return bytes.size() - consumed; }
    };

    /// Append `data` to the outbound FIFO under frame cap `cap`, merging into
    /// the back cohort only when its cap matches. The caller must hold
    /// `coalesce_mutex_`. Never emits — emission belongs to the driver.
    void fifo_append_locked(std::span<const uint8_t> data, std::size_t cap);

    /// Publish the terminal `Abort` intent (slice 3 of the outbound-send
    /// driver design, issue #24): seal ordinary DATA admission and abandon
    /// everything undelivered — the cohort FIFO and any deferred-close
    /// bookkeeping riding on its drain. The caller must hold
    /// `coalesce_mutex_`, which is what makes the seal atomic with the
    /// abandonment: an admission racing this either lands before (and is
    /// abandoned) or re-checks the seal after and is refused.
    ///
    /// In the design's `LocalTerminalIntent` ladder (None < LocalEof <
    /// GracefulClose < Abort) only `Abort` is materialized so far — the two
    /// graceful levels still live in the flags that predate the ladder
    /// (`pending_tcp_eof_` / `close_pending_`), because enforcing them on
    /// ordinary admission requires the slice-4 privileged capability that
    /// drains the sealed pending-TCP backlog. No graceful operation may ever
    /// route through here: Abort abandons bytes, and `close()` / TCP EOF owe
    /// theirs to the peer.
    void publish_abort_locked();

    /// THE single outbound emission driver for TUNNEL_DATA (slice 2 of the
    /// outbound-send-driver design, issue #24). At most one thread drains at a
    /// time; every send callback runs with NO lock held (frame selection and
    /// consumption-commit each take `coalesce_mutex_` briefly, the send happens
    /// between them). A caller that finds the driver busy has its request
    /// queued behind the active emitter — a FlushAll intent is latched so the
    /// active emitter honours it — and gets `DeferredToActiveEmitter`, which
    /// must never be treated as drained.
    ///
    /// On toxcore backpressure the in-flight bytes are RETAINED at the front of
    /// their cohort (the send window stays charged, so upstream TCP reads
    /// pause) and the retry timer is armed. Dropping them would silently
    /// truncate the stream.
    ///
    /// When the driver empties the FIFO it also performs the deferred-close
    /// bookkeeping (`close_pending_` / `remote_close_pending_`) that used to
    /// live in the flush-timer handler, so a deferred CLOSE is emitted by
    /// whichever emitter actually finishes the drain.
    ///
    /// `arm_timer_on_remainder` is false only for the `Drain` coalesce policy,
    /// whose sub-cap remainder waits for overflow or an explicit flush rather
    /// than the timer.
    [[nodiscard]] EmitOutcome run_emission_driver(DrainPolicy policy,
                                                  bool arm_timer_on_remainder = true);

    /// Send TUNNEL_CLOSE and move to Disconnecting. Must be called WITHOUT
    /// `coalesce_mutex_` held (it sends through the Tox callback).
    void emit_close_and_transition();

    /// Send local TUNNEL_CLOSE without notifying final tunnel closure. Used by
    /// TCP half-close: the peer may still send data until its own close.
    void emit_local_close_only();

    /// Flush TCP bytes already read locally but still buffered behind the
    /// tunnel send window. Returns true when the backlog is now empty.
    bool flush_pending_tcp_input();

    /// Local TCP EOF can arrive while `pending_tcp_input_` still holds bytes
    /// waiting for an ACK-driven retry. Finish the half-close once they drain.
    void maybe_finish_pending_tcp_eof();

    /// Complete a peer-initiated close after any outbound buffered DATA has
    /// drained. Must be called WITHOUT `coalesce_mutex_` held.
    void finalize_remote_close();

    /// (Re)arm the flush timer if the buffer is non-empty and no timer is
    /// pending. The caller must hold `coalesce_mutex_`.
    void coalesce_arm_timer_locked();

    /// Bytes still pending in the outbound cohort FIFO. The caller must hold
    /// `coalesce_mutex_`.
    [[nodiscard]] std::size_t coalesce_pending_locked() const noexcept {
        return outbound_fifo_pending_;
    }

    /// Live bytes still queued in `pending_tcp_input_` (total minus the
    /// already-sent prefix). The caller must hold `tcp_backpressure_mutex_`.
    [[nodiscard]] std::size_t pending_tcp_pending_locked() const noexcept {
        return pending_tcp_input_.size() - pending_tcp_consumed_;
    }

    /// Bump the last-activity timestamp to "now". Called only on TUNNEL_DATA
    /// in either direction; keep-alive and control frames do NOT bump.
    void BumpActivity() noexcept;

    /// Transition to a new state and invoke callback.
    void transition_state(State new_state);

    /// Transition only if the tunnel is still in @p expected, and report
    /// whether this call was the one that did it.
    ///
    /// The unconditional `transition_state()` is a blind store, which is fine
    /// where exactly one writer can reach a given edge. The open handshake is
    /// not such a place: `open()`, `retry_open_send()`, `close()` and
    /// `force_close()` can all be racing for the same tunnel, and the loser
    /// publishing its state on top of the winner's is a real corruption
    /// (`Closed -> None` strands a tunnel the manager has already released,
    /// `Closed -> Error` double-counts the closure). `open_retry_mutex_` alone
    /// cannot fix that: the callback fired from inside a transition forbids
    /// holding a lock across it (H-01), so the claim and the transition would
    /// sit in different critical sections. The compare-exchange here IS the
    /// claim — whoever wins it owns the terminal bookkeeping that follows.
    [[nodiscard]] bool transition_state_if(State expected, State desired);

    /// Snapshot the state-change callback under `mutex_` and invoke it with the
    /// lock released (H-01). Shared by every transition path, including
    /// `open()`, which publishes its own None -> Connecting edge so the claim
    /// and the target write can be one critical section.
    void notify_state_change(State new_state);

    /// Check if ACK should be sent and send it.
    void maybe_send_ack();

    /// Send ACK frame for received bytes. Returns true if all accumulated
    /// bytes were acked (nothing left pending), false if a send backpressured
    /// and some remain in `bytes_received_since_ack_` for a later retry.
    bool send_ack();

    /// Retry a deferred ACK after the Tox lossless send queue has had a chance
    /// to drain. Used when notify_tcp_writable() cannot flush the ACK itself.
    void arm_ack_retry_timer();

    /// Invoke the close callback at most once for terminal states (Closed/Error).
    void notify_close_once();

    // -----------------------------------------------------------------
    // TUNNEL_OPEN ownership
    // -----------------------------------------------------------------

    /// Where this tunnel's TUNNEL_OPEN is on its journey to the peer.
    ///
    /// A plain `bool open_sent_` cannot express the one case that actually
    /// races: a retry that is *inside* its send call when close() runs. The
    /// send has not returned, so "sent" is not yet knowable, and both answers
    /// are wrong for one of the two outcomes. `Sending` makes that ambiguity
    /// explicit so cancel_open_retry() can resolve it deliberately (it assumes
    /// the OPEN landed) instead of by accident.
    enum class OpenPhase : std::uint8_t {
        Pending,    ///< Not accepted yet; a retry is armed, or about to be.
        Sending,    ///< A send attempt is in flight on some thread right now.
        Sent,       ///< toxcore accepted it — the peer knows this tunnel id.
        Abandoned,  ///< Resolved locally before the peer ever heard of it.
        Failed,     ///< The transport rejected it permanently.
    };

    /// Guards the OPEN phase and every access to `open_retry_timer_`. Never
    /// held across a send callback (H-01) — attempt_open_send() takes it, marks
    /// `Sending`, drops it, sends, and retakes it to record the verdict.
    mutable std::mutex open_retry_mutex_;
    OpenPhase open_phase_{OpenPhase::Pending};
    /// Set by cancel_open_retry(); stops a re-arm decided by a send that was
    /// already in flight when the tunnel was abandoned.
    bool open_abandon_requested_{false};
    bool open_retry_armed_{false};
    std::uint64_t open_retry_epoch_{0};
    /// Dedicated timer with a dedicated cadence — see sendq_retry.hpp for why
    /// this is not the coalesce timer's delay.
    asio::steady_timer open_retry_timer_;
    /// Total TUNNEL_OPEN send attempts (initial + retries); test observability.
    std::atomic<unsigned> open_attempts_{0};
    /// Set when a close landed while a TUNNEL_OPEN send was in flight. The
    /// sending thread consumes it once the transport has answered, so the
    /// CLOSE is emitted after the OPEN it retracts, and only if that OPEN was
    /// accepted. Guarded by `open_retry_mutex_`.
    bool open_close_owed_{false};

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// Friend number.
    uint32_t friend_number_;

    /// Current state.
    std::atomic<State> state_{State::None};

    /// Set when a maintenance timer (idle reaper / half-close cap) is closing
    /// this tunnel, so the close is booked as CloseReason::Timeout.
    std::atomic<bool> timeout_close_{false};

    /// Last TUNNEL_ERROR seen, exposed via last_error_code() /
    /// last_error_description() so callers (SOCKS5) can tell a rules denial
    /// apart from an unreachable target.
    std::atomic<std::uint8_t> last_error_code_{0};
    mutable std::mutex last_error_mutex_;
    std::string last_error_description_;

    /// Target hostname (set during open).
    std::string target_host_;

    /// Target port (set during open).
    std::uint16_t target_port_{0};

    /// TCP connection (may be null).
    std::shared_ptr<core::TcpConnection> tcp_conn_;

    /// Send window size.
    std::size_t send_window_size_;

    /// Bytes currently in the send window.
    std::atomic<std::size_t> send_window_used_{0};

    /// ACK threshold.
    std::size_t ack_threshold_ = kDefaultAckThreshold;

    /// Bytes received since last ACK.
    std::atomic<std::size_t> bytes_received_since_ack_{0};

    /// Total bytes received.
    std::atomic<std::size_t> total_bytes_received_{0};

    /// Total bytes sent (accepted from local TCP, charged to the send window).
    std::atomic<std::size_t> total_bytes_sent_{0};

    /// Lossless flow accounting. Lock-free by design: the ACK handler must
    /// never need coalesce_mutex_, so a synchronous ACK round-trip
    /// re-entering from inside the emission driver's send callback works with
    /// no lock (see handle_tunnel_ack_frame). The emitter itself MAY touch
    /// these while holding coalesce_mutex_ (the driver's rollback does) —
    /// the atomics carry the correctness, not the mutex.
    ///  - total_bytes_emitted_: payload bytes actually handed to toxcore.
    ///    Stored with release at the emit sites.
    ///  - total_bytes_acked_: cumulative peer-acked bytes, CLAMPED so it can
    ///    never exceed total_bytes_emitted_ (a peer cannot ACK-credit the send
    ///    window for bytes we never put on the wire — forged-ACK OOM defense).
    /// The ACK handler does an acquire-load of emitted; causality (we
    /// store-release BEFORE sending, the peer can only ACK what it received
    /// AFTER we sent) guarantees that load sees emitted >= the acked bytes, so
    /// a legitimate ACK is never under-credited.
    std::atomic<std::uint64_t> total_bytes_emitted_{0};
    std::atomic<std::uint64_t> total_bytes_acked_{0};

    /// Last activity timestamp as nanoseconds since steady_clock epoch.
    /// Atomic so the reaper thread can sample without taking the tunnel mutex.
    std::atomic<int64_t> last_activity_ns_;

    // ---- Write coalescing state ------------------------------------------
    // Separate mutex from `mutex_` so a flush that crosses to the Tox thread
    // never races with state/callback edits (which also call into us).
    mutable std::mutex coalesce_mutex_;
    // Outbound cohort FIFO (slice 2, issue #24). Each cohort carries the frame
    // cap it was admitted under; only the emission driver consumes, always from
    // the front. `outbound_fifo_pending_` caches the summed pending bytes so
    // coalesce_pending_locked() stays O(1).
    std::deque<OutboundCohort> outbound_fifo_;
    std::size_t outbound_fifo_pending_{0};
    // True while one thread is the emission driver. Guarded by
    // `coalesce_mutex_`; every exit decision (drain complete, sub-cap stop,
    // backpressure) happens in the same critical section that clears it, and
    // every append happens under the same mutex, so a wakeup can never be lost
    // between "driver saw an empty FIFO" and "a producer appended".
    bool driver_active_{false};
    // A FlushAll request arrived (possibly from a deferred caller) and has not
    // yet been honoured by a complete drain. Re-read by the active driver on
    // every iteration; cleared when the FIFO empties or the drain backpressures
    // (the retry timer flushes everything anyway).
    bool driver_flush_all_requested_{false};
    // The terminal `Abort` seal (see publish_abort_locked). One-way. Always
    // STORED under `coalesce_mutex_` so the seal and the FIFO abandonment are
    // one atomic step; exposed as an atomic only so admission can fast-reject
    // without the lock (the authoritative re-check happens under the lock
    // before any append).
    std::atomic<bool> outbound_abort_published_{false};
    // The single terminal TUNNEL_ERROR has been claimed (send_error). Always
    // STORED under `coalesce_mutex_`, in the same critical section as the
    // Abort seal; whoever flips it owes the frame and the state / close
    // notifications, and every later send_error() is a suppressed duplicate.
    // Atomic because emit_close_frame_once() reads it under
    // `close_frame_mutex_` as the ERROR->CLOSE fence: once the terminal ERROR
    // is claimed, NO tunnel CLOSE may be newly authorized — not even an Owed
    // one — or it would follow the ERROR onto the wire. Deliberately narrower
    // than `outbound_abort_published_`: a force_close teardown (Abort without
    // an ERROR) must still allow the handed-off CLOSE that an in-flight OPEN's
    // sender owes the peer.
    std::atomic<bool> terminal_error_claimed_{false};
    // Releasability fence for the terminal ERROR's own transport attempt. Set
    // by send_error() before it invokes the transport, cleared after the
    // attempt and the terminal transition settle. While set,
    // id_releasable_locked() answers no: the ERROR frame is (or may be)
    // inside the transport naming this id, and the Abandoned verdict a
    // concurrently-fenced CLOSE records must not release the id out from
    // under it — a recycled id would make the in-flight ERROR name the
    // replacement. The wakeup that matters fires from send_error() itself
    // (cancel_close_retry -> maybe_notify) after the fence clears.
    std::atomic<bool> terminal_error_in_flight_{false};
    asio::steady_timer coalesce_timer_;
    // Receiver-side ACK retry state. This is intentionally separate from the
    // DATA coalescing timer: an inbound TCP drain can need to retry only ACKs
    // while the outbound DATA coalesce buffer is empty.
    asio::steady_timer ack_retry_timer_;
    mutable std::mutex ack_retry_mutex_;
    bool ack_retry_timer_armed_{false};
    std::uint64_t ack_retry_timer_epoch_{0};
    std::uint32_t coalesce_max_delay_us_{kDefaultCoalesceMaxDelayUs};
    std::uint32_t coalesce_max_bytes_{kDefaultCoalesceMaxBytes};
    bool coalesce_timer_armed_{false};
    std::uint64_t coalesce_timer_epoch_{0};
    // A local close() arrived while the coalesce buffer was backpressured.
    // TUNNEL_CLOSE is deferred until the retry timer fully drains the buffer,
    // otherwise the CLOSE would overtake the still-buffered DATA and the peer
    // would drop the trailing bytes as frames for an "unknown tunnel".
    bool close_pending_{false};
    // True when the pending local close was a full close() request rather than
    // a TCP half-close. Full close preserves the historical behavior of firing
    // on_close_ as soon as local buffered DATA drains and CLOSE is emitted.
    bool close_pending_full_{false};
    // Local TUNNEL_CLOSE has been emitted.
    bool local_close_sent_{false};
    // The local->remote direction is finished from this endpoint's
    // perspective. This is normally set with local_close_sent_, and also set
    // for test/manager-only tunnels that do not own a local TcpConnection.
    bool local_stream_done_{false};
    // Peer TUNNEL_CLOSE has been received.
    bool remote_close_received_{false};
    // A peer TUNNEL_CLOSE arrived while our outbound coalesce buffer still held
    // DATA accepted from local TCP. Keep the tunnel alive until those bytes are
    // handed to Tox; otherwise full-duplex streams such as SSH stdout truncate
    // when the peer closes first.
    bool remote_close_pending_{false};
    // Bytes already read from the local TCP socket but not yet admitted into
    // the tunnel send window. Retried when ACKs reopen space. Consumed via the
    // `pending_tcp_consumed_` read cursor and compacted lazily (see
    // flush_pending_tcp_input) so draining a large backlog stays O(n), not the
    // O(n^2) that erase-from-front per chunk produced.
    std::vector<std::uint8_t> pending_tcp_input_;
    std::size_t pending_tcp_consumed_{0};
    // Local TCP EOF arrived while `pending_tcp_input_` was non-empty; defer the
    // directional TUNNEL_CLOSE until those bytes flush.
    bool pending_tcp_eof_{false};
    mutable std::mutex tcp_backpressure_mutex_;

    // Adaptive coalescer + BDP flow control. Updated on the data path.
    WriteCoalescer coalescer_;
    BdpFlowControl flow_control_;
    /// Set to true once `configure_flow_control` has been called. When false
    /// the legacy `send_window_size_` (constructor argument) drives admission
    /// control byte-for-byte, preserving v0.3.0 semantics for tests and
    /// existing call sites that never opt in.
    std::atomic<bool> flow_control_configured_{false};
    std::atomic<std::int64_t> last_push_ns_{0};

    /// BDP sampling state.
    /// `burst_start_ns_`: steady_clock ns when send_window_used_ went 0->positive
    ///   (we use this to time the round-trip from first byte sent → first ACK
    ///   that brings the window back to zero). Stored as 0 when no burst is
    ///   in-flight.
    /// `last_ack_ns_`: steady_clock ns of the previous TUNNEL_ACK arrival,
    ///   used to compute instantaneous bandwidth = bytes_acked / delta_t.
    std::atomic<std::int64_t> burst_start_ns_{0};
    std::atomic<std::int64_t> last_ack_ns_{0};

    /// Protects non-atomic members.
    mutable std::mutex mutex_;

    // ---- Outbound fence (see close_outbound_gate) -------------------------
    /// One-way latch. Always *stored* under `mutex_` so the "gate closed?" test
    /// and the copy of the callbacks below are one atomic step (`OutboundSnapshot`);
    /// exposed as an atomic only so `outbound_gate_closed()` can be a lock-free
    /// accessor. Nothing is registered anywhere — the latch bounds which senders
    /// can still obtain a callback, not which sends are still running.
    std::atomic<bool> outbound_gate_closed_{false};
    // Callbacks (accessed under mutex)
    SendToToxCallback on_send_to_tox_;
    SendOwnedToToxCallback on_send_to_tox_owned_;
    SendToTcpCallback on_data_for_tcp_;
    SendToTcpOwnedCallback on_data_for_tcp_owned_;
    StateChangedCallback on_state_change_;
    ErrorCallback on_error_;
    CloseCallback on_close_;
    std::atomic<bool> close_notified_{false};
    /// Where this tunnel's single outbound TUNNEL_CLOSE is in its life.
    ///
    /// This replaced a counter, which could not be made correct: an owner had
    /// to decide it owed a CLOSE under one lock and then increment outside it,
    /// so a sender that emitted in between cleared the count and the late
    /// increment stranded the id forever — while force_close(), which owed one
    /// and never incremented, stranded nothing and recycled the id too early.
    /// Over- and under-counting on different paths, from the same split.
    ///
    /// A state machine has no such split, because there is only ever ONE CLOSE:
    /// any emission discharges whatever owed-ness existed, so owners never have
    /// to balance anything. Every transition happens under `close_frame_mutex_`,
    /// which makes the whole protocol linearizable.
    ///
    ///   NotOwed --note_close_owed()--> Owed
    ///   NotOwed --note_close_owed() after cancel_close_retry()--> Abandoned
    ///   {NotOwed, Owed} --emit claims--> InFlight --transport returns--> Resolved
    ///   Owed --abandon, or cancel_close_retry()--> Abandoned
    ///   InFlight --cancel_close_retry() fences the verdict--> Resolved | Abandoned
    ///
    /// The cancellation edges exist because `cancel_close_retry()` permanently
    /// fences emission: after it, publishing `Owed` would create a debt nothing
    /// could ever pay, and the id would stay pinned for the object's lifetime.
    ///
    /// The id may be reused only from `Resolved` (this object owes none), or
    /// from `NotOwed`/`Abandoned` once the tunnel is terminal (nothing will ever
    /// emit one). `Owed` and `InFlight` both pin the id — `InFlight` is the
    /// window where the frame is inside the transport callback, which a latch
    /// published before that call could not distinguish from "already handed
    /// over".
    enum class CloseFrameState : std::uint8_t {
        NotOwed,
        Owed,
        InFlight,
        /// `TunnelImpl` no longer owns an emission for this tunnel.
        ///
        /// Reached when the transport accepted the frame, rejected it
        /// permanently, or the serialization threw. Those differ in what the
        /// PEER knows — only the first tells it the tunnel is over — but not in
        /// the question this state answers, which is whether THIS OBJECT will
        /// put another CLOSE on the wire. It will not, in all three cases.
        ///
        /// Deliberately NOT "no frame naming this id can appear on the wire":
        /// that would be false. `route_sendq_full()` parks CLOSE in
        /// `TunnelManager`'s retry queue and reports `Sent`, so a manager-owned
        /// copy can still surface after this tunnel is done with it. That is the
        /// documented residual of leaving CLOSE on the manager queue.
        ///
        /// It is NOT bounded by `remove_tunnel_if()`'s id-release rule — reaching
        /// this state immediately permits that rule to release the id, so it
        /// cannot be what bounds it. What bounds it is the outbound FIFO barrier
        /// (`TunnelManager::outbound_queue_busy()`), which holds a new OPEN or
        /// OPEN_ACK for a recycled id behind any frame still parked or mid-drain.
        Resolved,
        Abandoned,
    };
    mutable std::mutex close_frame_mutex_;
    CloseFrameState close_frame_state_{CloseFrameState::NotOwed};
    /// SENDQ retry for a backpressured TUNNEL_CLOSE. Guarded by
    /// `close_frame_mutex_`, like every other close-frame decision.
    asio::steady_timer close_retry_timer_;
    bool close_retry_armed_{false};
    std::uint64_t close_retry_epoch_{0};
    /// Backoff step for the CLOSE retry; advances so the delay actually grows.
    unsigned close_retry_attempt_{0};
    /// See set_terminal_claim_test_hook(). Guarded by `close_frame_mutex_`.
    std::function<void()> terminal_claim_test_hook_;
    /// Latched by `cancel_close_retry()`. Fences an attempt that is already
    /// `InFlight`: cancellation could only reach `Owed`, so a transport call
    /// already inside the callback would come back `SendqFull`, restore `Owed`
    /// and arm a NEW strong-self timer *after* teardown had cancelled — exactly
    /// what the shutdown contract promises cannot happen. Guarded by
    /// `close_frame_mutex_`.
    bool close_retry_cancelled_{false};
    /// One-shot "this id can be reused" callback; see set_on_id_releasable().
    /// Both guarded by `mutex_`. The latch is consumed only when there is a
    /// callback to run: the releasable condition is usually reached BEFORE the
    /// owner installs its hook (the teardown that installs it is the same one
    /// that emits the CLOSE), and an eagerly-consumed latch would swallow the
    /// only notification the owner ever gets — leaving the id reserved forever.
    std::function<void()> on_id_releasable_;
    bool id_releasable_notified_{false};
    /// One-shot latch for force_close()'s resource release, so an already
    /// terminal tunnel still gets its socket closed exactly once.
    std::atomic<bool> resources_released_{false};
};

}  // namespace toxtunnel::tunnel
