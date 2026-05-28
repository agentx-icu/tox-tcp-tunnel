#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>

#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/bdp_flow_control.hpp"
#include "toxtunnel/tunnel/owned_frame_buffer.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/write_coalescer.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tunnel {

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
    /// Returns true if the underlying Tox send accepted the bytes,
    /// false if the send was dropped (toxcore queue full, friend
    /// offline, etc.). The caller uses the return value to refund the
    /// per-tunnel send-window accounting; without it a transient drop
    /// would leak window bytes forever (S27 in the 2026-05-20 follow-up).
    using SendToToxCallback = std::function<bool(std::span<const uint8_t> data)>;

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
    /// Same drop/refund contract as `SendToToxCallback`: true = sent,
    /// false = dropped so the tunnel can refund its window.
    using SendOwnedToToxCallback = std::function<bool(OwnedFrameBuffer buf)>;

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
    /// @param host  Target hostname or IP address.
    /// @param port  Target TCP port.
    /// @return      True if the open was initiated, false if wrong state.
    [[nodiscard]] bool open(const std::string& host, uint16_t port);

    /// Immediately close the tunnel without graceful shutdown.
    void force_close();

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

    /// Send an error frame and transition to Error state.
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

    /// Return the number of bytes sent.
    [[nodiscard]] std::size_t bytes_sent() const noexcept {
        return total_bytes_sent_.load(std::memory_order_relaxed);
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

   private:
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

    /// Send a frame to the Tox peer via the callback. Returns the
    /// underlying ToxAdapter accept/drop result; callers that need to
    /// refund send-window accounting on drop should propagate it.
    bool send_frame_to_tox(const ProtocolFrame& frame);

    /// Send a fully-framed TUNNEL_DATA OwnedFrameBuffer to the Tox peer via
    /// the zero-copy callback if it is set; otherwise fall back to the
    /// span-based callback. Same accept/drop return semantics as
    /// `send_frame_to_tox`.
    bool send_owned_data_to_tox(OwnedFrameBuffer buf);

    /// Append `data` to the coalesce buffer, draining full-MTU frames as it
    /// fills. The caller must hold `coalesce_mutex_`.
    void coalesce_append_locked(std::span<const uint8_t> data);

    /// Emit a single TUNNEL_DATA frame carrying the front of the coalesce
    /// buffer (up to `coalesce_max_bytes_` bytes). The caller must hold
    /// `coalesce_mutex_`. Returns true if the frame was handed to Tox (and the
    /// bytes erased from the buffer); returns false if Tox backpressured
    /// (toxcore lossless SENDQ full) — in that case the bytes are RETAINED for
    /// a later retry and the send window is NOT refunded. Dropping them would
    /// silently truncate the tunnel (a lossless stream must never lose bytes to
    /// transient transport backpressure).
    [[nodiscard]] bool coalesce_emit_front_locked(std::size_t bytes);

    /// Drain the coalesce buffer in <= MTU frames (full frames then the
    /// remainder). Stops at the first backpressured emit. Returns true iff the
    /// buffer is now empty. The caller must hold `coalesce_mutex_`.
    [[nodiscard]] bool coalesce_try_drain_locked();

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

    /// Bytes still pending in the coalesce buffer (total minus the already-
    /// emitted prefix). The caller must hold `coalesce_mutex_`.
    [[nodiscard]] std::size_t coalesce_pending_locked() const noexcept {
        return coalesce_buf_.size() - coalesce_consumed_;
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
    // Data members
    // -----------------------------------------------------------------

    /// Friend number.
    uint32_t friend_number_;

    /// Current state.
    std::atomic<State> state_{State::None};

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

    /// Total bytes sent.
    std::atomic<std::size_t> total_bytes_sent_{0};

    /// Last activity timestamp as nanoseconds since steady_clock epoch.
    /// Atomic so the reaper thread can sample without taking the tunnel mutex.
    std::atomic<int64_t> last_activity_ns_;

    // ---- Write coalescing state ------------------------------------------
    // Separate mutex from `mutex_` so a flush that crosses to the Tox thread
    // never races with state/callback edits (which also call into us).
    mutable std::mutex coalesce_mutex_;
    std::vector<std::uint8_t> coalesce_buf_;
    // Bytes already emitted from the front of coalesce_buf_ but not yet erased.
    // Consuming via this offset (instead of erase-from-front on every frame)
    // keeps draining a large backpressured buffer O(n) instead of O(n^2). The
    // prefix is reclaimed lazily: reset to 0 when the buffer fully drains, and
    // compacted in coalesce_append_locked once the consumed prefix dominates.
    std::size_t coalesce_consumed_{0};
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

    // Callbacks (accessed under mutex)
    SendToToxCallback on_send_to_tox_;
    SendOwnedToToxCallback on_send_to_tox_owned_;
    SendToTcpCallback on_data_for_tcp_;
    SendToTcpOwnedCallback on_data_for_tcp_owned_;
    StateChangedCallback on_state_change_;
    ErrorCallback on_error_;
    CloseCallback on_close_;
    std::atomic<bool> close_notified_{false};
};

}  // namespace toxtunnel::tunnel
