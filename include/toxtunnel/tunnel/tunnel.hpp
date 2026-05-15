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
#include "toxtunnel/tunnel/protocol.hpp"
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
class Tunnel {
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
    using SendToToxCallback = std::function<void(std::span<const uint8_t> data)>;

    /// Called when data should be written to the TCP connection.
    using SendToTcpCallback = std::function<void(std::span<const uint8_t> data)>;

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

    /// Flush any buffered coalesced bytes immediately as one frame.
    /// Used by close() / force_close() and exposed for tests.
    void flush_pending_writes();

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

    /// Set callback for sending data to TCP.
    void set_on_data_for_tcp(SendToTcpCallback cb);

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

    /// Send a frame to the Tox peer via the callback.
    void send_frame_to_tox(const ProtocolFrame& frame);

    /// Append `data` to the coalesce buffer, draining full-MTU frames as it
    /// fills. The caller must hold `coalesce_mutex_`.
    void coalesce_append_locked(std::span<const uint8_t> data);

    /// Emit a single TUNNEL_DATA frame carrying the front of the coalesce
    /// buffer (up to `coalesce_max_bytes_` bytes). The caller must hold
    /// `coalesce_mutex_`.
    void coalesce_emit_front_locked(std::size_t bytes);

    /// (Re)arm the flush timer if the buffer is non-empty and no timer is
    /// pending. The caller must hold `coalesce_mutex_`.
    void coalesce_arm_timer_locked();

    /// Bump the last-activity timestamp to "now". Called only on TUNNEL_DATA
    /// in either direction; keep-alive and control frames do NOT bump.
    void BumpActivity() noexcept;

    /// Transition to a new state and invoke callback.
    void transition_state(State new_state);

    /// Check if ACK should be sent and send it.
    void maybe_send_ack();

    /// Send ACK frame for received bytes.
    void send_ack();

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
    asio::steady_timer coalesce_timer_;
    std::uint32_t coalesce_max_delay_us_{kDefaultCoalesceMaxDelayUs};
    std::uint32_t coalesce_max_bytes_{kDefaultCoalesceMaxBytes};
    bool coalesce_timer_armed_{false};
    std::uint64_t coalesce_timer_epoch_{0};

    /// Protects non-atomic members.
    mutable std::mutex mutex_;

    // Callbacks (accessed under mutex)
    SendToToxCallback on_send_to_tox_;
    SendToTcpCallback on_data_for_tcp_;
    StateChangedCallback on_state_change_;
    ErrorCallback on_error_;
    CloseCallback on_close_;
};

}  // namespace toxtunnel::tunnel
