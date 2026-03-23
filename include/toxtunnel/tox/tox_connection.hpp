#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <vector>

namespace toxtunnel::tox {

/// Represents a Tox friend connection for tunneling data.
///
/// ToxConnection manages per-friend state including connection lifecycle,
/// send/receive byte buffers with flow control, and backpressure signalling.
/// It is the Tox-side counterpart of core::TcpConnection.
///
/// Thread safety: all public methods are safe to call from any thread.
/// Internal state is protected by a mutex and/or atomic variables.
///
/// Typical usage:
/// @code
///   ToxConnection conn(friend_number);
///   conn.set_state(ToxConnection::State::Connected);
///
///   // Queue outbound data (TCP -> Tox direction)
///   std::vector<uint8_t> payload = {0xa0, 1, 2, 3};
///   conn.queue_data(payload.data(), payload.size());
///
///   // Retrieve pending data to send via tox_friend_send_lossless_packet
///   auto chunk = conn.get_pending_data(1371);
///
///   // Deliver inbound data (Tox -> TCP direction)
///   conn.on_data_received(rx_data, rx_len);
///   auto received = conn.read_received_data(8192);
/// @endcode
class ToxConnection {
   public:
    // -----------------------------------------------------------------
    // Connection states
    // -----------------------------------------------------------------

    /// Lifecycle states for a Tox friend connection.
    ///
    /// Valid transitions:
    ///   None -> Requesting -> Connected -> Disconnected
    ///   None -> Connected (when accepting an incoming request)
    ///   Connected -> Disconnected
    enum class State : uint8_t {
        None,          ///< Initial state; no connection attempted.
        Requesting,    ///< Friend request sent, awaiting acceptance.
        Connected,     ///< Friend is online and data can be exchanged.
        Disconnected,  ///< Friend went offline or connection was closed.
    };

    // -----------------------------------------------------------------
    // Callback signatures
    // -----------------------------------------------------------------

    /// Called when data is received from this friend.
    ///
    /// @param data    Pointer to the received bytes.
    /// @param length  Number of bytes received.
    using DataReceivedCallback = std::function<void(const uint8_t* data, std::size_t length)>;

    /// Called when the connection state changes.
    ///
    /// @param new_state  The state that was just entered.
    using StateChangedCallback = std::function<void(State new_state)>;

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Construct a ToxConnection for the given friend number.
    ///
    /// @param friend_number    The toxcore friend number.
    /// @param send_window_size Maximum bytes that may be in-flight before
    ///                         backpressure signals (default 256 KiB).
    explicit ToxConnection(uint32_t friend_number, std::size_t send_window_size = 256 * 1024);

    /// Non-copyable (mutex is non-copyable).
    ToxConnection(const ToxConnection&) = delete;
    ToxConnection& operator=(const ToxConnection&) = delete;

    /// Non-movable (contains atomic member).
    ToxConnection(ToxConnection&&) = delete;
    ToxConnection& operator=(ToxConnection&&) = delete;

    ~ToxConnection() = default;

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the toxcore friend number associated with this connection.
    [[nodiscard]] uint32_t friend_number() const noexcept { return friend_number_; }

    /// Return the current connection state.
    [[nodiscard]] State state() const noexcept { return state_.load(std::memory_order_acquire); }

    /// Return true if the connection is in the Connected state.
    [[nodiscard]] bool is_connected() const noexcept {
        return state_.load(std::memory_order_acquire) == State::Connected;
    }

    // -----------------------------------------------------------------
    // State management
    // -----------------------------------------------------------------

    /// Transition to a new connection state.
    ///
    /// If a StateChangedCallback is registered, it is invoked (under the
    /// lock, so keep it lightweight).
    void set_state(State new_state);

    // -----------------------------------------------------------------
    // Send (outbound: TCP -> Tox direction)
    // -----------------------------------------------------------------

    /// Return true if the send window has room for more data.
    ///
    /// When this returns false, the caller should stop feeding data until
    /// acknowledgements free up send-window space.
    [[nodiscard]] bool can_send() const;

    /// Return the number of bytes of send-window space remaining.
    [[nodiscard]] std::size_t send_buffer_space() const;

    /// Return the total number of bytes currently queued for sending.
    [[nodiscard]] std::size_t send_buffer_size() const;

    /// Queue data for sending to this friend.
    ///
    /// The data is appended to the internal send buffer.  The send-window
    /// usage counter is incremented accordingly.
    ///
    /// @param data    Pointer to the bytes to queue.
    /// @param length  Number of bytes.
    void queue_data(const uint8_t* data, std::size_t length);

    /// @overload  Convenience accepting a vector.
    void queue_data(const std::vector<uint8_t>& data);

    /// Retrieve up to @p max_bytes of pending outbound data.
    ///
    /// The returned bytes are removed from the send buffer.  The caller
    /// should pass these to tox_friend_send_lossless_packet.
    ///
    /// @param max_bytes  Maximum number of bytes to dequeue.
    /// @return           A vector containing up to @p max_bytes of data
    ///                   (may be empty if the buffer is empty).
    [[nodiscard]] std::vector<uint8_t> get_pending_data(std::size_t max_bytes);

    // -----------------------------------------------------------------
    // Receive (inbound: Tox -> TCP direction)
    // -----------------------------------------------------------------

    /// Deliver data received from this friend.
    ///
    /// If a DataReceivedCallback is registered, it is invoked immediately
    /// (under the lock).  The data is also buffered for later retrieval
    /// via read_received_data().
    ///
    /// @param data    Pointer to the received bytes.
    /// @param length  Number of bytes.
    void on_data_received(const uint8_t* data, std::size_t length);

    /// @overload  Convenience accepting a vector.
    void on_data_received(const std::vector<uint8_t>& data);

    /// Read up to @p max_bytes from the receive buffer.
    ///
    /// The returned bytes are removed from the buffer.
    ///
    /// @param max_bytes  Maximum number of bytes to retrieve.
    /// @return           A vector containing up to @p max_bytes of data
    ///                   (may be empty if the buffer is empty).
    [[nodiscard]] std::vector<uint8_t> read_received_data(std::size_t max_bytes);

    /// Return the number of bytes currently buffered for reading.
    [[nodiscard]] std::size_t receive_buffer_size() const;

    // -----------------------------------------------------------------
    // Flow control
    // -----------------------------------------------------------------

    /// Process an acknowledgement that @p bytes_acked bytes have been
    /// consumed by the remote end.
    ///
    /// This frees up send-window space, potentially allowing more data to
    /// be queued.
    void on_ack(uint32_t bytes_acked);

    /// Return the configured send-window size.
    [[nodiscard]] std::size_t send_window_size() const noexcept { return send_window_size_; }

    /// Return the number of bytes currently counted against the send window.
    [[nodiscard]] std::size_t send_window_used() const noexcept {
        return send_window_used_.load(std::memory_order_acquire);
    }

    // -----------------------------------------------------------------
    // Buffer management
    // -----------------------------------------------------------------

    /// Discard all buffered send and receive data and reset the send-window
    /// usage counter.
    void clear_buffers();

    // -----------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------

    /// Register a callback invoked whenever data is received.
    void set_on_data_received(DataReceivedCallback cb);

    /// Register a callback invoked whenever the connection state changes.
    void set_on_state_changed(StateChangedCallback cb);

   private:
    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// The toxcore friend number.
    uint32_t friend_number_;

    /// Current connection state.
    std::atomic<State> state_{State::None};

    /// Outbound byte buffer (TCP -> Tox).
    std::deque<uint8_t> send_buffer_;

    /// Inbound byte buffer (Tox -> TCP).
    std::deque<uint8_t> receive_buffer_;

    /// Maximum bytes allowed in-flight before backpressure.
    std::size_t send_window_size_;

    /// Bytes currently counted against the send window.
    std::atomic<std::size_t> send_window_used_{0};

    /// Protects send_buffer_ and receive_buffer_.
    mutable std::mutex mutex_;

    /// Callback invoked on data reception.
    DataReceivedCallback on_data_received_cb_;

    /// Callback invoked on state change.
    StateChangedCallback on_state_changed_cb_;
};

/// Return a human-readable label for a ToxConnection state.
[[nodiscard]] const char* to_string(ToxConnection::State state) noexcept;

}  // namespace toxtunnel::tox
