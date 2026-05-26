#include "toxtunnel/tox/tox_connection.hpp"

#include <algorithm>
#include <cassert>

namespace toxtunnel::tox {

// ===========================================================================
// Construction
// ===========================================================================

ToxConnection::ToxConnection(uint32_t friend_number, std::size_t send_window_size)
    : friend_number_(friend_number),
      state_(State::None),
      send_window_size_(send_window_size),
      send_window_used_(0) {}

// ===========================================================================
// State management
// ===========================================================================

void ToxConnection::set_state(State new_state) {
    state_.store(new_state, std::memory_order_release);

    // Invoke the state-change callback, if registered.
    // We read the callback under the lock to avoid a race with
    // set_on_state_changed().
    StateChangedCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_state_changed_cb_;
    }
    if (cb) {
        cb(new_state);
    }
}

// ===========================================================================
// Send (outbound: TCP -> Tox direction)
// ===========================================================================

bool ToxConnection::can_send() const {
    return send_window_used_.load(std::memory_order_acquire) < send_window_size_;
}

std::size_t ToxConnection::send_buffer_space() const {
    std::size_t used = send_window_used_.load(std::memory_order_acquire);
    return (used < send_window_size_) ? (send_window_size_ - used) : 0;
}

std::size_t ToxConnection::send_buffer_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return send_buffer_.size();
}

std::size_t ToxConnection::queue_data(const uint8_t* data, std::size_t length) {
    if (length == 0 || data == nullptr) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Enforce the send window internally so a missed can_send() check can't
    // grow send_buffer_ without bound. Accept only what fits in the remaining
    // window; the caller learns from the (possibly short) return value that it
    // must retry the remainder after on_ack() frees up space.
    const std::size_t used = send_window_used_.load(std::memory_order_acquire);
    if (used >= send_window_size_) {
        return 0;
    }
    const std::size_t accepted = std::min(length, send_window_size_ - used);

    send_buffer_.insert(send_buffer_.end(), data, data + accepted);
    send_window_used_.fetch_add(accepted, std::memory_order_acq_rel);
    return accepted;
}

std::size_t ToxConnection::queue_data(const std::vector<uint8_t>& data) {
    return queue_data(data.data(), data.size());
}

std::vector<uint8_t> ToxConnection::get_pending_data(std::size_t max_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t available = std::min(max_bytes, send_buffer_.size());
    if (available == 0) {
        return {};
    }

    std::vector<uint8_t> result(send_buffer_.begin(),
                                send_buffer_.begin() + static_cast<std::ptrdiff_t>(available));
    send_buffer_.erase(send_buffer_.begin(),
                       send_buffer_.begin() + static_cast<std::ptrdiff_t>(available));
    return result;
}

// ===========================================================================
// Receive (inbound: Tox -> TCP direction)
// ===========================================================================

void ToxConnection::on_data_received(const uint8_t* data, std::size_t length) {
    if (length == 0) {
        return;
    }

    DataReceivedCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        receive_buffer_.insert(receive_buffer_.end(), data, data + length);
        cb = on_data_received_cb_;
    }

    // Invoke the callback outside the lock to reduce contention, but after
    // the data has been buffered so that read_received_data() can see it.
    if (cb) {
        cb(data, length);
    }
}

void ToxConnection::on_data_received(const std::vector<uint8_t>& data) {
    on_data_received(data.data(), data.size());
}

std::vector<uint8_t> ToxConnection::read_received_data(std::size_t max_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t available = std::min(max_bytes, receive_buffer_.size());
    if (available == 0) {
        return {};
    }

    std::vector<uint8_t> result(receive_buffer_.begin(),
                                receive_buffer_.begin() + static_cast<std::ptrdiff_t>(available));
    receive_buffer_.erase(receive_buffer_.begin(),
                          receive_buffer_.begin() + static_cast<std::ptrdiff_t>(available));
    return result;
}

std::size_t ToxConnection::receive_buffer_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return receive_buffer_.size();
}

// ===========================================================================
// Flow control
// ===========================================================================

void ToxConnection::on_ack(uint32_t bytes_acked) {
    // Atomically subtract, clamping to zero to avoid underflow.
    std::size_t current = send_window_used_.load(std::memory_order_acquire);
    std::size_t acked = static_cast<std::size_t>(bytes_acked);

    // CAS loop to safely clamp the subtraction.
    while (true) {
        std::size_t desired = (current > acked) ? (current - acked) : 0;
        if (send_window_used_.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
                                                    std::memory_order_acquire)) {
            break;
        }
        // current is reloaded by compare_exchange_weak on failure.
    }
}

// ===========================================================================
// Buffer management
// ===========================================================================

void ToxConnection::clear_buffers() {
    std::lock_guard<std::mutex> lock(mutex_);
    send_buffer_.clear();
    receive_buffer_.clear();
    send_window_used_.store(0, std::memory_order_release);
}

// ===========================================================================
// Callbacks
// ===========================================================================

void ToxConnection::set_on_data_received(DataReceivedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_received_cb_ = std::move(cb);
}

void ToxConnection::set_on_state_changed(StateChangedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_state_changed_cb_ = std::move(cb);
}

// ===========================================================================
// Free functions
// ===========================================================================

const char* to_string(ToxConnection::State state) noexcept {
    switch (state) {
        case ToxConnection::State::None:
            return "None";
        case ToxConnection::State::Requesting:
            return "Requesting";
        case ToxConnection::State::Connected:
            return "Connected";
        case ToxConnection::State::Disconnected:
            return "Disconnected";
    }
    return "Unknown";
}

}  // namespace toxtunnel::tox
