#include "toxtunnel/tunnel/tunnel.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace toxtunnel::tunnel {

namespace {

// tox custom lossless packets max out at 1373 bytes. Our tunnel framing adds
// a 1-byte tox packet prefix and a 5-byte tunnel frame header, leaving 1367
// bytes for raw TCP payload per frame.
constexpr std::size_t kMaxTcpPayloadPerToxFrame = 1367;

}  // namespace

// ===========================================================================
// to_string(Tunnel::State)
// ===========================================================================

const char* to_string(Tunnel::State state) noexcept {
    switch (state) {
        case Tunnel::State::None:
            return "None";
        case Tunnel::State::Connecting:
            return "Connecting";
        case Tunnel::State::Connected:
            return "Connected";
        case Tunnel::State::Disconnecting:
            return "Disconnecting";
        case Tunnel::State::Closed:
            return "Closed";
        case Tunnel::State::Error:
            return "Error";
        default:
            return "Unknown";
    }
}

// ===========================================================================
// TunnelImpl - Construction / Destruction
// ===========================================================================

TunnelImpl::TunnelImpl(asio::io_context& io_ctx, uint16_t tunnel_id, uint32_t friend_number,
                       std::size_t send_window)
    : Tunnel(tunnel_id, io_ctx),
      friend_number_(friend_number),
      send_window_size_(send_window),
      last_activity_(std::chrono::steady_clock::now()) {
    util::Logger::debug("Tunnel created: id={}, friend={}, window={}", tunnel_id_, friend_number_,
                        send_window_size_);
}

TunnelImpl::~TunnelImpl() {
    util::Logger::debug("Tunnel destroyed: id={}", tunnel_id_);
}

// ===========================================================================
// Accessors
// ===========================================================================

std::string TunnelImpl::target_host() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return target_host_;
}

uint16_t TunnelImpl::target_port() const noexcept {
    return target_port_;
}

std::chrono::steady_clock::time_point TunnelImpl::last_activity() const {
    return last_activity_;
}

// ===========================================================================
// TCP connection management
// ===========================================================================

void TunnelImpl::set_tcp_connection(std::shared_ptr<core::TcpConnection> tcp_conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    tcp_conn_ = std::move(tcp_conn);
}

std::shared_ptr<core::TcpConnection> TunnelImpl::tcp_connection() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tcp_conn_;
}

// ===========================================================================
// State management
// ===========================================================================

void TunnelImpl::set_state(State new_state) {
    transition_state(new_state);
}

void TunnelImpl::transition_state(State new_state) {
    State old_state = state_.exchange(new_state, std::memory_order_acq_rel);
    if (old_state != new_state) {
        util::Logger::debug("Tunnel {} state: {} -> {}", tunnel_id_, to_string(old_state),
                            to_string(new_state));

        StateChangedCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = on_state_change_;
        }

        if (cb) {
            cb(new_state);
        }
    }
}

// ===========================================================================
// Tunnel lifecycle
// ===========================================================================

bool TunnelImpl::open(const std::string& host, uint16_t port) {
    State current = state_.load(std::memory_order_acquire);
    if (current != State::None) {
        util::Logger::warn("Tunnel {} open failed: invalid state {}", tunnel_id_,
                           to_string(current));
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        target_host_ = host;
        target_port_ = port;
    }

    // Send TUNNEL_OPEN frame
    auto frame = ProtocolFrame::make_tunnel_open(tunnel_id_, host, port);
    send_frame_to_tox(frame);

    // Transition to Connecting state
    transition_state(State::Connecting);

    util::Logger::info("Tunnel {} opening: {}:{}", tunnel_id_, host, port);
    return true;
}

void TunnelImpl::close() {
    State current = state_.load(std::memory_order_acquire);

    // Only close from Connected state
    if (current != State::Connected) {
        util::Logger::debug("Tunnel {} close ignored: state {}", tunnel_id_, to_string(current));
        return;
    }

    // Send TUNNEL_CLOSE frame
    auto frame = ProtocolFrame::make_tunnel_close(tunnel_id_);
    send_frame_to_tox(frame);

    // Transition to Disconnecting state
    transition_state(State::Disconnecting);

    util::Logger::info("Tunnel {} closing", tunnel_id_);
}

void TunnelImpl::force_close() {
    State current = state_.load(std::memory_order_acquire);
    if (current == State::Closed) {
        return;
    }

    // Close TCP connection if any
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tcp_conn_) {
            tcp_conn_->force_close();
            tcp_conn_.reset();
        }
    }

    transition_state(State::Closed);
    util::Logger::info("Tunnel {} force closed", tunnel_id_);
}

// ===========================================================================
// Frame handling
// ===========================================================================

void TunnelImpl::handle_frame(const ProtocolFrame& frame) {
    // Ignore frames with wrong tunnel_id (except PING/PONG which use tunnel_id 0)
    if (frame.type() != FrameType::PING && frame.type() != FrameType::PONG) {
        if (frame.tunnel_id() != tunnel_id_) {
            util::Logger::debug("Tunnel {} ignored frame for tunnel {}", tunnel_id_,
                                frame.tunnel_id());
            return;
        }
    }

    update_activity();

    switch (frame.type()) {
        case FrameType::TUNNEL_OPEN:
            handle_tunnel_open_frame(frame);
            break;
        case FrameType::TUNNEL_DATA:
            handle_tunnel_data_frame(frame);
            break;
        case FrameType::TUNNEL_CLOSE:
            handle_tunnel_close_frame(frame);
            break;
        case FrameType::TUNNEL_ACK:
            handle_tunnel_ack_frame(frame);
            break;
        case FrameType::TUNNEL_ERROR:
            handle_tunnel_error_frame(frame);
            break;
        case FrameType::PING:
            handle_ping_frame(frame);
            break;
        case FrameType::PONG:
            handle_pong_frame(frame);
            break;
        default:
            util::Logger::warn("Tunnel {} received unknown frame type: {}", tunnel_id_,
                               static_cast<int>(frame.type()));
            break;
    }
}

void TunnelImpl::handle_tunnel_open_frame(const ProtocolFrame& frame) {
    // Server-side: handle incoming TUNNEL_OPEN request
    auto payload = frame.as_tunnel_open();
    if (!payload) {
        util::Logger::warn("Tunnel {} received malformed TUNNEL_OPEN", tunnel_id_);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        target_host_ = payload->host;
        target_port_ = payload->port;
    }

    util::Logger::info("Tunnel {} received TUNNEL_OPEN for {}:{}", tunnel_id_, payload->host,
                       payload->port);
}

void TunnelImpl::handle_tunnel_data_frame(const ProtocolFrame& frame) {
    if (!is_connected()) {
        util::Logger::debug("Tunnel {} ignored TUNNEL_DATA: not connected", tunnel_id_);
        return;
    }

    auto data = frame.as_tunnel_data();
    if (data.empty()) {
        return;
    }

    // Update receive statistics
    std::size_t data_size = data.size();
    total_bytes_received_.fetch_add(data_size, std::memory_order_relaxed);
    bytes_received_since_ack_.fetch_add(data_size, std::memory_order_relaxed);

    // Forward data to TCP connection
    SendToTcpCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_data_for_tcp_;
    }

    if (cb) {
        cb(data);
    }

    // Check if we should send ACK
    maybe_send_ack();
}

void TunnelImpl::handle_tunnel_close_frame(const ProtocolFrame& /*frame*/) {
    util::Logger::info("Tunnel {} received TUNNEL_CLOSE", tunnel_id_);

    // Close TCP connection
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tcp_conn_) {
            tcp_conn_->close();
        }
    }

    transition_state(State::Closed);

    // Invoke close callback
    CloseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_close_;
    }
    if (cb) {
        cb();
    }
}

void TunnelImpl::handle_tunnel_ack_frame(const ProtocolFrame& frame) {
    auto payload = frame.as_tunnel_ack();
    if (!payload) {
        util::Logger::warn("Tunnel {} received malformed TUNNEL_ACK", tunnel_id_);
        return;
    }

    // If we're in Connecting state, an ACK means the tunnel is accepted
    State current = state_.load(std::memory_order_acquire);
    if (current == State::Connecting) {
        transition_state(State::Connected);
        util::Logger::info("Tunnel {} connected (received open ACK)", tunnel_id_);
        return;
    }

    // Free up send window
    std::size_t acked = payload->bytes_acked;
    std::size_t current_window = send_window_used_.load(std::memory_order_relaxed);
    while (current_window > 0) {
        std::size_t new_val = current_window > acked ? current_window - acked : 0;
        if (send_window_used_.compare_exchange_weak(current_window, new_val,
                                                    std::memory_order_relaxed)) {
            break;
        }
    }

    util::Logger::debug("Tunnel {} received ACK for {} bytes (window now {})", tunnel_id_, acked,
                        send_window_used_.load());
}

void TunnelImpl::handle_tunnel_error_frame(const ProtocolFrame& frame) {
    auto payload = frame.as_tunnel_error();
    if (!payload) {
        util::Logger::warn("Tunnel {} received malformed TUNNEL_ERROR", tunnel_id_);
        return;
    }

    util::Logger::error("Tunnel {} received TUNNEL_ERROR: code={}, desc='{}'", tunnel_id_,
                        payload->error_code, payload->description);

    transition_state(State::Error);

    // Invoke error callback
    ErrorCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_error_;
    }
    if (cb) {
        cb(*payload);
    }
}

void TunnelImpl::handle_ping_frame(const ProtocolFrame& /*frame*/) {
    // Respond with PONG
    auto pong = ProtocolFrame::make_pong();
    send_frame_to_tox(pong);
    util::Logger::debug("Tunnel {} responded to PING", tunnel_id_);
}

void TunnelImpl::handle_pong_frame(const ProtocolFrame& /*frame*/) {
    // PONG received - update activity timestamp (already done)
    util::Logger::debug("Tunnel {} received PONG", tunnel_id_);
}

// ===========================================================================
// TCP data handling
// ===========================================================================

void TunnelImpl::on_tcp_data_received(const uint8_t* data, std::size_t length) {
    if (!is_connected()) {
        return;
    }

    // Forward to Tox (ignore return value - backpressure is handled by TcpConnection)
    (void)send_data_to_tox(std::span<const uint8_t>(data, length));
}

// ===========================================================================
// Data sending
// ===========================================================================

bool TunnelImpl::send_data_to_tox(std::span<const uint8_t> data) {
    if (!is_connected()) {
        return false;
    }

    // Check window
    std::size_t data_size = data.size();
    std::size_t current = send_window_used_.load(std::memory_order_relaxed);
    if (current + data_size > send_window_size_) {
        util::Logger::debug("Tunnel {} send window full ({} + {} > {})", tunnel_id_, current,
                            data_size, send_window_size_);
        return false;
    }

    // Update window
    send_window_used_.fetch_add(data_size, std::memory_order_relaxed);

    // Update statistics
    total_bytes_sent_.fetch_add(data_size, std::memory_order_relaxed);

    for (std::size_t offset = 0; offset < data.size(); offset += kMaxTcpPayloadPerToxFrame) {
        const auto chunk_size = std::min(kMaxTcpPayloadPerToxFrame, data.size() - offset);
        auto frame = ProtocolFrame::make_tunnel_data(tunnel_id_, data.subspan(offset, chunk_size));
        send_frame_to_tox(frame);
    }

    return true;
}

bool TunnelImpl::send_data_to_tox(const std::vector<uint8_t>& data) {
    return send_data_to_tox(std::span<const uint8_t>(data.data(), data.size()));
}

// ===========================================================================
// Error handling
// ===========================================================================

void TunnelImpl::send_error(uint8_t error_code, const std::string& description) {
    auto frame = ProtocolFrame::make_tunnel_error(tunnel_id_, error_code, description);
    send_frame_to_tox(frame);
    transition_state(State::Error);

    util::Logger::error("Tunnel {} sent error: code={}, desc='{}'", tunnel_id_, error_code,
                        description);
}

// ===========================================================================
// Flow control
// ===========================================================================

void TunnelImpl::set_ack_threshold(std::size_t threshold) noexcept {
    ack_threshold_ = threshold;
}

void TunnelImpl::maybe_send_ack() {
    std::size_t pending = bytes_received_since_ack_.load(std::memory_order_relaxed);
    if (pending >= ack_threshold_) {
        send_ack();
    }
}

void TunnelImpl::send_ack() {
    std::size_t bytes_to_ack = bytes_received_since_ack_.exchange(0, std::memory_order_relaxed);
    if (bytes_to_ack > 0) {
        // Truncate to uint32_t range
        uint32_t ack_value = static_cast<uint32_t>(
            std::min<std::size_t>(bytes_to_ack, std::numeric_limits<uint32_t>::max()));

        auto frame = ProtocolFrame::make_tunnel_ack(tunnel_id_, ack_value);
        send_frame_to_tox(frame);

        util::Logger::debug("Tunnel {} sent ACK for {} bytes", tunnel_id_, ack_value);
    }
}

// ===========================================================================
// Statistics
// ===========================================================================

void TunnelImpl::reset_statistics() {
    total_bytes_received_.store(0, std::memory_order_relaxed);
    total_bytes_sent_.store(0, std::memory_order_relaxed);
    bytes_received_since_ack_.store(0, std::memory_order_relaxed);
    send_window_used_.store(0, std::memory_order_relaxed);
}

// ===========================================================================
// Callbacks
// ===========================================================================

void TunnelImpl::set_on_send_to_tox(SendToToxCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_send_to_tox_ = std::move(cb);
}

void TunnelImpl::set_on_data_for_tcp(SendToTcpCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_for_tcp_ = std::move(cb);
}

void TunnelImpl::set_on_state_change(StateChangedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_state_change_ = std::move(cb);
}

void TunnelImpl::set_on_error(ErrorCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_error_ = std::move(cb);
}

void TunnelImpl::set_on_close(CloseCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_close_ = std::move(cb);
}

// ===========================================================================
// Internal helpers
// ===========================================================================

void TunnelImpl::send_frame_to_tox(const ProtocolFrame& frame) {
    SendToToxCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_send_to_tox_;
    }

    if (cb) {
        auto wire = frame.serialize();
        cb(std::span<const uint8_t>(wire.data(), wire.size()));
    }
}

void TunnelImpl::update_activity() {
    last_activity_ = std::chrono::steady_clock::now();
}

}  // namespace toxtunnel::tunnel
