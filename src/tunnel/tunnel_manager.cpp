#include "toxtunnel/tunnel/tunnel_manager.hpp"

#include <algorithm>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tunnel {

// ===========================================================================
// Construction
// ===========================================================================

TunnelManager::TunnelManager(asio::io_context& io_ctx)
    : io_ctx_(io_ctx), used_ids_(65536, false), reaper_timer_(io_ctx) {
    // ID 0 is reserved for control frames (PING/PONG)
    used_ids_[0] = true;
}

TunnelManager::~TunnelManager() {
    disable_reaper();
    close_all();
}

// ===========================================================================
// Configuration
// ===========================================================================

void TunnelManager::set_send_handler(SendHandler handler) {
    std::lock_guard<std::mutex> lock(handler_mutex_);
    send_handler_ = std::move(handler);
}

void TunnelManager::set_on_tunnel_created(TunnelCreatedCallback cb) {
    std::unique_lock lock(mutex_);
    on_tunnel_created_ = std::move(cb);
}

void TunnelManager::set_on_tunnel_closed(TunnelClosedCallback cb) {
    std::unique_lock lock(mutex_);
    on_tunnel_closed_ = std::move(cb);
}

void TunnelManager::set_max_tunnels(std::size_t max) {
    std::unique_lock lock(mutex_);
    max_tunnels_ = max;
}

void TunnelManager::set_backpressure_threshold(std::size_t bytes) {
    std::unique_lock lock(mutex_);
    backpressure_threshold_ = bytes;
}

// ===========================================================================
// Idle-tunnel reaper
// ===========================================================================

void TunnelManager::enable_reaper(uint32_t idle_timeout_seconds, uint32_t tick_seconds) {
    if (idle_timeout_seconds == 0 || tick_seconds == 0) {
        return;
    }

    const auto idle_ns =
        std::chrono::nanoseconds(std::chrono::seconds(idle_timeout_seconds)).count();
    reaper_idle_timeout_ns_.store(static_cast<int64_t>(idle_ns), std::memory_order_relaxed);
    reaper_tick_ = std::chrono::seconds(tick_seconds);

    // Re-entering enable_reaper() while already armed is fine — schedule_reaper_tick()
    // is idempotent in the sense that the new expiry replaces the old.
    schedule_reaper_tick();

    util::Logger::info("TunnelManager: reaper enabled (idle={}s, tick={}s)", idle_timeout_seconds,
                       tick_seconds);
}

void TunnelManager::disable_reaper() {
    reaper_idle_timeout_ns_.store(0, std::memory_order_relaxed);
    if (reaper_active_.exchange(false, std::memory_order_acq_rel)) {
        reaper_timer_.cancel();
    }
}

void TunnelManager::schedule_reaper_tick() {
    reaper_active_.store(true, std::memory_order_release);
    reaper_timer_.expires_after(reaper_tick_);
    reaper_timer_.async_wait([this](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        // Stash & re-read the timeout: disable_reaper() may have raced in.
        if (reaper_idle_timeout_ns_.load(std::memory_order_relaxed) == 0) {
            reaper_active_.store(false, std::memory_order_release);
            return;
        }

        reap_idle_tunnels_once();

        if (reaper_idle_timeout_ns_.load(std::memory_order_relaxed) > 0) {
            schedule_reaper_tick();
        } else {
            reaper_active_.store(false, std::memory_order_release);
        }
    });
}

std::size_t TunnelManager::reap_idle_tunnels_once() {
    const int64_t idle_timeout_ns = reaper_idle_timeout_ns_.load(std::memory_order_relaxed);
    if (idle_timeout_ns <= 0) {
        return 0;
    }

    // Snapshot the candidate set under shared lock so the scan never blocks
    // route_frame on the hot path. Only TunnelImpl exposes IdleNanos();
    // abstract Tunnels used in some tests are skipped.
    std::vector<uint16_t> to_close;
    {
        std::shared_lock lock(mutex_);
        to_close.reserve(tunnels_.size());
        for (const auto& [id, tunnel] : tunnels_) {
            const auto* impl = dynamic_cast<const TunnelImpl*>(tunnel.get());
            if (impl == nullptr) {
                continue;
            }
            if (impl->state() == Tunnel::State::Connecting) {
                continue;
            }
            if (impl->IdleNanos() >= idle_timeout_ns) {
                to_close.push_back(id);
            }
        }
    }

    std::size_t closed = 0;
    for (uint16_t id : to_close) {
        // remove_tunnel() invokes Tunnel::close() under its own lock, which
        // emits TUNNEL_CLOSE to the peer before erasing the entry. A tunnel
        // may have already been removed between the scan and now — that's
        // fine; remove_tunnel() is a no-op on missing IDs.
        if (has_tunnel(id)) {
            remove_tunnel(id);
            ++closed;
        }
    }

    if (closed > 0) {
        util::Logger::info("TunnelManager: reaper closed {} idle tunnels (timeout={}s)", closed,
                           idle_timeout_ns / 1'000'000'000);
    }
    return closed;
}

// ===========================================================================
// Tunnel ID allocation
// ===========================================================================

uint16_t TunnelManager::allocate_tunnel_id() {
    std::unique_lock lock(mutex_);
    return find_available_id();
}

uint16_t TunnelManager::find_available_id() {
    // Try to find an available ID starting from next_tunnel_id_
    uint16_t start = next_tunnel_id_;
    do {
        if (!used_ids_[next_tunnel_id_]) {
            uint16_t result = next_tunnel_id_;
            used_ids_[result] = true;
            // Advance to next ID, wrapping at 65535, skipping 0
            next_tunnel_id_ =
                (next_tunnel_id_ == 65535) ? 1 : static_cast<uint16_t>(next_tunnel_id_ + 1);
            return result;
        }
        next_tunnel_id_ =
            (next_tunnel_id_ == 65535) ? 1 : static_cast<uint16_t>(next_tunnel_id_ + 1);
    } while (next_tunnel_id_ != start);

    // No available IDs - this should be very rare
    util::Logger::error("TunnelManager: no available tunnel IDs");
    return 0;
}

void TunnelManager::release_tunnel_id(uint16_t tunnel_id) {
    std::unique_lock lock(mutex_);
    if (tunnel_id > 0) {
        used_ids_[tunnel_id] = false;
    }
}

void TunnelManager::set_next_tunnel_id(uint16_t next_id) {
    std::unique_lock lock(mutex_);
    // Ensure we don't set it to 0
    next_tunnel_id_ = (next_id == 0) ? 1 : next_id;
}

// ===========================================================================
// Tunnel lifecycle
// ===========================================================================

void TunnelManager::add_tunnel(uint16_t tunnel_id, std::shared_ptr<Tunnel> tunnel) {
    if (!tunnel) {
        util::Logger::warn("TunnelManager::add_tunnel: null tunnel for id {}", tunnel_id);
        return;
    }

    TunnelCreatedCallback created_cb;

    {
        std::unique_lock lock(mutex_);

        // Check if we're at the limit
        if (tunnels_.size() >= max_tunnels_ && tunnels_.find(tunnel_id) == tunnels_.end()) {
            util::Logger::warn("TunnelManager: max tunnels ({}) reached, cannot add tunnel {}",
                               max_tunnels_, tunnel_id);
            return;
        }

        // If a tunnel with this ID already exists, close it first
        auto it = tunnels_.find(tunnel_id);
        if (it != tunnels_.end()) {
            util::Logger::debug("TunnelManager: replacing existing tunnel {}", tunnel_id);
            it->second->close();
            tunnels_.erase(it);
        } else {
            // Mark ID as used
            used_ids_[tunnel_id] = true;
        }

        tunnels_[tunnel_id] = std::move(tunnel);

        // Copy callbacks to invoke outside the lock
        created_cb = on_tunnel_created_;
    }

    util::Logger::debug("TunnelManager: added tunnel {}", tunnel_id);

    // Invoke callback outside the lock
    if (created_cb) {
        asio::post(io_ctx_, [created_cb, tunnel_id]() { created_cb(tunnel_id); });
    }
}

void TunnelManager::remove_tunnel(uint16_t tunnel_id) {
    TunnelClosedCallback closed_cb;

    {
        std::unique_lock lock(mutex_);

        auto it = tunnels_.find(tunnel_id);
        if (it == tunnels_.end()) {
            return;
        }

        // Close the tunnel
        it->second->close();

        // Remove from map
        tunnels_.erase(it);

        // Release the ID
        used_ids_[tunnel_id] = false;

        // Copy callback to invoke outside the lock
        closed_cb = on_tunnel_closed_;
    }

    util::Logger::debug("TunnelManager: removed tunnel {}", tunnel_id);

    // Invoke callback outside the lock
    if (closed_cb) {
        asio::post(io_ctx_, [closed_cb, tunnel_id]() { closed_cb(tunnel_id); });
    }
}

std::shared_ptr<Tunnel> TunnelManager::get_tunnel(uint16_t tunnel_id) {
    std::shared_lock lock(mutex_);
    auto it = tunnels_.find(tunnel_id);
    return (it != tunnels_.end()) ? it->second : nullptr;
}

std::shared_ptr<const Tunnel> TunnelManager::get_tunnel(uint16_t tunnel_id) const {
    std::shared_lock lock(mutex_);
    auto it = tunnels_.find(tunnel_id);
    return (it != tunnels_.end()) ? it->second : nullptr;
}

bool TunnelManager::has_tunnel(uint16_t tunnel_id) const {
    std::shared_lock lock(mutex_);
    return tunnels_.find(tunnel_id) != tunnels_.end();
}

uint16_t TunnelManager::create_tunnel(const std::string& host, uint16_t port) {
    // Allocate an ID first
    uint16_t tunnel_id = allocate_tunnel_id();
    if (tunnel_id == 0) {
        util::Logger::error("TunnelManager::create_tunnel: failed to allocate tunnel ID");
        return 0;
    }

    // Send TUNNEL_OPEN frame to the remote peer
    ProtocolFrame open_frame = ProtocolFrame::make_tunnel_open(tunnel_id, host, port);

    SendHandler handler;
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        handler = send_handler_;
    }

    if (!handler) {
        // No send handler - cannot create tunnel
        release_tunnel_id(tunnel_id);
        return 0;
    }

    auto wire = open_frame.serialize();
    if (!handler(wire)) {
        util::Logger::warn("TunnelManager::create_tunnel: failed to send TUNNEL_OPEN for {}",
                           tunnel_id);
        release_tunnel_id(tunnel_id);
        return 0;
    }

    util::Logger::info("TunnelManager: created tunnel {} -> {}:{}", tunnel_id, host, port);

    // Record statistics
    record_frame_sent();
    record_bytes_sent(open_frame.serialized_size());

    return tunnel_id;
}

void TunnelManager::close_all() {
    std::map<uint16_t, std::shared_ptr<Tunnel>> tunnels_to_close;
    TunnelClosedCallback closed_cb;

    {
        std::unique_lock lock(mutex_);

        // Swap out the tunnels map to close outside the lock
        tunnels_to_close.swap(tunnels_);

        // Release all IDs
        for (auto& [id, tunnel] : tunnels_to_close) {
            used_ids_[id] = false;
        }

        closed_cb = on_tunnel_closed_;
    }

    // Close all tunnels outside the lock
    for (auto& [id, tunnel] : tunnels_to_close) {
        if (tunnel) {
            tunnel->close();
        }

        // Invoke callback
        if (closed_cb) {
            asio::post(io_ctx_, [closed_cb, id = id]() { closed_cb(id); });
        }
    }

    util::Logger::debug("TunnelManager: closed all tunnels");
}

// ===========================================================================
// Frame routing
// ===========================================================================

void TunnelManager::route_frame(const ProtocolFrame& frame) {
    // Record statistics
    record_frame_received();
    record_bytes_received(frame.serialized_size());

    uint16_t tid = frame.tunnel_id();

    // Handle control frames (tunnel_id == 0)
    if (tid == 0) {
        switch (frame.type()) {
            case FrameType::PING:
                handle_ping_frame(frame);
                break;
            case FrameType::PONG:
                handle_pong_frame(frame);
                break;
            default:
                util::Logger::warn("TunnelManager: unexpected control frame type: {}",
                                   to_string(frame.type()));
                break;
        }
        return;
    }

    // Route to the appropriate tunnel
    Tunnel* tunnel = nullptr;
    {
        std::shared_lock lock(mutex_);
        auto it = tunnels_.find(tid);
        if (it != tunnels_.end()) {
            tunnel = it->second.get();
        }
    }

    if (tunnel) {
        tunnel->handle_frame(frame);
    } else {
        util::Logger::debug("TunnelManager: received frame for unknown tunnel {}", tid);

        // Send TUNNEL_ERROR back if this was a data frame
        if (frame.type() == FrameType::TUNNEL_DATA) {
            ProtocolFrame error_frame =
                ProtocolFrame::make_tunnel_error(tid, static_cast<uint8_t>(1), "Tunnel not found");
            send_frame(error_frame);
        }
    }
}

bool TunnelManager::handle_incoming_open(const ProtocolFrame& frame) {
    auto open_payload = frame.as_tunnel_open();
    if (!open_payload) {
        util::Logger::warn("TunnelManager: malformed TUNNEL_OPEN frame");
        return false;
    }

    uint16_t tunnel_id = frame.tunnel_id();

    {
        std::unique_lock lock(mutex_);

        // Check if we're at the limit
        if (tunnels_.size() >= max_tunnels_) {
            util::Logger::warn("TunnelManager: max tunnels ({}) reached, rejecting incoming open",
                               max_tunnels_);
            ProtocolFrame error_frame = ProtocolFrame::make_tunnel_error(
                tunnel_id, static_cast<uint8_t>(3), "Tunnel limit exceeded");
            // Unlock before sending to avoid potential deadlock
            lock.unlock();
            send_frame(error_frame);
            return false;
        }

        // Check if tunnel ID is already in use
        if (tunnels_.find(tunnel_id) != tunnels_.end()) {
            util::Logger::warn("TunnelManager: tunnel {} already exists, rejecting open",
                               tunnel_id);
            ProtocolFrame error_frame = ProtocolFrame::make_tunnel_error(
                tunnel_id, static_cast<uint8_t>(2), "Tunnel ID in use");
            lock.unlock();
            send_frame(error_frame);
            return false;
        }

        // Mark the ID as used
        used_ids_[tunnel_id] = true;
    }

    util::Logger::info("TunnelManager: accepted incoming tunnel {} -> {}:{}", tunnel_id,
                       open_payload->host, open_payload->port);

    TunnelCreatedCallback created_cb;
    {
        std::shared_lock lock(mutex_);
        created_cb = on_tunnel_created_;
    }

    if (created_cb) {
        asio::post(io_ctx_, [created_cb, tunnel_id]() { created_cb(tunnel_id); });
    }

    return true;
}

bool TunnelManager::send_frame(const ProtocolFrame& frame) {
    SendHandler handler;
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        handler = send_handler_;
    }

    if (!handler) {
        util::Logger::warn("TunnelManager::send_frame: no send handler registered");
        return false;
    }

    auto wire = frame.serialize();
    bool success = handler(wire);

    if (success) {
        record_frame_sent();
        record_bytes_sent(frame.serialized_size());
    } else {
        util::Logger::debug(
            "TunnelManager::send_frame: send handler returned false (backpressure)");
    }

    return success;
}

// ===========================================================================
// Backpressure tracking
// ===========================================================================

std::size_t TunnelManager::total_buffer_level() const {
    std::shared_lock lock(mutex_);
    std::size_t total = 0;
    for (const auto& [id, tunnel] : tunnels_) {
        total += tunnel->buffer_level();
    }
    return total;
}

bool TunnelManager::has_backpressure() const {
    return total_buffer_level() >= backpressure_threshold();
}

std::size_t TunnelManager::backpressure_threshold() const noexcept {
    return backpressure_threshold_;
}

// ===========================================================================
// Statistics
// ===========================================================================

void TunnelManager::record_bytes_sent(std::size_t bytes) {
    total_bytes_sent_.fetch_add(bytes, std::memory_order_relaxed);
}

void TunnelManager::record_bytes_received(std::size_t bytes) {
    total_bytes_received_.fetch_add(bytes, std::memory_order_relaxed);
}

void TunnelManager::record_frame_sent() {
    frames_sent_.fetch_add(1, std::memory_order_relaxed);
}

void TunnelManager::record_frame_received() {
    frames_received_.fetch_add(1, std::memory_order_relaxed);
}

std::size_t TunnelManager::total_bytes_sent() const noexcept {
    return total_bytes_sent_.load(std::memory_order_relaxed);
}

std::size_t TunnelManager::total_bytes_received() const noexcept {
    return total_bytes_received_.load(std::memory_order_relaxed);
}

std::size_t TunnelManager::frames_sent() const noexcept {
    return frames_sent_.load(std::memory_order_relaxed);
}

std::size_t TunnelManager::frames_received() const noexcept {
    return frames_received_.load(std::memory_order_relaxed);
}

// ===========================================================================
// Accessors
// ===========================================================================

std::size_t TunnelManager::tunnel_count() const {
    std::shared_lock lock(mutex_);
    return tunnels_.size();
}

bool TunnelManager::empty() const {
    std::shared_lock lock(mutex_);
    return tunnels_.empty();
}

std::vector<uint16_t> TunnelManager::get_tunnel_ids() const {
    std::shared_lock lock(mutex_);
    std::vector<uint16_t> ids;
    ids.reserve(tunnels_.size());
    for (const auto& [id, tunnel] : tunnels_) {
        ids.push_back(id);
    }
    return ids;
}

ManagerSnapshot TunnelManager::snapshot() const {
    ManagerSnapshot out;
    out.bytes_in = total_bytes_received();
    out.bytes_out = total_bytes_sent();
    out.frames_in = frames_received();
    out.frames_out = frames_sent();

    const auto now = std::chrono::steady_clock::now();

    std::shared_lock lock(mutex_);
    out.tunnels.reserve(tunnels_.size());
    for (const auto& [id, tunnel] : tunnels_) {
        TunnelSnapshot t;
        t.id = id;
        t.state = to_string(tunnel->state());
        // Only TunnelImpl carries target host/port + byte counters; the
        // abstract base used in unit tests does not.
        if (const auto* impl = dynamic_cast<const TunnelImpl*>(tunnel.get())) {
            t.target_host = impl->target_host();
            t.target_port = impl->target_port();
            t.bytes_in = impl->bytes_received();
            t.bytes_out = impl->bytes_sent();
            t.idle_seconds =
                std::chrono::duration_cast<std::chrono::seconds>(now - impl->last_activity());
        }
        out.tunnels.push_back(std::move(t));
    }
    return out;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

void TunnelManager::handle_ping_frame(const ProtocolFrame& /*frame*/) {
    util::Logger::debug("TunnelManager: received PING, sending PONG");
    ProtocolFrame pong = ProtocolFrame::make_pong();
    send_frame(pong);
}

void TunnelManager::handle_pong_frame(const ProtocolFrame& /*frame*/) {
    util::Logger::debug("TunnelManager: received PONG");
    // PONG received - could update last-seen timestamp for keepalive tracking
}

}  // namespace toxtunnel::tunnel
