#include "toxtunnel/tunnel/tunnel_manager.hpp"

#include <algorithm>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tunnel {

// ===========================================================================
// Construction
// ===========================================================================

TunnelManager::TunnelManager(asio::io_context& io_ctx)
    : io_ctx_(io_ctx),
      used_ids_(65536, false),
      reaper_timer_(io_ctx),
      pending_drain_timer_(io_ctx),
      keepalive_timer_(io_ctx) {
    // ID 0 is reserved for control frames (PING/PONG)
    used_ids_[0] = true;
}

TunnelManager::~TunnelManager() {
    disable_reaper();
    disable_keepalive();
    // Cancel any in-flight pending-drain timer so its handler runs with an
    // error_code and bails (the handler captures a weak_ptr so this isn't
    // a UAF risk by itself, but cancelling shrinks the dangling-timer window).
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_drain_armed_ = false;
        pending_outbound_.clear();
    }
    pending_drain_timer_.cancel();
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
    backpressure_threshold_.store(bytes, std::memory_order_relaxed);
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
    // S17 / 2026-05-20 follow-up: weak_ptr capture so the handler
    // gracefully bails out if the manager was destroyed between
    // `cancel()` (non-blocking) and dispatch.
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    reaper_timer_.async_wait([weak](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        auto self = weak.lock();
        if (!self) {
            return;  // Manager was destroyed before the timer fired.
        }
        // Stash & re-read the timeout: disable_reaper() may have raced in.
        if (self->reaper_idle_timeout_ns_.load(std::memory_order_relaxed) == 0) {
            self->reaper_active_.store(false, std::memory_order_release);
            return;
        }

        self->reap_idle_tunnels_once();

        if (self->reaper_idle_timeout_ns_.load(std::memory_order_relaxed) > 0) {
            self->schedule_reaper_tick();
        } else {
            self->reaper_active_.store(false, std::memory_order_release);
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
// Keepalive (M-02)
// ===========================================================================

void TunnelManager::set_on_peer_dead(std::function<void()> cb) {
    std::lock_guard<std::mutex> lock(handler_mutex_);
    on_peer_dead_ = std::move(cb);
}

void TunnelManager::note_pong() {
    last_pong_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                        std::memory_order_relaxed);
}

void TunnelManager::enable_keepalive(uint32_t interval_seconds, uint32_t timeout_seconds) {
    if (interval_seconds == 0) {
        return;
    }
    keepalive_interval_ = std::chrono::seconds(interval_seconds);
    keepalive_timeout_ =
        std::chrono::seconds(timeout_seconds == 0 ? interval_seconds * 3 : timeout_seconds);
    // Reset the liveness baseline + the one-shot dead latch so re-enabling on a
    // reconnect starts fresh.
    last_pong_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                        std::memory_order_relaxed);
    peer_dead_latched_.store(false, std::memory_order_release);
    schedule_keepalive_tick();
    util::Logger::info("TunnelManager: keepalive enabled (interval={}s, timeout={}s)",
                       interval_seconds, static_cast<uint32_t>(keepalive_timeout_.count()));
}

void TunnelManager::disable_keepalive() {
    if (keepalive_active_.exchange(false, std::memory_order_acq_rel)) {
        keepalive_timer_.cancel();
    }
}

void TunnelManager::schedule_keepalive_tick() {
    keepalive_active_.store(true, std::memory_order_release);
    keepalive_timer_.expires_after(keepalive_interval_);
    // weak_ptr capture so a teardown racing a dispatched tick bails gracefully
    // (mirrors the reaper).
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    keepalive_timer_.async_wait([weak](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        auto self = weak.lock();
        if (!self || !self->keepalive_active_.load(std::memory_order_acquire)) {
            return;
        }

        // Liveness check: if no PONG within the timeout, declare the peer dead.
        const int64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        const int64_t last_ns = self->last_pong_ns_.load(std::memory_order_relaxed);
        const int64_t timeout_ns = std::chrono::nanoseconds(self->keepalive_timeout_).count();
        if (last_ns > 0 && now_ns - last_ns > timeout_ns) {
            if (!self->peer_dead_latched_.exchange(true, std::memory_order_acq_rel)) {
                util::Logger::warn(
                    "TunnelManager: keepalive — no PONG for >{}s, declaring peer dead",
                    static_cast<int64_t>(self->keepalive_timeout_.count()));
                std::function<void()> cb;
                {
                    std::lock_guard<std::mutex> lock(self->handler_mutex_);
                    cb = self->on_peer_dead_;
                }
                if (cb) {
                    cb();
                }
            }
            // Stop pinging a peer we've given up on; re-enable on reconnect.
            self->keepalive_active_.store(false, std::memory_order_release);
            return;
        }

        // Send a PING and re-arm. send_frame is a no-op-ish false when the peer
        // is unreachable; we keep the timer running so the timeout still trips.
        ProtocolFrame ping = ProtocolFrame::make_ping();
        self->send_frame(ping);
        self->schedule_keepalive_tick();
    });
}

// ===========================================================================
// Tunnel ID allocation
// ===========================================================================

std::optional<uint16_t> TunnelManager::allocate_tunnel_id() {
    std::unique_lock lock(mutex_);
    return find_available_id();
}

std::optional<uint16_t> TunnelManager::find_available_id() {
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

    // Every id in [1, 65535] is in use. Return nullopt so the caller refuses
    // the new tunnel instead of falling back to id 0 (the control-plane id).
    util::Logger::error("TunnelManager: no available tunnel IDs");
    return std::nullopt;
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

bool TunnelManager::add_tunnel(uint16_t tunnel_id, std::shared_ptr<Tunnel> tunnel) {
    if (!tunnel) {
        util::Logger::warn("TunnelManager::add_tunnel: null tunnel for id {}", tunnel_id);
        return false;
    }

    TunnelCreatedCallback created_cb;

    {
        std::unique_lock lock(mutex_);

        // Check if we're at the limit
        if (tunnels_.size() >= max_tunnels_ && tunnels_.find(tunnel_id) == tunnels_.end()) {
            util::Logger::warn("TunnelManager: max tunnels ({}) reached, cannot add tunnel {}",
                               max_tunnels_, tunnel_id);
            return false;
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
    return true;
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
    auto allocated = allocate_tunnel_id();
    if (!allocated) {
        util::Logger::error("TunnelManager::create_tunnel: failed to allocate tunnel ID");
        return 0;
    }
    const uint16_t tunnel_id = *allocated;

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
    const auto outcome = handler(wire);
    if (outcome == SendOutcome::PermanentFail) {
        util::Logger::warn("TunnelManager::create_tunnel: failed to send TUNNEL_OPEN for {}",
                           tunnel_id);
        release_tunnel_id(tunnel_id);
        return 0;
    }
    // outcome == Sent OR SendqFull: in the SendqFull case the frame is now
    // in toxcore's local queue but not yet on the wire; the caller treats
    // both as "open in flight".

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
            case FrameType::Unknown:
                // Forward-compat: an unrecognised opcode deserialises to
                // Unknown. Silently ignore it on the control plane rather than
                // logging a warn per frame — a newer peer rolling out a new
                // tunnel_id==0 opcode must not flood an older peer's log.
                break;
            default:
                util::Logger::warn("TunnelManager: unexpected control frame type: {}",
                                   to_string(frame.type()));
                break;
        }
        return;
    }

    // Route to the appropriate tunnel. Hold the shared_ptr (not a raw
    // Tunnel*) across the unlocked handle_frame() call so that a racing
    // close_all() / remove_tunnel() cannot destroy the Tunnel before
    // handle_frame returns (C-20 in the 2026-05-20 review). The map
    // already stores shared_ptr<Tunnel>; a local copy is the cheap fix.
    std::shared_ptr<Tunnel> tunnel;
    {
        std::shared_lock lock(mutex_);
        auto it = tunnels_.find(tid);
        if (it != tunnels_.end()) {
            tunnel = it->second;
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

    // C-07: tunnel id 0 is the control-plane id (PING/PONG). A peer must never
    // open a data tunnel on it; reject without touching the reserved slot.
    if (tunnel_id == 0) {
        util::Logger::warn("TunnelManager: rejecting incoming open on reserved tunnel id 0");
        return false;
    }

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

        // Check if tunnel ID is already in use. Test used_ids_ too, not just
        // tunnels_: handle_incoming_open reserves the id here but the matching
        // tunnels_ entry is only inserted later by add_tunnel(). Two TUNNEL_OPENs
        // for the same id arriving back-to-back would both pass a tunnels_-only
        // check (the map is still empty for that id) and both reserve it,
        // producing a brief double-acceptance. The reservation bitmap closes
        // that window.
        if (tunnels_.find(tunnel_id) != tunnels_.end() || used_ids_[tunnel_id]) {
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

namespace {
// Cap on parked-outbound frames per manager. With 1366-byte Tox MTU, 4096
// frames is ~5 MiB worst case — bounded but generous enough to weather a
// realistic burst (toxcore's lossless SENDQ is ~1024 packets, so 4× headroom).
constexpr std::size_t kMaxPendingOutbound = 4096;
// How long to wait before retrying a SENDQ-full drain. Tuned to be longer
// than one tox_iterate cycle (~50ms default interval) so the queue has a
// real chance to drain, but short enough that the OPEN_ACK round-trip
// budget under stress stays bounded.
constexpr auto kPendingDrainDelay = std::chrono::milliseconds(20);
}  // namespace

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

    // Best-effort FIFO: if anything is parked in pending_outbound_ already,
    // this frame queues *behind* it. The strict guarantee only holds for
    // serial callers; a concurrent send_frame can still slip past a drain
    // that already popped the only parked entry (it observes empty queue
    // between pop and handler call). This is acceptable for the frames
    // that route through send_frame today — PING/PONG and TUNNEL_OPEN_ACK
    // / TUNNEL_ERROR have no required relative order across tunnels, and
    // within a tunnel each of those is emitted at most once. Per-tunnel
    // TUNNEL_DATA / TUNNEL_CLOSE go through the per-tunnel callback path
    // and never traverse this queue.
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        if (!pending_outbound_.empty()) {
            if (pending_outbound_.size() >= kMaxPendingOutbound) {
                pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
                util::Logger::warn(
                    "TunnelManager::send_frame: pending queue at cap ({}); dropping frame",
                    kMaxPendingOutbound);
                return false;
            }
            pending_outbound_.push_back(std::move(wire));
            pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
            arm_pending_drain_timer_locked();
            return true;
        }
    }

    const SendOutcome outcome = handler(wire);

    if (outcome == SendOutcome::Sent) {
        record_frame_sent();
        record_bytes_sent(frame.serialized_size());
        return true;
    }
    if (outcome == SendOutcome::PermanentFail) {
        // Peer disconnected, frame malformed, etc. Retrying would either burn
        // CPU or, on the client under multi-server failover, eventually
        // replay against the wrong server. Surface the failure.
        return false;
    }

    // SendqFull. Park the frame and retry on the drain timer instead of
    // dropping. record_frame_sent / record_bytes_sent fire only after the
    // parked frame actually goes out (in drain_pending_outbound), so the
    // stats reflect wire activity.
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (pending_outbound_.size() >= kMaxPendingOutbound) {
        pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
        util::Logger::warn(
            "TunnelManager::send_frame: pending queue at cap ({}); dropping frame",
            kMaxPendingOutbound);
        return false;
    }
    pending_outbound_.push_back(std::move(wire));
    pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
    util::Logger::debug(
        "TunnelManager::send_frame: SENDQ-full, parked frame (queue depth={})",
        pending_outbound_.size());
    arm_pending_drain_timer_locked();
    return true;
}

bool TunnelManager::queue_outbound_for_retry(std::vector<uint8_t> wire) {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (pending_outbound_.size() >= kMaxPendingOutbound) {
        pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
        util::Logger::warn(
            "TunnelManager::queue_outbound_for_retry: queue at cap ({}); dropping",
            kMaxPendingOutbound);
        return false;
    }
    pending_outbound_.push_back(std::move(wire));
    pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
    util::Logger::debug(
        "TunnelManager::queue_outbound_for_retry: parked frame (queue depth={})",
        pending_outbound_.size());
    arm_pending_drain_timer_locked();
    return true;
}

void TunnelManager::arm_pending_drain_timer_locked() {
    // Caller holds `pending_mutex_`. Idempotent: a single retry tick is
    // enough since drain_pending_outbound re-arms itself when the SENDQ
    // is still full.
    if (pending_drain_armed_ || pending_outbound_.empty()) {
        return;
    }
    pending_drain_armed_ = true;
    pending_drain_timer_.expires_after(kPendingDrainDelay);
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    pending_drain_timer_.async_wait([weak](const std::error_code& ec) {
        if (ec) {
            return;
        }
        auto self = weak.lock();
        if (!self) {
            return;
        }
        self->drain_pending_outbound();
    });
}

void TunnelManager::drain_pending_outbound() {
    SendHandler handler;
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        handler = send_handler_;
    }
    if (!handler) {
        // Handler was uninstalled between arming and firing — drop the
        // armed flag so a future send_frame can re-arm if needed.
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_drain_armed_ = false;
        return;
    }

    while (true) {
        std::vector<uint8_t> wire;
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            if (pending_outbound_.empty()) {
                pending_drain_armed_ = false;
                return;
            }
            // Pop AFTER deciding to send; if the send fails we push it back
            // to the front to preserve FIFO order.
            wire = std::move(pending_outbound_.front());
            pending_outbound_.pop_front();
        }

        const SendOutcome outcome = handler(wire);
        if (outcome == SendOutcome::Sent) {
            record_frame_sent();
            // Use the wire length directly; the parked entry is already
            // serialized so we don't have access to ProtocolFrame here.
            record_bytes_sent(wire.size());
            continue;
        }
        if (outcome == SendOutcome::PermanentFail) {
            // Friend disconnected (or worse) since the frame was parked.
            // Retrying would either spin forever or, if a switchover races
            // here, route the frame at the wrong peer. Drop and continue
            // to the next queued entry — if everything in the queue is in
            // the same shape we'll drain the whole queue in one tick.
            pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
            util::Logger::debug(
                "TunnelManager::drain_pending_outbound: permanent send failure, dropping frame");
            continue;
        }

        // SENDQ still full — push the frame back to the front of the queue
        // (preserving FIFO order with respect to any frames a concurrent
        // send_frame() pushed to the back), and re-arm the timer.
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            pending_outbound_.push_front(std::move(wire));
            pending_drain_armed_ = false;
            arm_pending_drain_timer_locked();
        }
        return;
    }
}

void TunnelManager::clear_pending_outbound() {
    std::size_t dropped = 0;
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        dropped = pending_outbound_.size();
        pending_outbound_.clear();
        pending_drain_armed_ = false;
    }
    // Cancel any outstanding timer so its handler bails on the next firing
    // (the handler also re-checks `pending_drain_armed_` and the queue, so
    // a race here just turns into a cheap no-op).
    pending_drain_timer_.cancel();
    if (dropped > 0) {
        pending_dropped_total_.fetch_add(dropped, std::memory_order_relaxed);
        util::Logger::info("TunnelManager: cleared {} pending outbound frame(s)", dropped);
    }
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
    return backpressure_threshold_.load(std::memory_order_relaxed);
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
    // Refresh the keepalive liveness deadline (M-02). No-op when keepalive is
    // disabled — last_pong_ns_ is simply never read.
    note_pong();
}

}  // namespace toxtunnel::tunnel
