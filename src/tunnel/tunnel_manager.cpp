#include "toxtunnel/tunnel/tunnel_manager.hpp"

#include <algorithm>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tunnel {

// ===========================================================================
// Outbound send-handler snapshot
// ===========================================================================

TunnelManager::SendSnapshot::SendSnapshot(TunnelManager& manager) {
    // The whole point is that the gate test and the handler copy happen under
    // ONE acquisition. Copying the handler first and checking the gate
    // afterwards (or vice versa) is the check-to-call seam this replaces: a
    // sender could otherwise ACQUIRE a copy after close_all_local() had closed
    // the gate. A copy taken BEFORE the gate closed is still valid and may
    // still be called — see close_all_local() for that residual.
    std::lock_guard<std::mutex> lock(manager.handler_mutex_);
    if (manager.send_gate_closed_) {
        gate_closed_ = true;
        return;
    }
    handler_ = manager.send_handler_;
}

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
    reaper_tick_ns_.store(std::chrono::nanoseconds(std::chrono::seconds(tick_seconds)).count(),
                          std::memory_order_relaxed);

    // Re-entering enable_reaper() while already armed is fine — the new expiry
    // replaces the old. Bump the generation so any tick already dispatched from
    // the previous arming retires instead of racing this one into a
    // double-armed timer. Generation bump and arm happen under `timer_mutex_`
    // as one step: a stale handler that is between its own epoch check and its
    // re-arm must not be able to interleave here (see timer_mutex_'s docs).
    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        schedule_reaper_tick_locked(reaper_epoch_.fetch_add(1, std::memory_order_acq_rel) + 1);
    }

    util::Logger::info("TunnelManager: idle reaper enabled (idle={}s, tick={}s)",
                       idle_timeout_seconds, tick_seconds);
}

void TunnelManager::enable_half_close_reaper(uint32_t half_close_timeout_seconds,
                                             uint32_t tick_seconds) {
    if (half_close_timeout_seconds == 0 || tick_seconds == 0) {
        return;
    }

    const auto half_close_ns =
        std::chrono::nanoseconds(std::chrono::seconds(half_close_timeout_seconds)).count();
    reaper_half_close_timeout_ns_.store(static_cast<int64_t>(half_close_ns),
                                        std::memory_order_relaxed);
    reaper_tick_ns_.store(std::chrono::nanoseconds(std::chrono::seconds(tick_seconds)).count(),
                          std::memory_order_relaxed);

    // Shares reaper_timer_ with the idle reaper. Re-arming an already-armed
    // timer just replaces the expiry — harmless when both policies are enabled
    // back-to-back at startup.
    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        schedule_reaper_tick_locked(reaper_epoch_.fetch_add(1, std::memory_order_acq_rel) + 1);
    }

    util::Logger::info("TunnelManager: half-close linger cap enabled (timeout={}s, tick={}s)",
                       half_close_timeout_seconds, tick_seconds);
}

void TunnelManager::disable_reaper() {
    // Disables BOTH maintenance policies (idle reaper + half-close cap) — they
    // share one timer. Production calls this at teardown and when a manager is
    // parked for resume.
    reaper_idle_timeout_ns_.store(0, std::memory_order_relaxed);
    reaper_half_close_timeout_ns_.store(0, std::memory_order_relaxed);
    // Retire the generation BEFORE cancelling: a handler already dispatched on
    // the io_context is past `operation_aborted` and will only be stopped by
    // the epoch gate, so the gate has to be closed first. Both steps run under
    // `timer_mutex_` so a stale handler cannot re-arm between them (and so we
    // are not touching the timer object concurrently with an arming thread).
    std::lock_guard<std::mutex> lock(timer_mutex_);
    reaper_epoch_.fetch_add(1, std::memory_order_acq_rel);
    if (reaper_active_.exchange(false, std::memory_order_acq_rel)) {
        reaper_timer_.cancel();
    }
}

bool TunnelManager::reaper_epoch_current(std::uint64_t epoch) const noexcept {
    return reaper_epoch_.load(std::memory_order_acquire) == epoch;
}

std::uint64_t TunnelManager::reaper_epoch() const noexcept {
    return reaper_epoch_.load(std::memory_order_acquire);
}

void TunnelManager::rearm_reaper_after_tick(std::uint64_t epoch) {
    // The whole point of this function: the generation check and the arm are
    // ONE critical section. Splitting them (the previous shape — check the
    // epoch, then call an unconditional schedule_*_tick) let a stale handler
    // that had already passed its check be preempted by disable_*() +
    // enable_*(), and then overwrite the successor's wait with its own retired
    // one. `expires_after` cancels the pending wait, so the successor's handler
    // fired with operation_aborted and the stale wait was refused at the entry
    // gate: no live chain at all.
    std::lock_guard<std::mutex> lock(timer_mutex_);
    if (!reaper_epoch_current(epoch)) {
        return;
    }
    const bool maintenance_on = reaper_idle_timeout_ns_.load(std::memory_order_relaxed) > 0 ||
                                reaper_half_close_timeout_ns_.load(std::memory_order_relaxed) > 0;
    if (!maintenance_on) {
        // Only the live generation may clear the armed flag; a retired one
        // would otherwise stomp a freshly armed successor. Guaranteed here by
        // the epoch check above plus the lock.
        reaper_active_.store(false, std::memory_order_release);
        return;
    }
    schedule_reaper_tick_locked(epoch);
}

void TunnelManager::schedule_reaper_tick_locked(std::uint64_t epoch) {
    reaper_active_.store(true, std::memory_order_release);
    reaper_timer_.expires_after(
        std::chrono::nanoseconds(reaper_tick_ns_.load(std::memory_order_relaxed)));
    // S17 / 2026-05-20 follow-up: weak_ptr capture so the handler
    // gracefully bails out if the manager was destroyed between
    // `cancel()` (non-blocking) and dispatch.
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    reaper_timer_.async_wait([weak, epoch](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        auto self = weak.lock();
        if (!self) {
            return;  // Manager was destroyed before the timer fired.
        }
        // Generation gate: disable_reaper() may have run after this handler was
        // dispatched but before it got to execute. The timeout re-reads below
        // would catch a plain disable, but not a disable immediately followed by
        // an enable (the resume pause/resurrect sequence) — that would leave two
        // live tick chains on one timer.
        if (!self->reaper_epoch_current(epoch)) {
            return;
        }
        // Stash & re-read the timeouts: disable_reaper() may have raced in.
        // Either maintenance policy keeps the timer alive.
        const bool maintenance_on =
            self->reaper_idle_timeout_ns_.load(std::memory_order_relaxed) > 0 ||
            self->reaper_half_close_timeout_ns_.load(std::memory_order_relaxed) > 0;
        if (!maintenance_on) {
            self->reaper_active_.store(false, std::memory_order_release);
            return;
        }

        // Unlocked: reap_idle_tunnels_once() runs tunnel teardown, which
        // re-enters application callbacks (and can disable us). `timer_mutex_`
        // is a leaf and must never be held across it.
        self->reap_idle_tunnels_once(epoch);

        // Re-check the generation and re-arm as ONE step.
        self->rearm_reaper_after_tick(epoch);
    });
}

std::size_t TunnelManager::reap_idle_tunnels_once(std::uint64_t epoch) {
    const int64_t idle_timeout_ns = reaper_idle_timeout_ns_.load(std::memory_order_relaxed);
    const int64_t half_close_ns = reaper_half_close_timeout_ns_.load(std::memory_order_relaxed);
    if (idle_timeout_ns <= 0 && half_close_ns <= 0) {
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
            const Tunnel::State st = impl->state();
            if (st == Tunnel::State::Connecting) {
                continue;
            }
            const int64_t idle = impl->IdleNanos();
            // General idle reaper (opt-in): reaps any non-Connecting tunnel.
            const bool idle_reap = idle_timeout_ns > 0 && idle >= idle_timeout_ns;
            // Half-close linger cap (on by default): reaps only tunnels stuck in
            // Disconnecting. IdleNanos (not time-since-Disconnecting) so a still-
            // active one-way tail transfer keeps the tunnel alive — handle_tunnel
            // _data_frame accepts DATA in Disconnecting and bumps activity.
            const bool half_close_reap =
                half_close_ns > 0 && st == Tunnel::State::Disconnecting && idle >= half_close_ns;
            if (idle_reap || half_close_reap) {
                to_close.push_back(id);
            }
        }
    }

    std::size_t closed = 0;
    for (uint16_t id : to_close) {
        // close_for_timeout() first: it books the close as reason="timeout"
        // instead of "local", and — for a tunnel stuck in Disconnecting — tells
        // the peer explicitly, so the linger cap does not trade our fd leak for
        // one on the far side. remove_tunnel() then erases the entry; its own
        // close() call is a no-op once we are already Closed, and it is a no-op
        // on IDs that vanished between the scan and now.
        std::shared_ptr<Tunnel> doomed;
        {
            std::shared_lock lock(mutex_);
            auto it = tunnels_.find(id);
            if (it != tunnels_.end()) {
                doomed = it->second;
            }
        }
        if (!doomed) {
            continue;
        }
        // Re-check the generation before each close, not just once per pass:
        // this loop runs unlocked (it must — close paths re-enter application
        // callbacks), so a disable+enable can land in the middle of it. Without
        // this, a retired pass could keep reaping tunnels belonging to a
        // manager that has since been resumed.
        if (epoch != kAnyReaperEpoch && !reaper_epoch_current(epoch)) {
            break;
        }
        if (auto* impl = dynamic_cast<TunnelImpl*>(doomed.get())) {
            impl->close_for_timeout();
        }
        // Name the tunnel we actually reaped. `has_tunnel(id)` followed by an
        // id-only remove_tunnel(id) was check-then-act across an unlocked
        // close: the reap can release the id and a replacement can take it
        // before the removal runs, and the removal would then take out the
        // replacement.
        (void)remove_tunnel_if(id, doomed.get());
        ++closed;
    }

    if (closed > 0) {
        util::Logger::info(
            "TunnelManager: maintenance closed {} tunnels (idle_timeout={}s, half_close={}s)",
            closed, idle_timeout_ns / 1'000'000'000, half_close_ns / 1'000'000'000);
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
    keepalive_interval_ns_.store(
        std::chrono::nanoseconds(std::chrono::seconds(interval_seconds)).count(),
        std::memory_order_relaxed);
    const uint32_t timeout = timeout_seconds == 0 ? interval_seconds * 3 : timeout_seconds;
    keepalive_timeout_ns_.store(std::chrono::nanoseconds(std::chrono::seconds(timeout)).count(),
                                std::memory_order_relaxed);
    // Reset the liveness baseline + the one-shot dead latch so re-enabling on a
    // reconnect starts fresh.
    last_pong_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                        std::memory_order_relaxed);
    peer_dead_latched_.store(false, std::memory_order_release);
    // New generation: retires any tick still in flight from a previous enable,
    // so re-enabling on a reconnect cannot end up with two PING chains. Bump
    // and arm under `timer_mutex_` — the "disable immediately followed by
    // enable" sequence (resume pause/resurrect) is exactly where a stale
    // handler used to squeeze in and clobber this arming.
    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        schedule_keepalive_tick_locked(keepalive_epoch_.fetch_add(1, std::memory_order_acq_rel) +
                                       1);
    }
    util::Logger::info("TunnelManager: keepalive enabled (interval={}s, timeout={}s)",
                       interval_seconds, timeout);
}

void TunnelManager::disable_keepalive() {
    // Retire the generation FIRST. `cancel()` only aborts a wait that has not
    // been dispatched yet; a handler already queued on the io_context (or one
    // mid-execution, sitting inside send_frame) sails past the abort check.
    // Before the epoch gate existed, such a handler still emitted its PING and
    // then called schedule_keepalive_tick(), which set keepalive_active_ back
    // to true — a manager that had been "stopped" (parked for resume, or
    // abandoned by close_all_local) kept pinging the peer indefinitely.
    std::lock_guard<std::mutex> lock(timer_mutex_);
    keepalive_epoch_.fetch_add(1, std::memory_order_acq_rel);
    if (keepalive_active_.exchange(false, std::memory_order_acq_rel)) {
        keepalive_timer_.cancel();
    }
}

bool TunnelManager::keepalive_epoch_current(std::uint64_t epoch) const noexcept {
    return keepalive_epoch_.load(std::memory_order_acquire) == epoch;
}

std::uint64_t TunnelManager::keepalive_epoch() const noexcept {
    return keepalive_epoch_.load(std::memory_order_acquire);
}

void TunnelManager::rearm_keepalive_after_tick(std::uint64_t epoch) {
    // Generation check + arm as one indivisible step; see
    // rearm_reaper_after_tick() for the interleaving this closes.
    std::lock_guard<std::mutex> lock(timer_mutex_);
    if (!keepalive_epoch_current(epoch)) {
        return;
    }
    schedule_keepalive_tick_locked(epoch);
}

void TunnelManager::schedule_keepalive_tick_locked(std::uint64_t epoch) {
    keepalive_active_.store(true, std::memory_order_release);
    keepalive_timer_.expires_after(
        std::chrono::nanoseconds(keepalive_interval_ns_.load(std::memory_order_relaxed)));
    // weak_ptr capture so a teardown racing a dispatched tick bails gracefully
    // (mirrors the reaper).
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    keepalive_timer_.async_wait([weak, epoch](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        auto self = weak.lock();
        if (!self) {
            return;
        }
        // Gate 1 — entry. Everything below this point sends or re-arms, so a
        // retired generation must stop here.
        if (!self->keepalive_epoch_current(epoch) ||
            !self->keepalive_active_.load(std::memory_order_acquire)) {
            return;
        }

        // Liveness check: if no PONG within the timeout, declare the peer dead.
        const int64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        const int64_t last_ns = self->last_pong_ns_.load(std::memory_order_relaxed);
        const int64_t timeout_ns = self->keepalive_timeout_ns_.load(std::memory_order_relaxed);
        if (last_ns > 0 && now_ns - last_ns > timeout_ns) {
            if (!self->peer_dead_latched_.exchange(true, std::memory_order_acq_rel)) {
                util::Logger::warn(
                    "TunnelManager: keepalive — no PONG for >{}s, declaring peer dead",
                    timeout_ns / 1'000'000'000);
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
            // Only if we are still the live generation — on_peer_dead_ runs
            // application code that routinely calls enable_keepalive() on a
            // replacement session, and clearing the flag then would silently
            // stop the successor's chain. Under `timer_mutex_` so the check and
            // the store cannot straddle a concurrent enable_keepalive().
            {
                std::lock_guard<std::mutex> lock(self->timer_mutex_);
                if (self->keepalive_epoch_current(epoch)) {
                    self->keepalive_active_.store(false, std::memory_order_release);
                }
            }
            return;
        }

        // Gate 2 — before the send. The liveness branch above can invoke
        // on_peer_dead_, i.e. arbitrary application code, which may disable us.
        if (!self->keepalive_epoch_current(epoch)) {
            return;
        }

        // Send a PING and re-arm. send_frame is a no-op-ish false when the peer
        // is unreachable; we keep the timer running so the timeout still trips.
        // Deliberately outside `timer_mutex_`: send_frame reaches into
        // ToxAdapter, and `timer_mutex_` is a leaf.
        ProtocolFrame ping = ProtocolFrame::make_ping();
        self->send_frame(ping);

        // Gate 3 — the re-arm. The send handler itself is application code (it
        // reaches into ToxAdapter and, on a permanent failure, the server tears
        // the manager down), so the generation may have turned over while the
        // PING was in flight. The check and the arm are one locked step; a
        // split check-then-arm is precisely the H-1 race.
        self->rearm_keepalive_after_tick(epoch);
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
    //
    // Distinguish "genuinely full" from "reserved but not registered". Ids stay
    // reserved across a teardown until the tunnel discharges its TUNNEL_CLOSE
    // obligation (see remove_tunnel_if), so a teardown that never resolves shows
    // up here as exhaustion rather than as a hang. The gap also counts ids that
    // are merely mid-registration (handle_incoming_open reserves before
    // add_tunnel inserts), so it is deliberately NOT labelled as stuck work —
    // only a gap that stays high over time is.
    const std::size_t registered = tunnels_.size();
    util::Logger::error(
        "TunnelManager: no available tunnel IDs ({} registered; {} reserved but unregistered). "
        "A reserved-but-unregistered count that stays high is a stuck close obligation; a "
        "transient one is normal (ids are reserved before registration and released after "
        "teardown).",
        registered, 65535 - registered);
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
    std::shared_ptr<Tunnel> replaced;

    {
        std::unique_lock lock(mutex_);

        // Check if we're at the limit
        if (tunnels_.size() >= max_tunnels_ && tunnels_.find(tunnel_id) == tunnels_.end()) {
            util::Logger::warn("TunnelManager: max tunnels ({}) reached, cannot add tunnel {}",
                               max_tunnels_, tunnel_id);
            return false;
        }

        auto it = tunnels_.find(tunnel_id);
        if (it != tunnels_.end()) {
            // Replace path. In production both callers reserve a free id before
            // calling add_tunnel (server: handle_incoming_open rejects in-use
            // ids; client: allocate_tunnel_id), so this is defensive. Pull the
            // old tunnel fully OUT of the map now and DON'T insert the new one
            // yet: its teardown (below, after unlock) fires on_close_ ->
            // remove_tunnel(id), and if the replacement were already in the slot
            // that callback would drop it. With the old tunnel erased and the
            // new one not yet inserted, that re-entrant remove is a clean no-op.
            // The id stays reserved in used_ids_ across the swap.
            util::Logger::debug("TunnelManager: replacing existing tunnel {}", tunnel_id);
            replaced = std::move(it->second);
            tunnels_.erase(it);
        } else {
            used_ids_[tunnel_id] = true;
            tunnels_[tunnel_id] = std::move(tunnel);
            created_cb = on_tunnel_created_;
        }
    }

    // Replace path: tear the old tunnel down OUTSIDE the lock (re-entrancy rule,
    // see remove_tunnel), THEN publish the replacement. force_close() releases
    // the old socket and drives it terminal without emitting TUNNEL_CLOSE — the
    // right behaviour for a reused id (a stale close could kill the peer's new
    // tunnel). force_close lives on TunnelImpl, not the abstract base.
    if (replaced) {
        if (auto* impl = dynamic_cast<TunnelImpl*>(replaced.get())) {
            impl->force_close();
        } else {
            replaced->close();
        }
        std::unique_lock lock(mutex_);
        tunnels_[tunnel_id] = std::move(tunnel);
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
    (void)remove_tunnel_impl(tunnel_id, nullptr, /*match_any=*/true);
}

bool TunnelManager::remove_tunnel_if(uint16_t tunnel_id, const Tunnel* expected) {
    if (expected == nullptr) {
        // Same contract as close_tunnel_if(): naming nothing removes nothing.
        // Callers land here when their weak_ptr has lapsed, and a destroyed
        // tunnel cannot still be registered — so anything under this id is
        // somebody else's.
        return false;
    }
    return remove_tunnel_impl(tunnel_id, expected, /*match_any=*/false);
}

bool TunnelManager::remove_tunnel_impl(uint16_t tunnel_id, const Tunnel* expected, bool match_any) {
    TunnelClosedCallback closed_cb;
    std::shared_ptr<Tunnel> doomed;

    {
        std::unique_lock lock(mutex_);

        auto it = tunnels_.find(tunnel_id);
        if (it == tunnels_.end()) {
            return false;
        }
        // Identity check under the same lock that owns the map, so a caller
        // naming a specific tunnel can never take out the replacement that
        // recycled its id.
        if (!match_any && it->second.get() != expected) {
            util::Logger::debug(
                "TunnelManager: skipping removal of tunnel {}; it now belongs to another tunnel",
                tunnel_id);
            return false;
        }

        // Snapshot + erase BEFORE running teardown. The tunnel's on_close_
        // callback may re-enter remove_tunnel(tunnel_id) synchronously — the
        // client wires it that way (src/app/tunnel_client.cpp). Erasing first
        // means that re-entry finds the slot already gone and returns a no-op,
        // instead of trying to re-lock this non-recursive shared_mutex on the
        // same thread and deadlocking. This was latent until the idle/half-close
        // reaper (the only caller that removes a still-live tunnel) was wired in.
        doomed = std::move(it->second);
        tunnels_.erase(it);
        // NOTE: used_ids_[tunnel_id] stays TRUE here. The teardown below runs
        // unlocked (it must — close paths re-enter application callbacks) and
        // can emit this tunnel's TUNNEL_CLOSE. Releasing the id now would let
        // allocate_tunnel_id() hand it to a replacement while that CLOSE was
        // still on its way out, and the CLOSE would then name the replacement.
        // The id is returned to the allocator after the teardown resolves.

        // Copy callback to invoke outside the lock
        closed_cb = on_tunnel_closed_;
    }

    // Teardown OUTSIDE the lock (see above).
    if (doomed) {
        // close() is a no-op once a tunnel is past Connected, so a tunnel caught
        // mid-half-close (Disconnecting, awaiting the peer's reciprocal
        // TUNNEL_CLOSE) would never release its local TCP fd. force_close()
        // drives it to Closed, drops the socket, and fires on_close_. A Connected
        // tunnel keeps the graceful close() (drain pending bytes + emit
        // TUNNEL_CLOSE). force_close() lives on TunnelImpl, not the abstract
        // base, so reach it via dynamic_cast (mirrors reap_idle_tunnels_once).
        // The state read below only PICKS a path; it is not a decision that has
        // to hold. force_close() claims the state word atomically and announces
        // a TUNNEL_CLOSE if what it claimed turns out to be Connected, so a
        // publication that wins between this read and that claim is still
        // announced to the peer rather than silently dropped — the ordering
        // that used to strand a peer holding our OPEN_ACK.
        //
        // close() is a no-op outside Connected, so two states need force_close()
        // to actually release anything:
        //  * Disconnecting — we sent our half-close and the peer never
        //    reciprocated; close() would leave the local TCP fd pinned.
        //  * None — an unpublished tunnel, which the server's OPEN_ACK gate
        //    leaves sitting there until its ACK is on the wire. close() would
        //    drop it from this map while its target socket stayed open and its
        //    on_close_ never fired. This is also what gives
        //    TunnelImpl::try_publish_connected() something to lose against: a
        //    removal moves the state out of None, so a publication racing it
        //    fails its compare-exchange instead of publishing a detached tunnel.
        // A Connected tunnel keeps the graceful close (drain pending bytes +
        // emit TUNNEL_CLOSE). force_close() lives on TunnelImpl, not the
        // abstract base, so reach it via dynamic_cast.
        auto* impl = dynamic_cast<TunnelImpl*>(doomed.get());

        // Hand the id release to the tunnel BEFORE tearing it down. `close()`
        // returning is not the moment the id becomes reusable: it can return
        // with the CLOSE still owed — deferred behind a backpressured coalesce
        // buffer, or handed to a send still inside the transport — and a
        // replacement taking the id then would be named by that CLOSE when it
        // finally goes out. TunnelImpl fires this when it can no longer put any
        // frame on the wire for the id, which may be during the teardown below
        // (the common case, synchronously) or later.
        std::weak_ptr<TunnelManager> weak_self = weak_from_this();
        const bool defer_release = impl != nullptr && !weak_self.expired();
        if (defer_release) {
            impl->set_on_id_releasable([weak_self, tunnel_id]() {
                // weak, never raw: this can fire long after the teardown, from
                // a coalesce timer or a send thread, by which time the manager
                // may be gone.
                if (auto self = weak_self.lock()) {
                    self->release_tunnel_id(tunnel_id);
                }
            });
        }

        const auto state = doomed->state();
        if (state == Tunnel::State::Disconnecting || state == Tunnel::State::None) {
            if (impl != nullptr) {
                impl->force_close();
            } else {
                doomed->close();
            }
        } else {
            doomed->close();
        }

        if (!defer_release) {
            // No obligation tracking available — an abstract Tunnel, or a
            // manager that is not shared-owned (test fixtures, where a deferred
            // callback could outlive the object). Release now, as before.
            release_tunnel_id(tunnel_id);
        }
    } else {
        release_tunnel_id(tunnel_id);
    }

    util::Logger::debug("TunnelManager: removed tunnel {}", tunnel_id);

    // Invoke callback outside the lock
    if (closed_cb) {
        asio::post(io_ctx_, [closed_cb, tunnel_id]() { closed_cb(tunnel_id); });
    }
    return true;
}

bool TunnelManager::close_tunnel_if(uint16_t tunnel_id, const Tunnel* expected) {
    if (expected == nullptr) {
        return false;
    }
    std::shared_ptr<Tunnel> doomed;
    {
        std::shared_lock lock(mutex_);
        auto it = tunnels_.find(tunnel_id);
        if (it == tunnels_.end() || it->second.get() != expected) {
            return false;
        }
        doomed = it->second;
    }
    // Outside the lock: close() runs the tunnel's send and close callbacks,
    // which re-enter this manager (H-01).
    doomed->close();
    return true;
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
    // An abandoned manager must not mint a tunnel, let alone emit TUNNEL_OPEN
    // on an id the peer has already recycled into a live session.
    if (outbound_muted()) {
        util::Logger::debug("TunnelManager::create_tunnel: manager is muted, refusing");
        return 0;
    }

    // Allocate an ID first
    auto allocated = allocate_tunnel_id();
    if (!allocated) {
        util::Logger::error("TunnelManager::create_tunnel: failed to allocate tunnel ID");
        return 0;
    }
    const uint16_t tunnel_id = *allocated;

    // Send TUNNEL_OPEN frame to the remote peer
    ProtocolFrame open_frame = ProtocolFrame::make_tunnel_open(tunnel_id, host, port);

    // Snapshot, not a bare handler copy: the mute check at the top of this
    // function is only an entry gate, and close_all_local() could previously
    // latch between it and the call below, letting a TUNNEL_OPEN for a recycled
    // id reach the peer's live session.
    SendSnapshot snapshot(*this);
    if (snapshot.gate_closed() || !snapshot.handler()) {
        // Abandoned session, or no send handler — cannot create a tunnel.
        release_tunnel_id(tunnel_id);
        return 0;
    }

    // Same FIFO barrier the per-tunnel senders consult: this is an OPEN, and an
    // OPEN sent past a parked stale frame for a recycled id is the exact hazard
    // the barrier exists for. Without this check the rule "OPEN is barriered"
    // would have a public exception, even though nothing in production calls
    // this entry point today.
    if (outbound_queue_busy()) {
        util::Logger::debug(
            "TunnelManager::create_tunnel: an outbound frame is still queued; refusing tunnel {}",
            tunnel_id);
        release_tunnel_id(tunnel_id);
        return 0;
    }

    auto wire = open_frame.serialize();
    const auto outcome = snapshot.handler()(wire);
    if (outcome != SendOutcome::Sent) {
        // Anything but Sent means the peer was NOT told about this id, so
        // returning it would be a lie: the caller would treat the tunnel as
        // opening and eventually release an id the peer never allocated, while
        // no retry exists to put the OPEN on the wire (this entry point builds
        // no Tunnel object, so there is no driver to retain the frame — unlike
        // TunnelImpl::open(), which does).
        //
        // The previous code accepted SendqFull with a comment claiming the
        // frame was "in toxcore's local queue". It is not: SendqFull means
        // toxcore refused it outright. SendqFull is transient, so failing here
        // leaves the caller free to call create_tunnel() again — an unrefined
        // recovery, but a truthful one.
        util::Logger::warn("TunnelManager::create_tunnel: TUNNEL_OPEN for {} not sent ({})",
                           tunnel_id,
                           outcome == SendOutcome::SendqFull ? "SENDQ full" : "permanent failure");
        release_tunnel_id(tunnel_id);
        return 0;
    }

    util::Logger::info("TunnelManager: created tunnel {} -> {}:{}", tunnel_id, host, port);

    // Record statistics
    record_frame_sent();
    record_bytes_sent(open_frame.serialized_size());

    return tunnel_id;
}

bool TunnelManager::outbound_muted() const noexcept {
    return outbound_muted_.load(std::memory_order_acquire);
}

void TunnelManager::close_all_local() {
    // Step 1 — stop this manager's own frame generators. The keepalive tick
    // emits PING and the maintenance tick can emit TUNNEL_ERROR / TUNNEL_CLOSE
    // via close_for_timeout(); both are addressed at a session the peer has
    // abandoned. Their epoch gates (see disable_keepalive) guarantee a tick
    // already dispatched cannot re-arm behind us.
    disable_keepalive();
    disable_reaper();

    // Step 2 — ONE critical section latches the mute and empties the retry
    // queue. Doing both under `pending_mutex_` is what makes the contract hold:
    // no thread can observe "muted" while frames are still parked, nor "queue
    // empty" while the mute is not yet visible. A drain already in flight holds
    // its own copy of the old send handler (it was copied before this call), so
    // clearing the queue alone would not stop it — it re-checks the latch under
    // this same mutex on every pop, and again immediately before each send.
    std::size_t dropped = 0;
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        outbound_muted_.store(true, std::memory_order_release);
        dropped = pending_outbound_.size();
        pending_outbound_.clear();
        pending_drain_armed_ = false;
    }
    if (dropped > 0) {
        pending_dropped_total_.fetch_add(dropped, std::memory_order_relaxed);
    }
    // Outside the mutex: cancel() completes inline on some backends and the
    // handler re-takes pending_mutex_.
    pending_drain_timer_.cancel();

    // Step 3 — close the manager's outbound gate.
    //
    // Dropping `send_handler_` alone was never enough: every send path copies
    // the handler out from under `handler_mutex_` and calls it after the
    // unlock, because the handler re-enters ToxAdapter and, on a permanent
    // failure, the owning server — running that under one of this class's locks
    // is the re-entrancy H-01 forbids. A sender holding a copy could therefore
    // deliver its frame after this call returned.
    //
    // The gate flag is raised in the SAME critical section that hands out
    // SendSnapshots and copies the handler, so from here on no send can be
    // AUTHORISED. It does not stop a send already authorised: a sender that
    // snapshotted the handler microseconds ago can be descheduled and start its
    // call after this returns.
    //
    // We deliberately do NOT wait for those sends. That wait deadlocks: the
    // data path holds coalesce_mutex_ across its callback, and this function
    // goes on to force_close() every tunnel, whose flush_pending_writes()
    // re-takes that same non-recursive mutex. force_close() now skips the flush
    // once the gate is closed, which defuses the re-entrant route; the wait
    // stays gone because it bought a guarantee this layer cannot honour anyway.
    // See the contract on close_all_local() for the exact residual and why
    // closing it is a design change.
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        send_gate_closed_ = true;
        send_handler_ = nullptr;
    }

    // Step 4 — detach every tunnel from the manager and release its id, then
    // (still under the same lock) close its outbound gate. The per-tunnel
    // TUNNEL_DATA path bypasses the manager entirely — it runs
    // Tunnel::on_send_to_tox straight into ToxAdapter — so the manager latch
    // cannot cover it. Doing it here means a tunnel is gated at the very
    // instant it stops being reachable through the manager, rather than in a
    // second unsynchronised pass.
    //
    // `close_outbound_gate()` replaces the old pair of callback setters, which
    // could not be made one atomic step and, worse, left a window in which a
    // sender could still ACQUIRE a callback (that is the whole reason for the
    // gate/snapshot design — see TunnelImpl::close_outbound_gate). A sender
    // that had already acquired one is outside what either design covers.
    //
    // H-01 discipline: `close_outbound_gate()` is the only thing called under
    // `mutex_`, and it is provably non-re-entrant — it takes the tunnel's own
    // `mutex_` and `coalesce_mutex_` together (one scoped_lock: the gate and
    // the terminal Abort seal are a single authority since issue #24 slice 3)
    // to raise two flags, clear the abandoned FIFO and null two
    // std::functions, then returns. It never calls back into the manager and
    // never blocks on a send. The lock order manager-mutex_ -> tunnel-mutexes
    // is the one snapshot() already uses, and no path takes them the other
    // way round.
    std::map<uint16_t, std::shared_ptr<Tunnel>> doomed;
    TunnelClosedCallback closed_cb;
    {
        std::unique_lock lock(mutex_);
        doomed.swap(tunnels_);
        for (const auto& [id, tunnel] : doomed) {
            used_ids_[id] = false;
            if (auto* impl = dynamic_cast<TunnelImpl*>(tunnel.get())) {
                impl->close_outbound_gate();
            }
        }
        closed_cb = on_tunnel_closed_;
    }

    // Step 5 — release local resources OUTSIDE `mutex_`. force_close() (rather
    // than close()) is what actually frees things: it drops the target TCP
    // socket, drives the tunnel to Closed even from Disconnecting — where
    // close() is a no-op and would leak the fd — and fires on_close_ so the
    // owning server decrements its gauges.
    //
    // Must be outside the lock: force_close() fires on_close_, which re-enters
    // the owning server (H-01). It also takes each tunnel's `coalesce_mutex_`
    // — but only for the socket/state half: because we closed every outbound
    // gate above, force_close() takes its local-abandon path and skips the
    // coalesce flush entirely. That matters when this whole call is running
    // inside a Tox send callback, which the data path invokes while holding
    // that very mutex.
    for (auto& [id, tunnel] : doomed) {
        if (!tunnel) {
            continue;
        }
        if (auto* impl = dynamic_cast<TunnelImpl*>(tunnel.get())) {
            impl->force_close();
        } else {
            tunnel->close();
        }
        if (closed_cb) {
            asio::post(io_ctx_, [closed_cb, id = id]() { closed_cb(id); });
        }
    }

    util::Logger::info(
        "TunnelManager: abandoned session locally — closed {} tunnel(s), dropped {} pending "
        "outbound frame(s); no further send can be authorised",
        doomed.size(), dropped);
}

void TunnelManager::close_all() {
    std::map<uint16_t, std::shared_ptr<Tunnel>> tunnels_to_close;
    TunnelClosedCallback closed_cb;

    {
        std::unique_lock lock(mutex_);

        // Swap out the tunnels map to close outside the lock
        tunnels_to_close.swap(tunnels_);

        // IDs stay reserved across the teardown below, for the same reason as
        // remove_tunnel_impl(): a tunnel being closed may still emit its
        // TUNNEL_CLOSE, and that frame must not be able to name a replacement.
        closed_cb = on_tunnel_closed_;
    }

    // Close all tunnels outside the lock
    for (auto& [id, tunnel] : tunnels_to_close) {
        if (tunnel) {
            // Same reasoning as remove_tunnel_impl(): close() no-ops for a
            // tunnel that is still None or already Disconnecting, which would
            // detach it here while leaving its socket open and its on_close_
            // unfired — and the id release is coupled to the tunnel discharging
            // its CLOSE obligation, not to close() returning.
            const auto state = tunnel->state();
            auto* impl = dynamic_cast<TunnelImpl*>(tunnel.get());
            std::weak_ptr<TunnelManager> weak_self = weak_from_this();
            const bool defer_release = impl != nullptr && !weak_self.expired();
            if (defer_release) {
                const uint16_t id_copy = id;
                impl->set_on_id_releasable([weak_self, id_copy]() {
                    if (auto self = weak_self.lock()) {
                        self->release_tunnel_id(id_copy);
                    }
                });
            } else {
                release_tunnel_id(id);
            }
            if (impl != nullptr &&
                (state == Tunnel::State::None || state == Tunnel::State::Disconnecting)) {
                impl->force_close();
            } else {
                tunnel->close();
            }
        } else {
            release_tunnel_id(id);
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
            // Code 2, not 1: a frame for an unknown tunnel is a routing
            // failure, not a policy denial. Code 1 now means specifically
            // "the server's configuration refused this open".
            ProtocolFrame error_frame =
                ProtocolFrame::make_tunnel_error(tid, static_cast<uint8_t>(2), "Tunnel not found");
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
            // Code 1: a capacity cap is policy, not a target failure.
            ProtocolFrame error_frame = ProtocolFrame::make_tunnel_error(
                tunnel_id, static_cast<uint8_t>(1), "Tunnel limit exceeded");
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
    // Historical contract preserved exactly: true means "queued for sending",
    // which includes "parked in pending_outbound_ for the drain timer".
    return send_frame_impl(frame, /*park_on_backpressure=*/true) == SendOutcome::Sent;
}

SendOutcome TunnelManager::send_frame_typed(const ProtocolFrame& frame) {
    return send_frame_impl(frame, /*park_on_backpressure=*/false);
}

SendOutcome TunnelManager::send_frame_impl(const ProtocolFrame& frame, bool park_on_backpressure) {
    // Cheap pre-check so a muted manager does no work at all; the authoritative
    // check happens under `pending_mutex_` below, where it is ordered against
    // close_all_local()'s queue flush.
    if (outbound_muted()) {
        return SendOutcome::PermanentFail;
    }

    // Take the snapshot BEFORE anything else: it fuses the gate test with the
    // handler copy, so close_all_local() cannot latch between them. It lives to
    // the end of the function, and holds `handler_mutex_` only inside its own
    // constructor — nothing here nests that mutex under `pending_mutex_`.
    SendSnapshot snapshot(*this);
    if (snapshot.gate_closed()) {
        return SendOutcome::PermanentFail;
    }
    const SendHandler& handler = snapshot.handler();

    if (!handler) {
        util::Logger::warn("TunnelManager::send_frame: no send handler registered");
        return SendOutcome::PermanentFail;
    }

    auto wire = frame.serialize();

    // FIFO barrier: if anything is parked in pending_outbound_, or popped and
    // mid-drain, this frame queues *behind* it. `pending_drain_in_flight_` is
    // what covers the mid-drain case — the frame has left the deque but has not
    // reached toxcore, and without it a concurrent sender observing an empty
    // queue would overtake it.
    //
    // What remains best-effort is the gap between this check and the handler
    // call below, which happens with the mutex released (it must: the handler
    // re-enters ToxAdapter). A frame parked by another thread in that gap is
    // still overtaken. That residual is purely concurrent — it needs two
    // unrelated senders racing — whereas the hazard this barrier exists for is
    // causal: a frame parked before a tunnel id is released is necessarily
    // visible to any later send for that recycled id. Closing the concurrent
    // residual too requires a single outbound owner, i.e. the driver from the
    // later slices.
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        // Authoritative mute check: same mutex close_all_local() latches under,
        // so once it has run no frame can be parked behind its flush.
        if (outbound_muted_.load(std::memory_order_relaxed)) {
            return SendOutcome::PermanentFail;
        }
        // `pending_drain_in_flight_` counts as a non-empty queue: the drain has
        // popped its entry but has not yet handed it to toxcore, so sending
        // past it here would reorder the stream just as visibly as jumping the
        // deque would.
        if (!pending_outbound_.empty() || pending_drain_in_flight_) {
            if (!park_on_backpressure) {
                // A typed caller owns its frame, so it must not overtake what is
                // already parked ahead of it. Report backpressure and let it
                // retry once the queue has drained.
                return SendOutcome::SendqFull;
            }
            if (pending_outbound_.size() >= kMaxPendingOutbound) {
                pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
                util::Logger::warn(
                    "TunnelManager::send_frame: pending queue at cap ({}); dropping frame",
                    kMaxPendingOutbound);
                return SendOutcome::PermanentFail;
            }
            pending_outbound_.push_back(std::move(wire));
            pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
            arm_pending_drain_timer_locked();
            return SendOutcome::Sent;
        }
    }

    // Cheap early-out for the common case; correctness no longer rests on it.
    // The snapshot taken at the top of this function is what forbids a send
    // from being AUTHORISED after the gate closes. (The old code had only this
    // check, one instruction before the call, and the review was right that the
    // gap it leaves is a frame per concurrently-sending tunnel.) Note this does
    // not make teardown wait: a send already authorised may still land.
    if (outbound_muted()) {
        return SendOutcome::PermanentFail;
    }

    const SendOutcome outcome = handler(wire);

    if (outcome == SendOutcome::Sent) {
        record_frame_sent();
        record_bytes_sent(frame.serialized_size());
        return SendOutcome::Sent;
    }
    if (outcome == SendOutcome::PermanentFail) {
        // Peer disconnected, frame malformed, etc. Retrying would either burn
        // CPU or, on the client under multi-server failover, eventually
        // replay against the wrong server. Surface the failure.
        return SendOutcome::PermanentFail;
    }

    // SendqFull.
    if (!park_on_backpressure) {
        // The typed caller keeps the frame and retries it itself, which is the
        // whole point: this queue would strip the tunnel identity off it.
        return SendOutcome::SendqFull;
    }

    // Park the frame and retry on the drain timer instead of dropping.
    // record_frame_sent / record_bytes_sent fire only after the parked frame
    // actually goes out (in drain_pending_outbound), so the stats reflect wire
    // activity.
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (outbound_muted_.load(std::memory_order_relaxed)) {
        // Latched while the send was in flight — do not resurrect the queue
        // close_all_local() just emptied.
        return SendOutcome::PermanentFail;
    }
    if (pending_outbound_.size() >= kMaxPendingOutbound) {
        pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
        util::Logger::warn("TunnelManager::send_frame: pending queue at cap ({}); dropping frame",
                           kMaxPendingOutbound);
        return SendOutcome::PermanentFail;
    }
    pending_outbound_.push_back(std::move(wire));
    pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
    util::Logger::debug("TunnelManager::send_frame: SENDQ-full, parked frame (queue depth={})",
                        pending_outbound_.size());
    arm_pending_drain_timer_locked();
    return SendOutcome::Sent;
}

namespace {

/// Frame types whose backpressure retry belongs to a driver (the tunnel, the
/// server's OPEN_ACK gate, or the per-tunnel coalesce buffer) rather than to
/// this manager's queue.
bool driver_owns_retry(FrameType type) noexcept {
    switch (type) {
        case FrameType::TUNNEL_OPEN:
        case FrameType::TUNNEL_ACK:
        case FrameType::TUNNEL_DATA:
            return true;
        default:
            return false;
    }
}

}  // namespace

SendOutcome route_sendq_full(TunnelManager& manager, std::span<const std::uint8_t> wire) {
    if (wire.empty()) {
        // Not a frame at all; nothing sensible to retry.
        return SendOutcome::PermanentFail;
    }

    // ProtocolFrame layout: [type:1][tunnel_id:2][length:2]. See the header for
    // why each class of frame is routed the way it is.
    if (driver_owns_retry(static_cast<FrameType>(wire[0]))) {
        // Reporting the backpressure verbatim is the whole point of the typed
        // seam: the caller still owns the frame.
        return SendOutcome::SendqFull;
    }

    return manager.queue_outbound_for_retry(std::vector<std::uint8_t>(wire.begin(), wire.end()))
               ? SendOutcome::Sent
               : SendOutcome::PermanentFail;
}

bool frame_must_respect_outbound_barrier(FrameType type) noexcept {
    // OPEN and OPEN_ACK only. These are the identity-carrying handshake frames
    // this slice moved to driver ownership, and they are what the recycled-id
    // hazard turns on: holding an OPEN behind a parked CLOSE for the same id
    // restores close-then-open ordering at the peer.
    //
    // TUNNEL_DATA is deliberately NOT here, and does not need to be. DATA only
    // flows once the tunnel is Connected, which on the client requires its OPEN
    // to have been sent and ACKed and on the server requires the OPEN_ACK to
    // have been sent — both of which are barriered — so DATA is already ordered
    // behind them transitively. Adding DATA would instead stall a live stream
    // behind an unrelated parked PING for up to a drain interval.
    //
    // CLOSE / ERROR / PING / PONG / INFO / RESUME are not here either: they are
    // still owned by TunnelManager's retry queue, and a direct send of one that
    // toxcore happens to accept can still overtake a parked frame. That is the
    // documented residual of leaving them parked, and it goes away when they
    // move to driver ownership (see route_sendq_full's contract).
    return type == FrameType::TUNNEL_OPEN || type == FrameType::TUNNEL_ACK;
}

bool TunnelManager::outbound_queue_busy() const {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    return !pending_outbound_.empty() || pending_drain_in_flight_;
}

bool TunnelManager::queue_outbound_for_retry(std::vector<uint8_t> wire) {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (outbound_muted_.load(std::memory_order_relaxed)) {
        // The per-tunnel senders park their SENDQ-full frames here. For an
        // abandoned session those frames are addressed at recycled ids, so
        // they must be dropped rather than retried.
        return false;
    }
    if (pending_outbound_.size() >= kMaxPendingOutbound) {
        pending_dropped_total_.fetch_add(1, std::memory_order_relaxed);
        util::Logger::warn("TunnelManager::queue_outbound_for_retry: queue at cap ({}); dropping",
                           kMaxPendingOutbound);
        return false;
    }
    pending_outbound_.push_back(std::move(wire));
    pending_enqueued_total_.fetch_add(1, std::memory_order_relaxed);
    util::Logger::debug("TunnelManager::queue_outbound_for_retry: parked frame (queue depth={})",
                        pending_outbound_.size());
    arm_pending_drain_timer_locked();
    return true;
}

void TunnelManager::arm_pending_drain_timer_locked() {
    // Caller holds `pending_mutex_`. Idempotent: a single retry tick is
    // enough since drain_pending_outbound re-arms itself when the SENDQ
    // is still full.
    if (pending_drain_armed_ || pending_outbound_.empty() ||
        outbound_muted_.load(std::memory_order_relaxed)) {
        return;
    }
    // The drain callback captures `weak_from_this()`. When the manager is
    // not held by a shared_ptr (e.g. test fixtures that allocate via
    // `std::unique_ptr<TunnelManager>` or stack-construct one), the weak
    // pointer is empty and the callback would just bail when it eventually
    // fires. Avoid arming the timer in that case: the outstanding
    // async_wait would otherwise force the io_context destructor to
    // service one pending op, which on the Windows IOCP backend was
    // observed to stall the unit_tests process indefinitely on the
    // windows-x86_64 CI runner. Production paths always own the manager
    // via shared_ptr so this branch is purely a test-safety guard.
    std::weak_ptr<TunnelManager> weak = weak_from_this();
    if (weak.expired()) {
        return;
    }
    pending_drain_armed_ = true;
    pending_drain_timer_.expires_after(kPendingDrainDelay);
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
    // One snapshot for the whole drain. close_all_local() does NOT wait for this
    // loop; the per-iteration mute re-check below is what stops it, so a drain
    // that was already running when the session was abandoned emits at most the
    // frame it had already popped.
    SendSnapshot snapshot(*this);
    if (snapshot.gate_closed()) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_outbound_.clear();
        pending_drain_armed_ = false;
        return;
    }
    const SendHandler& handler = snapshot.handler();
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
            // Re-check the mute on EVERY iteration, under the same mutex
            // close_all_local() latches it with. `handler` above is a copy
            // taken before the latch, so this is the only thing that stops a
            // drain that was already running when the session was abandoned.
            if (outbound_muted_.load(std::memory_order_relaxed)) {
                pending_outbound_.clear();
                pending_drain_armed_ = false;
                return;
            }
            if (pending_outbound_.empty()) {
                pending_drain_armed_ = false;
                return;
            }
            // Pop AFTER deciding to send; if the send fails we push it back
            // to the front to preserve FIFO order.
            wire = std::move(pending_outbound_.front());
            pending_outbound_.pop_front();
            // Keep the barrier closed across the unlocked transport call: the
            // frame has left the deque but has not reached toxcore, and a
            // concurrent sender that saw an empty queue would overtake it.
            pending_drain_in_flight_ = true;
        }

        // Clear the in-flight barrier on EVERY exit from this iteration — the
        // two `continue`s, the SENDQ-full `return` and the muted-latch `return`
        // below. A missed clear would latch the barrier shut for the manager's
        // lifetime and turn every later typed send into a permanent SendqFull,
        // so this is RAII rather than four hand-written resets.
        struct DrainInFlightGuard {
            TunnelManager* manager;
            ~DrainInFlightGuard() {
                std::lock_guard<std::mutex> lock(manager->pending_mutex_);
                manager->pending_drain_in_flight_ = false;
            }
        } in_flight_guard{this};

        // The frame is now out of the queue and off the mutex; if the latch
        // landed in between, drop it here rather than putting it on the wire.
        // Best-effort: close_all_local() does NOT wait for this loop, so this
        // re-check is the only thing that stops a drain already in flight.
        if (outbound_muted()) {
            return;
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
