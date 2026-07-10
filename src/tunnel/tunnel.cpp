#include "toxtunnel/tunnel/tunnel.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::tunnel {

namespace {

// tox custom lossless packets max out at 1373 bytes. Our tunnel framing adds
// a 1-byte tox packet prefix and a 5-byte tunnel frame header, leaving 1367
// bytes for raw TCP payload per frame.
constexpr std::size_t kMaxTcpPayloadPerToxFrame = 1367;
constexpr auto kAckRetryDelay = std::chrono::milliseconds(1);

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
      last_activity_ns_(std::chrono::steady_clock::now().time_since_epoch().count()),
      coalesce_timer_(io_ctx),
      ack_retry_timer_(io_ctx) {
    util::Logger::debug("Tunnel created: id={}, friend={}, window={}", tunnel_id_, friend_number_,
                        send_window_size_);
}

TunnelImpl::~TunnelImpl() {
    // Cancel pending timer waits; already-dispatched handlers capture weak_ptr
    // and bail out if destruction won the race.
    coalesce_timer_.cancel();
    ack_retry_timer_.cancel();
    util::Logger::debug("Tunnel destroyed: id={}", tunnel_id_);
}

// ===========================================================================
// Accessors
// ===========================================================================

std::string TunnelImpl::target_host() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return target_host_;
}

void TunnelImpl::set_target(const std::string& host, std::uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    target_host_ = host;
    target_port_ = port;
}

uint16_t TunnelImpl::target_port() const noexcept {
    return target_port_;
}

std::chrono::steady_clock::time_point TunnelImpl::last_activity() const {
    return std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(last_activity_ns_.load(std::memory_order_relaxed)));
}

int64_t TunnelImpl::IdleNanos() const noexcept {
    const int64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const int64_t last_ns = last_activity_ns_.load(std::memory_order_relaxed);
    return now_ns - last_ns;
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

    // H-08: the wire host_len field is a single byte. Reject an overlong host
    // here instead of letting make_tunnel_open silently truncate it and dial a
    // prefix of the intended target (a real DNS name is <= 253 bytes, so this
    // only fires on a malformed rule / proxy request).
    if (host.size() > 255) {
        util::Logger::error("Tunnel {} open rejected: host length {} exceeds 255-byte limit",
                            tunnel_id_, host.size());
        return false;
    }

    // M-08: record target + move to Connecting BEFORE sending TUNNEL_OPEN, so a
    // synchronous send callback or a fast ACK observes a coherent target and
    // state (the old order left a window where state was still None / target
    // empty). On send failure we roll back to None so the caller can release
    // the id without the tunnel lingering in Connecting.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        target_host_ = host;
        target_port_ = port;
    }
    transition_state(State::Connecting);

    auto frame = ProtocolFrame::make_tunnel_open(tunnel_id_, host, port);
    if (!send_frame_to_tox(frame)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            target_host_.clear();
            target_port_ = 0;
        }
        transition_state(State::None);
        util::Logger::warn("Tunnel {} open failed: initial TUNNEL_OPEN send rejected", tunnel_id_);
        return false;
    }

    util::Logger::info("Tunnel {} opening: {}:{}", tunnel_id_, host, port);
    return true;
}

void TunnelImpl::close() {
    State current = state_.load(std::memory_order_acquire);

    // C-05: close requested while the open handshake is still in flight (the
    // local TCP side disconnected before the peer ACKed our TUNNEL_OPEN).
    // Without handling this, the tunnel stays in Connecting forever — the
    // reaper deliberately skips Connecting tunnels — leaking both the object
    // and its tunnel id. Send a best-effort TUNNEL_CLOSE so the peer can
    // release its half, then move straight to Closed and notify so the manager
    // reclaims the id. No coalesce buffer can hold data here (send_data_to_tox
    // refuses while not Connected), so there is nothing to drain.
    if (current == State::Connecting) {
        auto frame = ProtocolFrame::make_tunnel_close(tunnel_id_);
        send_frame_to_tox(frame);
        util::MetricsRegistry::instance().inc_tunnels_closed(
            util::MetricsRegistry::CloseReason::Local);
        transition_state(State::Closed);
        notify_close_once();
        util::Logger::info("Tunnel {} closed during handshake", tunnel_id_);
        return;
    }

    // Only close from Connected state (None/Disconnecting/Closed/Error: no-op).
    if (current != State::Connected) {
        util::Logger::debug("Tunnel {} close ignored: state {}", tunnel_id_, to_string(current));
        return;
    }

    // Drain pending coalesced data before signalling close so the peer
    // observes every byte we accepted. If Tox backpressures mid-drain, DEFER
    // the TUNNEL_CLOSE: emitting it now would let it overtake the still-buffered
    // DATA, and the peer drops post-close frames as "unknown tunnel" (the
    // close-before-drain truncation bug). The retry timer sends CLOSE once the
    // buffer is fully drained — see the timer handler in coalesce_arm_timer_locked.
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (!coalesce_try_drain_locked()) {
            close_pending_ = true;
            close_pending_full_ = true;
            coalesce_arm_timer_locked();
            util::Logger::debug("Tunnel {} close deferred until coalesce buffer drains",
                                tunnel_id_);
            return;
        }
    }

    emit_close_and_transition();
}

void TunnelImpl::emit_close_and_transition() {
    bool should_send_close = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (!local_close_sent_) {
            local_close_sent_ = true;
            local_stream_done_ = true;
            should_send_close = true;
        }
    }

    if (should_send_close) {
        auto frame = ProtocolFrame::make_tunnel_close(tunnel_id_);
        send_frame_to_tox(frame);
        util::MetricsRegistry::instance().inc_tunnels_closed(
            util::MetricsRegistry::CloseReason::Local);
    }

    // Transition to Disconnecting state
    transition_state(State::Disconnecting);

    util::Logger::info("Tunnel {} closing", tunnel_id_);

    // The buffer is fully drained and CLOSE has been emitted — it is now safe
    // for the owner to tear the tunnel down. Firing this only here (rather than
    // when close() is first requested) is what lets a backpressured tunnel
    // finish flushing its data before removal, instead of dropping it. The
    // callback is responsible for deferring the actual teardown (asio::post)
    // so it never destroys this tunnel mid-call.
    notify_close_once();
}

void TunnelImpl::emit_local_close_only() {
    auto frame = ProtocolFrame::make_tunnel_close(tunnel_id_);
    send_frame_to_tox(frame);
    util::MetricsRegistry::instance().inc_tunnels_closed(util::MetricsRegistry::CloseReason::Local);
    transition_state(State::Disconnecting);
    util::Logger::info("Tunnel {} sent local half-close", tunnel_id_);
}

bool TunnelImpl::flush_pending_tcp_input() {
    for (;;) {
        std::vector<std::uint8_t> chunk;
        {
            std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
            const std::size_t pending = pending_tcp_pending_locked();
            if (pending == 0) {
                return true;
            }

            std::size_t effective_window = send_window_size_;
            if (flow_control_configured_.load(std::memory_order_acquire)) {
                effective_window = std::max<std::size_t>(
                    send_window_size_,
                    static_cast<std::size_t>(flow_control_.target_window_bytes()));
            }

            const std::size_t used = send_window_used_.load(std::memory_order_relaxed);
            if (used >= effective_window) {
                return false;
            }

            const std::size_t send_budget = effective_window - used;
            const std::size_t to_send = std::min(send_budget, pending);
            const auto first =
                pending_tcp_input_.begin() + static_cast<std::ptrdiff_t>(pending_tcp_consumed_);
            chunk.assign(first, first + static_cast<std::ptrdiff_t>(to_send));
        }

        if (!send_data_to_tox(std::span<const std::uint8_t>(chunk.data(), chunk.size()))) {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
            // Advance the read cursor instead of erasing from the front each
            // iteration (which shifted every surviving byte — O(n) per chunk,
            // O(n^2) to drain a large backlog). Compact lazily: clear once fully
            // drained, otherwise erase the consumed prefix when it reaches at
            // least half the buffer, keeping the amortised cost O(1). Mirrors
            // coalesce_buf_/coalesce_consumed_.
            pending_tcp_consumed_ += chunk.size();
            if (pending_tcp_consumed_ >= pending_tcp_input_.size()) {
                pending_tcp_input_.clear();
                pending_tcp_consumed_ = 0;
            } else if (pending_tcp_consumed_ >= pending_tcp_pending_locked()) {
                pending_tcp_input_.erase(pending_tcp_input_.begin(),
                                         pending_tcp_input_.begin() +
                                             static_cast<std::ptrdiff_t>(pending_tcp_consumed_));
                pending_tcp_consumed_ = 0;
            }
        }
    }
}

void TunnelImpl::maybe_finish_pending_tcp_eof() {
    bool should_finish = false;
    {
        std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
        if (pending_tcp_eof_ && pending_tcp_pending_locked() == 0) {
            pending_tcp_eof_ = false;
            should_finish = true;
        }
    }

    if (should_finish) {
        on_tcp_read_eof();
    }
}

void TunnelImpl::finalize_remote_close() {
    util::MetricsRegistry::instance().inc_tunnels_closed(
        util::MetricsRegistry::CloseReason::Remote);
    transition_state(State::Closed);
    notify_close_once();
}

void TunnelImpl::force_close() {
    State current = state_.load(std::memory_order_acquire);
    if (current == State::Closed) {
        return;
    }

    flush_pending_writes();

    // Close TCP connection if any
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tcp_conn_) {
            tcp_conn_->force_close();
            tcp_conn_.reset();
        }
    }

    transition_state(State::Closed);
    // M-07: force_close() drives a terminal state just like the remote-close /
    // error paths, so it must fire the close callback too. Otherwise a caller
    // that uses force_close() directly would bypass manager cleanup and the
    // active-tunnel gauge decrement. notify_close_once() is idempotent.
    notify_close_once();
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
    const State current = state_.load(std::memory_order_acquire);
    if (current != State::Connected && current != State::Disconnecting) {
        util::Logger::debug("Tunnel {} ignored TUNNEL_DATA: not connected", tunnel_id_);
        return;
    }

    auto data = frame.as_tunnel_data();
    if (data.empty()) {
        return;
    }

    BumpActivity();

    // Update receive statistics
    std::size_t data_size = data.size();
    total_bytes_received_.fetch_add(data_size, std::memory_order_relaxed);
    bytes_received_since_ack_.fetch_add(data_size, std::memory_order_relaxed);
    util::MetricsRegistry::instance().add_bytes_in(data_size);

    // Forward data to TCP connection. Prefer the zero-copy owned-buffer
    // callback when both are set; that path hands the payload to
    // `TcpConnection::write(OwnedBufferView)` without any payload copy
    // (the buffer was allocated by `ProtocolFrame::deserialize` and stays
    // alive until the async TCP write completes via shared_ptr refcount).
    SendToTcpOwnedCallback owned_cb;
    SendToTcpCallback span_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        owned_cb = on_data_for_tcp_owned_;
        span_cb = on_data_for_tcp_;
    }

    bool accepted = true;
    if (owned_cb) {
        accepted = owned_cb(frame.as_tunnel_data_owned());
    } else if (span_cb) {
        accepted = span_cb(data);
    }

    // C-03: only ACK what the local TCP side accepted. When it backpressures
    // (write queue over its limit), withhold the ACK: the peer's send window
    // fills, it stops sending, and notify_tcp_writable() flushes the deferred
    // ACK once the socket drains. The received bytes are NOT dropped — the
    // TcpConnection still enqueues them — so the stream stays intact; we are
    // only throttling the peer instead of silently ACKing data the socket
    // couldn't keep up with.
    if (accepted) {
        maybe_send_ack();
    } else {
        util::Logger::debug("Tunnel {} local TCP backpressured; deferring ACK", tunnel_id_);
    }
}

bool TunnelImpl::notify_tcp_writable() {
    // The local TCP write queue drained below its low-water mark; flush any
    // ACK we withheld while it was backpressured so the peer's send window
    // reopens. send_ack() is a no-op (returns true) when nothing is pending;
    // it returns false if the ACK send itself backpressured, in which case the
    // tunnel retry timer keeps trying even if this was the last TCP drain event.
    return send_ack();
}

void TunnelImpl::handle_tunnel_close_frame(const ProtocolFrame& /*frame*/) {
    util::Logger::info("Tunnel {} received TUNNEL_CLOSE", tunnel_id_);

    std::shared_ptr<core::TcpConnection> conn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        conn = tcp_conn_;
    }

    bool finalize_now = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        remote_close_received_ = true;
        if (!conn) {
            local_stream_done_ = true;
        }
        if (!coalesce_try_drain_locked()) {
            remote_close_pending_ = true;
            coalesce_arm_timer_locked();
        } else if (local_stream_done_) {
            finalize_now = true;
        }
    }

    // Peer close is directional: no more TUNNEL_DATA will arrive from the
    // peer, so send TCP EOF to the local socket. Keep the read side open so
    // locally-produced bytes (for example SSH stdout) can still flow back.
    if (conn) {
        conn->shutdown_send();
    }

    if (finalize_now) {
        finalize_remote_close();
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

    // Free up send window. Capture pre- and post- values to detect a
    // window-drain transition (post == 0) that lets us close out an RTT sample.
    // Clamp the peer-supplied ack to what we have ACTUALLY emitted but not yet
    // had acked. A malicious peer that ACK-credits bytes we never put on the
    // wire could otherwise drive send_window_used_ to 0 at will, defeating the
    // only bound on coalesce_buf_ and OOMing us.
    //
    // LOCK-FREE on purpose: the coalesce drain holds coalesce_mutex_ across
    // send_frame_to_tox, and a synchronous ACK round-trip (test harness, or any
    // in-process loopback) would re-enter here on the same thread — taking
    // coalesce_mutex_ would self-deadlock. Correctness without the lock comes
    // from causality: emit stores total_bytes_emitted_ with release BEFORE the
    // bytes go on the wire, and the peer can only ACK bytes it received AFTER
    // that send, so this acquire-load always observes emitted >= the acked
    // bytes — a legitimate ACK is credited in full; only a forged over-ack is
    // clamped.
    std::size_t credited = 0;
    {
        const std::uint64_t emitted = total_bytes_emitted_.load(std::memory_order_acquire);
        std::uint64_t acked_so_far = total_bytes_acked_.load(std::memory_order_relaxed);
        for (;;) {
            const std::uint64_t outstanding = emitted > acked_so_far ? emitted - acked_so_far : 0;
            const std::uint64_t want = std::min<std::uint64_t>(payload->bytes_acked, outstanding);
            if (want == 0) {
                break;
            }
            if (total_bytes_acked_.compare_exchange_weak(acked_so_far, acked_so_far + want,
                                                         std::memory_order_relaxed)) {
                credited = static_cast<std::size_t>(want);
                break;
            }
            // CAS failed: acked_so_far refreshed; recompute against same emitted.
        }
    }
    const std::size_t acked = credited;
    std::size_t current_window = send_window_used_.load(std::memory_order_relaxed);
    std::size_t new_window = current_window;
    while (current_window > 0) {
        std::size_t new_val = current_window > acked ? current_window - acked : 0;
        if (send_window_used_.compare_exchange_weak(current_window, new_val,
                                                    std::memory_order_relaxed)) {
            new_window = new_val;
            break;
        }
    }

    // Feed BDP flow control + metrics histograms. Only meaningful when an
    // ACK actually moved bytes; the OPEN-ACK path returns earlier above.
    if (acked > 0 && flow_control_configured_.load(std::memory_order_acquire)) {
        const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();

        // Bandwidth = bytes_acked / delta_t since the previous ACK. Skip the
        // first sample (no prev_ns) and very-small intervals (avoid div-by-zero
        // and bogus huge spikes from sub-millisecond jitter).
        const auto prev_ack_ns = last_ack_ns_.exchange(now_ns, std::memory_order_relaxed);
        if (prev_ack_ns > 0) {
            const std::int64_t delta_ns = now_ns - prev_ack_ns;
            if (delta_ns > 1'000'000) {  // > 1 ms
                // C-S-2 (2026-05-20 fix-storm review): S21 protected
                // `bps * rtt` in BdpFlowControl with __int128 but left
                // the upstream `bps` producer at plain int64. `acked`
                // is uint32_t, so `acked * 1e9` reaches ~4.3e18 — inside
                // int64 today, but a single bytes_acked widening to
                // uint64 in the future, or a coalesced ACK carrying
                // more than 4 GiB, would silently wrap. Compute in
                // __int128 and clamp to a sane 100 Gbps ceiling before
                // feeding the EWMA so a hostile peer can't pump the
                // estimator with bogus values.
                constexpr std::int64_t kMaxBpsCap = 12'500'000'000LL;  // 100 Gbps
                // C-S-2 (2026-05-20) used __int128; CI-pedantic-fix
                // (2026-05-21) replaces it because MSVC has no __int128.
                // `acked` is uint32_t so `acked * 1e9` tops out at
                // ~4.3e18 < INT64_MAX with headroom — plain int64 is
                // safe. The kMaxBpsCap saturation below still handles
                // divide-by-tiny-delta_ns.
                const std::int64_t bps_raw =
                    (static_cast<std::int64_t>(acked) * 1'000'000'000LL) / delta_ns;
                const std::int64_t bps = std::min(bps_raw, kMaxBpsCap);
                observe_bandwidth_bps(bps);
                util::MetricsRegistry::instance().observe_tunnel_bandwidth_bps(bps);
            }
        }

        // RTT = (now - burst_start) when this ACK fully drains the window.
        // burst_start_ns_ was stamped when send_window_used_ went 0 -> positive.
        // Reset it to 0 on drain so the next burst gets its own sample.
        if (new_window == 0) {
            const auto burst_start = burst_start_ns_.exchange(0, std::memory_order_relaxed);
            if (burst_start > 0) {
                const std::int64_t rtt_us = (now_ns - burst_start) / 1000;
                if (rtt_us > 0) {
                    observe_rtt_us(rtt_us);
                    util::MetricsRegistry::instance().observe_tunnel_rtt_us(rtt_us);
                }
            }
        }

        // Report current window target to /metrics so operators can watch
        // it ramp up under load.
        const auto win = flow_control_.target_window_bytes();
        if (win > 0) {
            util::MetricsRegistry::instance().observe_tunnel_send_window_bytes(win);
        }
    }

    util::Logger::debug("Tunnel {} received ACK for {} bytes (window now {})", tunnel_id_, acked,
                        new_window);

    // C-S-1 + H-S-1 (2026-05-20 fix-storm review):
    // (1) C-S-1: snapshot `tcp_conn_` under `mutex_` before deref —
    //     `force_close()` resets it under the same lock from any thread.
    // (2) H-S-1: the earlier `new_window < current_window` predicate
    //     silently broke after S29's saturating-CAS refund: a refund
    //     could drive send_window_used_ to 0 *before* this ACK landed,
    //     so by the time we read it both values are 0 and the resume is
    //     skipped — TCP read stays paused forever. Trigger resume on any
    //     ACK that carried bytes; resume_read is idempotent so it's a
    //     no-op when the loop wasn't paused.
    std::shared_ptr<core::TcpConnection> conn;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        conn = tcp_conn_;
    }
    const bool drained_pending_tcp = flush_pending_tcp_input();
    if (conn && acked > 0 && drained_pending_tcp) {
        conn->resume_read();
    }
    maybe_finish_pending_tcp_eof();
}

void TunnelImpl::handle_tunnel_error_frame(const ProtocolFrame& frame) {
    auto payload = frame.as_tunnel_error();
    if (!payload) {
        util::Logger::warn("Tunnel {} received malformed TUNNEL_ERROR", tunnel_id_);
        return;
    }

    // "Tunnel not found" is the peer's routine reply to frames that crossed
    // a close on the wire — one arrives per in-flight frame when a transfer
    // is aborted, so it flooded the log at error level. Log the first one
    // per tunnel at info; repeats (tunnel already in Error) and anything
    // arriving during teardown at debug. Real failures keep error. Match on
    // the description too: code 1 is also used for rules denials
    // (tunnel_server.cpp), and a policy denial must never be demoted.
    const State prior_state = state();
    const bool teardown = prior_state == State::Disconnecting || prior_state == State::Closed ||
                          prior_state == State::Error;
    if (payload->error_code == 1 && payload->description == "Tunnel not found") {
        if (prior_state == State::Error) {
            util::Logger::debug("Tunnel {} received TUNNEL_ERROR: code={}, desc='{}'", tunnel_id_,
                                payload->error_code, payload->description);
        } else {
            util::Logger::info("Tunnel {} received TUNNEL_ERROR: code={}, desc='{}'", tunnel_id_,
                               payload->error_code, payload->description);
        }
    } else if (teardown) {
        util::Logger::info("Tunnel {} received TUNNEL_ERROR: code={}, desc='{}'", tunnel_id_,
                           payload->error_code, payload->description);
    } else {
        util::Logger::error("Tunnel {} received TUNNEL_ERROR: code={}, desc='{}'", tunnel_id_,
                            payload->error_code, payload->description);
    }
    util::MetricsRegistry::instance().inc_tunnels_closed(util::MetricsRegistry::CloseReason::Error);

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
    notify_close_once();
}

void TunnelImpl::handle_ping_frame(const ProtocolFrame& /*frame*/) {
    // Respond with PONG
    auto pong = ProtocolFrame::make_pong();
    send_frame_to_tox(pong);
    util::Logger::debug("Tunnel {} responded to PING", tunnel_id_);
}

void TunnelImpl::handle_pong_frame(const ProtocolFrame& /*frame*/) {
    util::Logger::debug("Tunnel {} received PONG", tunnel_id_);
}

// ===========================================================================
// TCP data handling
// ===========================================================================

void TunnelImpl::on_tcp_data_received(const uint8_t* data, std::size_t length) {
    if (!is_connected()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
        if (pending_tcp_pending_locked() != 0) {
            pending_tcp_input_.insert(pending_tcp_input_.end(), data, data + length);
            std::shared_ptr<core::TcpConnection> conn;
            {
                std::lock_guard<std::mutex> conn_lock(mutex_);
                conn = tcp_conn_;
            }
            if (conn) {
                conn->pause_read();
            }
            return;
        }
    }

    // Forward to Tox; if the send window is full, propagate the backpressure
    // upstream by pausing TCP reads — otherwise the data would be silently
    // dropped (C-18 in the 2026-05-20 review). handle_tunnel_ack_frame
    // calls resume_read once the window drains.
    // L-S-1 (2026-05-20 fix-storm review): snapshot tcp_conn_ under
    // mutex_ before deref — force_close() resets it from any thread.
    const bool accepted = send_data_to_tox(std::span<const uint8_t>(data, length));
    if (!accepted) {
        {
            std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
            pending_tcp_input_.insert(pending_tcp_input_.end(), data, data + length);
        }
        std::shared_ptr<core::TcpConnection> conn;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            conn = tcp_conn_;
        }
        if (conn) {
            conn->pause_read();
        }
    }
}

void TunnelImpl::on_tcp_read_eof() {
    State current = state_.load(std::memory_order_acquire);
    if (current == State::Connecting) {
        close();
        return;
    }
    if (current != State::Connected && current != State::Disconnecting) {
        util::Logger::debug("Tunnel {} TCP EOF ignored: state {}", tunnel_id_, to_string(current));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(tcp_backpressure_mutex_);
        if (pending_tcp_pending_locked() != 0) {
            pending_tcp_eof_ = true;
            util::Logger::debug("Tunnel {} TCP EOF deferred until pending TCP backlog flushes",
                                tunnel_id_);
            return;
        }
    }

    bool emit_close = false;
    bool finalize_now = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (!coalesce_try_drain_locked()) {
            close_pending_ = true;
            coalesce_arm_timer_locked();
            util::Logger::debug("Tunnel {} TCP EOF deferred until coalesce buffer drains",
                                tunnel_id_);
            return;
        }
        if (!local_close_sent_) {
            local_close_sent_ = true;
            local_stream_done_ = true;
            emit_close = true;
        }
        finalize_now = remote_close_received_;
    }

    if (emit_close) {
        emit_local_close_only();
    }
    if (finalize_now) {
        finalize_remote_close();
    }
}

// ===========================================================================
// Data sending
// ===========================================================================

bool TunnelImpl::send_data_to_tox(std::span<const uint8_t> data) {
    if (!is_connected()) {
        return false;
    }

    // Check window. When `configure_flow_control` has been called, prefer
    // the BDP-driven target over the constructor-time `send_window_size_`:
    // in `fixed` mode they match, in `bdp` mode the estimator resizes the
    // window in place. Otherwise stick with the legacy v0.3.0 behaviour so
    // existing tests and pre-v0.4 callers see unchanged semantics.
    const std::size_t data_size = data.size();
    std::size_t effective_window = send_window_size_;
    if (flow_control_configured_.load(std::memory_order_acquire)) {
        effective_window = std::max<std::size_t>(
            send_window_size_, static_cast<std::size_t>(flow_control_.target_window_bytes()));
    }
    // Atomically check-and-reserve the window. A plain load-then-fetch_add
    // races: on_tcp_data_received (I/O thread) and flush_pending_tcp_input —
    // reached via handle_tunnel_ack_frame on the Tox thread — can both pass the
    // guard and then both fetch_add, overcommitting the BDP window by a chunk.
    // The CAS reserves the bytes only if they still fit under the window value
    // observed at compare time.
    std::size_t current = send_window_used_.load(std::memory_order_relaxed);
    for (;;) {
        if (current + data_size > effective_window) {
            util::Logger::debug("Tunnel {} send window full ({} + {} > {})", tunnel_id_, current,
                                data_size, effective_window);
            return false;
        }
        if (send_window_used_.compare_exchange_weak(current, current + data_size,
                                                    std::memory_order_relaxed)) {
            break;
        }
        // CAS failed: `current` was refreshed with the latest value; re-check.
    }
    // On a successful CAS `current` still holds the pre-reservation usage.

    // Mark burst-start when we go 0 -> positive so the next ACK that drains us
    // back to 0 gives us an RTT sample.
    if (current == 0) {
        const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        burst_start_ns_.store(now_ns, std::memory_order_relaxed);
    }

    BumpActivity();

    // Update statistics
    total_bytes_sent_.fetch_add(data_size, std::memory_order_relaxed);
    util::MetricsRegistry::instance().add_bytes_out(data_size);

    // ---- Adaptive coalescer decision ------------------------------------
    // Update EWMA + select the active policy. The decision applies to this
    // push only; the policy may change on every call.
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto prev_ns = last_push_ns_.exchange(now_ns, std::memory_order_relaxed);
    const std::int64_t gap_us = prev_ns == 0 ? 0 : (now_ns - prev_ns) / 1000;
    coalescer_.observe(data_size, gap_us);
    const auto decision = coalescer_.decide();
    if (decision.transitioned) {
        util::MetricsRegistry::instance().inc_coalesce_policy_transitions();
        util::Logger::debug("Tunnel {} coalesce policy {} -> {}", tunnel_id_,
                            to_string(decision.previous), to_string(decision.policy));
    }

    // Determine which outbound path is active. We snapshot the owned-callback
    // presence before grabbing the coalesce mutex so the data path runs
    // lock-free against callback edits.
    bool zero_copy = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        zero_copy = static_cast<bool>(on_send_to_tox_owned_);
    }

    // Finding-1 (user-reported, 2026-05-21) + close-before-drain fix
    // (2026-05-25): a Tox SENDQ-full on the emit path is transient
    // backpressure, not a fatal error. Rather than dropping the bytes (silent
    // truncation) or tearing the tunnel down, both branches below RETAIN the
    // unsent bytes in the coalesce buffer and retry them on the flush timer,
    // keeping the lossless guarantee intact.
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);

        // `Bypass` policy and the legacy `max_delay_us == 0` path both emit
        // each chunk immediately with no coalesce buffer involvement.
        const bool emit_immediate =
            coalesce_max_delay_us_ == 0 || decision.policy == CoalescePolicy::Bypass;
        if (emit_immediate && coalesce_pending_locked() > 0) {
            // FIFO ordering: a prior emit hit Tox backpressure and parked its
            // remainder in coalesce_buf_ (drained by the retry timer). New data
            // must queue *behind* that remainder — emitting it directly here
            // would overtake the buffered bytes and silently reorder a lossless
            // stream (the bypass/adaptive path under sustained backpressure).
            // Route through the buffer, which drains full frames in order and
            // re-arms the timer if Tox is still backpressured.
            coalesce_append_locked(data);
            coalesce_arm_timer_locked();
        } else if (emit_immediate) {
            for (std::size_t offset = 0; offset < data.size();
                 offset += kMaxTcpPayloadPerToxFrame) {
                const auto chunk_size = std::min(kMaxTcpPayloadPerToxFrame, data.size() - offset);
                // Count the chunk as emitted BEFORE handing it to the (inline,
                // synchronous) send callback: an in-process ACK round-trip can
                // re-enter handle_tunnel_ack_frame on this very thread before the
                // send returns, and its acquire-load of total_bytes_emitted_ must
                // already include this chunk (else a legitimate ACK is
                // under-credited). Release pairs with that acquire. On send
                // failure we undo it below — those bytes never reached the wire.
                total_bytes_emitted_.fetch_add(chunk_size, std::memory_order_release);
                bool sent = false;
                if (zero_copy) {
                    auto buf = OwnedFrameBuffer::with_payload(data.subspan(offset, chunk_size));
                    util::MetricsRegistry::instance().inc_outbound_buffer_allocs();
                    ProtocolFrame::serialize_tunnel_data_in_place(buf, tunnel_id_);
                    sent = send_owned_data_to_tox(std::move(buf));
                } else {
                    auto frame = ProtocolFrame::make_tunnel_data(tunnel_id_,
                                                                 data.subspan(offset, chunk_size));
                    sent = send_frame_to_tox(frame);
                }
                if (!sent) {
                    // Tox SENDQ full (transient backpressure). Do NOT drop or
                    // tear down the tunnel — retain the unsent remainder in the
                    // coalesce buffer and retry on the timer, mirroring the
                    // batched path's lossless backpressure handling. The send
                    // window stays charged for these bytes so upstream TCP
                    // reads pause until they drain. (Earlier revisions refunded
                    // + transitioned to Error here, which truncated the stream
                    // on a momentarily-full Tox queue.)
                    total_bytes_emitted_.fetch_sub(chunk_size, std::memory_order_release);
                    const auto remainder = data.subspan(offset);
                    coalesce_buf_.insert(coalesce_buf_.end(), remainder.begin(), remainder.end());
                    coalesce_arm_timer_locked();
                    util::Logger::debug(
                        "Tunnel {} Tox send backpressured; buffered {} bytes for retry", tunnel_id_,
                        remainder.size());
                    break;
                }
            }
        } else {
            // `Drain` / `Batch` policy: write into the coalesce buffer and
            // (for Batch) arm the timer. Both helpers require coalesce_mutex_.
            coalesce_append_locked(data);
            if (decision.policy != CoalescePolicy::Drain) {
                coalesce_arm_timer_locked();
            }
        }
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
    notify_close_once();

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

bool TunnelImpl::send_ack() {
    const State current = state_.load(std::memory_order_acquire);
    if (current != State::Connected && current != State::Disconnecting) {
        return true;
    }

    std::size_t bytes_to_ack = bytes_received_since_ack_.exchange(0, std::memory_order_relaxed);
    // M-01: a single ACK frame can only carry a uint32_t count. If more than
    // 4 GiB accumulated since the last ACK, emit multiple frames so the peer's
    // send window is fully credited instead of permanently leaking the
    // remainder. On a send failure, restore the still-unacked bytes so a later
    // flush (next DATA or notify_tcp_writable) retries them, and report the
    // partial flush so the caller keeps the watermark armed and calls again.
    while (bytes_to_ack > 0) {
        const uint32_t ack_value = static_cast<uint32_t>(
            std::min<std::size_t>(bytes_to_ack, std::numeric_limits<uint32_t>::max()));
        auto frame = ProtocolFrame::make_tunnel_ack(tunnel_id_, ack_value);
        if (!send_frame_to_tox(frame)) {
            bytes_received_since_ack_.fetch_add(bytes_to_ack, std::memory_order_relaxed);
            util::Logger::debug("Tunnel {} ACK send backpressured; {} bytes still pending",
                                tunnel_id_, bytes_to_ack);
            arm_ack_retry_timer();
            return false;
        }
        bytes_to_ack -= ack_value;
        util::Logger::debug("Tunnel {} sent ACK for {} bytes", tunnel_id_, ack_value);
    }
    return true;
}

void TunnelImpl::arm_ack_retry_timer() {
    if (bytes_received_since_ack_.load(std::memory_order_relaxed) == 0) {
        return;
    }

    std::uint64_t epoch = 0;
    {
        std::lock_guard<std::mutex> lock(ack_retry_mutex_);
        if (ack_retry_timer_armed_) {
            return;
        }
        ack_retry_timer_armed_ = true;
        epoch = ++ack_retry_timer_epoch_;
        ack_retry_timer_.expires_after(kAckRetryDelay);
    }

    std::weak_ptr<Tunnel> weak = weak_from_this();
    ack_retry_timer_.async_wait([weak, epoch](const std::error_code& ec) {
        if (ec) {
            return;
        }
        auto self = std::static_pointer_cast<TunnelImpl>(weak.lock());
        if (!self) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(self->ack_retry_mutex_);
            if (epoch != self->ack_retry_timer_epoch_) {
                return;
            }
            self->ack_retry_timer_armed_ = false;
        }

        (void)self->send_ack();
    });
}

void TunnelImpl::notify_close_once() {
    if (close_notified_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    CloseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = std::move(on_close_);
    }
    if (cb) {
        cb();
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
    burst_start_ns_.store(0, std::memory_order_relaxed);
    last_ack_ns_.store(0, std::memory_order_relaxed);
}

// ===========================================================================
// Callbacks
// ===========================================================================

void TunnelImpl::set_on_send_to_tox(SendToToxCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_send_to_tox_ = std::move(cb);
}

void TunnelImpl::set_on_send_to_tox_owned(SendOwnedToToxCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_send_to_tox_owned_ = std::move(cb);
}

void TunnelImpl::set_on_data_for_tcp(SendToTcpCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_for_tcp_ = std::move(cb);
}

void TunnelImpl::set_on_data_for_tcp_owned(SendToTcpOwnedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_for_tcp_owned_ = std::move(cb);
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

bool TunnelImpl::send_frame_to_tox(const ProtocolFrame& frame) {
    SendToToxCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_send_to_tox_;
    }

    if (!cb) {
        return false;
    }
    auto wire = frame.serialize();
    return cb(std::span<const uint8_t>(wire.data(), wire.size()));
}

bool TunnelImpl::send_owned_data_to_tox(OwnedFrameBuffer buf) {
    SendOwnedToToxCallback owned_cb;
    SendToToxCallback span_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        owned_cb = on_send_to_tox_owned_;
        span_cb = on_send_to_tox_;
    }

    if (owned_cb) {
        return owned_cb(std::move(buf));
    }
    // Fallback: surface the bytes through the span callback so a partially
    // configured tunnel (e.g. tests that only wire the legacy callback) still
    // works. The wire bytes here are header+payload minus the leading 0xA0
    // lossless prefix — the legacy callback expects exactly that.
    if (span_cb && !buf.empty()) {
        const auto wire = buf.wire_view();
        // Skip the lossless prefix byte that the legacy callback will re-prepend.
        if (wire.size() > 1) {
            return span_cb(std::span<const std::uint8_t>(wire.data() + 1, wire.size() - 1));
        }
    }
    return false;
}

void TunnelImpl::BumpActivity() noexcept {
    last_activity_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                            std::memory_order_relaxed);
}

// ===========================================================================
// Write-side coalescing
// ===========================================================================

void TunnelImpl::configure_coalesce(std::uint32_t max_delay_us, std::uint32_t max_bytes) {
    // Clamp to the Tox-MTU ceiling so a single emitted frame always fits one
    // lossless custom packet.
    std::uint32_t clamped = max_bytes;
    if (clamped == 0 || clamped > kMaxTcpPayloadPerToxFrame) {
        clamped = static_cast<std::uint32_t>(kMaxTcpPayloadPerToxFrame);
    }

    std::lock_guard<std::mutex> lock(coalesce_mutex_);
    coalesce_max_delay_us_ = max_delay_us;
    coalesce_max_bytes_ = clamped;
    coalescer_.configure(clamped, max_delay_us);
    // If coalescing was just disabled, drain whatever's queued so order is
    // preserved relative to subsequent direct writes. Chunked so an
    // already-overflowed buffer never produces an oversized frame; any
    // backpressured remainder stays buffered for the retry timer.
    if (coalesce_max_delay_us_ == 0 && coalesce_pending_locked() > 0) {
        if (!coalesce_try_drain_locked()) {
            coalesce_arm_timer_locked();
        }
    }
}

void TunnelImpl::set_coalesce_mode(CoalesceMode mode) {
    coalescer_.set_mode(mode);
}

void TunnelImpl::configure_flow_control(const BdpFlowControl::Config& cfg) {
    flow_control_.configure(cfg);
    flow_control_configured_.store(true, std::memory_order_release);
    // Seed the per-tunnel window from the configured fixed value so the very
    // first push has a sensible budget regardless of mode.
    if (cfg.fixed_window_bytes > 0) {
        send_window_size_ = static_cast<std::size_t>(cfg.fixed_window_bytes);
    }
}

void TunnelImpl::observe_rtt_us(std::int64_t rtt_us) {
    flow_control_.observe_rtt_us(rtt_us);
}

void TunnelImpl::observe_bandwidth_bps(std::int64_t bps) {
    flow_control_.observe_bandwidth_bps(bps);
}

void TunnelImpl::flush_pending_writes() {
    std::lock_guard<std::mutex> lock(coalesce_mutex_);
    if (coalesce_pending_locked() == 0) {
        return;
    }
    // Best-effort chunked drain (force_close / explicit flush). On Tox
    // backpressure the bytes stay buffered: force_close() is tearing the tunnel
    // down regardless, and the graceful close() path defers via the timer.
    (void)coalesce_try_drain_locked();
    coalesce_timer_.cancel();
    coalesce_timer_armed_ = false;
}

void TunnelImpl::coalesce_append_locked(std::span<const uint8_t> data) {
    // Reclaim the consumed prefix before growing the buffer, but only once it
    // dominates the live bytes — amortised O(1) per byte, vs the O(n^2) that
    // erase-from-front-per-frame would cost while draining a large buffer.
    if (coalesce_consumed_ > 0 && coalesce_consumed_ >= coalesce_pending_locked()) {
        coalesce_buf_.erase(
            coalesce_buf_.begin(),
            coalesce_buf_.begin() + static_cast<std::ptrdiff_t>(coalesce_consumed_));
        coalesce_consumed_ = 0;
    }
    coalesce_buf_.insert(coalesce_buf_.end(), data.begin(), data.end());
    while (coalesce_pending_locked() >= coalesce_max_bytes_) {
        if (!coalesce_emit_front_locked(coalesce_max_bytes_)) {
            // Tox backpressured: leave the rest buffered and retry on the timer
            // rather than spin (or drop). The sub-MTU remainder, if any, is
            // also left for the timer flush.
            coalesce_arm_timer_locked();
            return;
        }
    }
}

bool TunnelImpl::coalesce_emit_front_locked(std::size_t bytes) {
    const std::size_t pending = coalesce_pending_locked();
    if (bytes == 0 || pending == 0) {
        return true;
    }
    bytes = std::min(bytes, pending);
    const std::uint8_t* front = coalesce_buf_.data() + coalesce_consumed_;
    // Prefer the Wave B zero-copy outbound path when the owned callback is
    // wired. We still need a single payload memcpy here (out of the
    // coalesce_buf_ deque into a freshly allocated frame buffer) because the
    // bytes were buffered before we knew the final emission boundary; the win
    // comes from skipping the secondary lossless-prefix-vector allocation in
    // the on_send_to_tox callback. Full zero-copy from TCP→Tox happens on the
    // coalesce-disabled path (max_delay_us == 0) and once the adaptive
    // bypass/drain policies (item 2) are wired up.
    bool zero_copy = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        zero_copy = static_cast<bool>(on_send_to_tox_owned_);
    }
    // Count as emitted BEFORE the (inline, synchronous) send callback: a same-
    // thread ACK round-trip can re-enter handle_tunnel_ack_frame before the send
    // returns, and its acquire-load of total_bytes_emitted_ must already include
    // these bytes or a legitimate ACK is under-credited. Undone on failure below.
    total_bytes_emitted_.fetch_add(bytes, std::memory_order_release);
    bool sent = false;
    if (zero_copy) {
        auto buf = OwnedFrameBuffer::with_payload(std::span<const std::uint8_t>(front, bytes));
        util::MetricsRegistry::instance().inc_outbound_buffer_allocs();
        ProtocolFrame::serialize_tunnel_data_in_place(buf, tunnel_id_);
        sent = send_owned_data_to_tox(std::move(buf));
    } else {
        auto frame =
            ProtocolFrame::make_tunnel_data(tunnel_id_, std::span<const uint8_t>(front, bytes));
        sent = send_frame_to_tox(frame);
    }
    if (!sent) {
        // Tox lossless SENDQ is full (transient transport backpressure). This
        // is NOT a drop point: a lossless tunnel must never lose bytes to a
        // momentarily-full send queue. RETAIN the bytes at the front of the
        // buffer and keep the send window charged so upstream TCP reads pause;
        // coalesce_try_drain_locked()'s caller re-arms the timer to retry.
        // (Earlier revisions erased + refunded here, silently truncating any
        // transfer large/fast enough to outrun the Tox congestion window —
        // observed as a hard ~85-90 KiB cap with the remainder lost.)
        total_bytes_emitted_.fetch_sub(bytes, std::memory_order_release);
        util::Logger::debug("Tunnel {} Tox backpressured; holding {} bytes for retry", tunnel_id_,
                            bytes);
        return false;
    }
    // Emitted successfully — the counter bumped above stands.
    // Consume via the offset (O(1)) instead of erase-from-front (O(n)). When
    // the buffer is fully drained, reset to reclaim it cheaply; otherwise the
    // prefix is reclaimed lazily in coalesce_append_locked.
    coalesce_consumed_ += bytes;
    if (coalesce_consumed_ == coalesce_buf_.size()) {
        coalesce_buf_.clear();
        coalesce_consumed_ = 0;
    }
    return true;
}

bool TunnelImpl::coalesce_try_drain_locked() {
    // Emit full-MTU frames first, then the sub-MTU remainder. Stop at the
    // first backpressured emit (bytes retained). Never build a frame larger
    // than one Tox MTU — emitting `coalesce_buf_.size()` directly would, once
    // backpressure has let the buffer grow past one MTU, exceed the wire
    // frame limit.
    while (coalesce_pending_locked() >= coalesce_max_bytes_) {
        if (!coalesce_emit_front_locked(coalesce_max_bytes_)) {
            return false;
        }
    }
    if (coalesce_pending_locked() > 0) {
        if (!coalesce_emit_front_locked(coalesce_pending_locked())) {
            return false;
        }
    }
    return true;
}

void TunnelImpl::coalesce_arm_timer_locked() {
    if (coalesce_pending_locked() == 0 || coalesce_timer_armed_) {
        return;
    }
    coalesce_timer_armed_ = true;
    const auto epoch = ++coalesce_timer_epoch_;
    coalesce_timer_.expires_after(std::chrono::microseconds(coalesce_max_delay_us_));
    // S17 / 2026-05-20 follow-up: capture weak_ptr instead of bare `this`.
    // steady_timer::cancel() is non-blocking; a handler already dispatched
    // to the io_context's worker queue will still run after this Tunnel
    // is destroyed unless the lambda holds a shared_ptr keeping it alive,
    // or (as here) gracefully bails out via `weak.lock()`.
    std::weak_ptr<Tunnel> weak = weak_from_this();
    coalesce_timer_.async_wait([weak, epoch](const std::error_code& ec) {
        if (ec) {
            return;
        }
        auto self = std::static_pointer_cast<TunnelImpl>(weak.lock());
        if (!self) {
            return;  // Tunnel was destroyed before the timer fired.
        }
        bool emit_close = false;
        bool emit_full_close = false;
        bool finalize_after_drain = false;
        {
            std::lock_guard<std::mutex> lock(self->coalesce_mutex_);
            // Reject stale firings (cancel-and-reset races).
            if (epoch != self->coalesce_timer_epoch_) {
                return;
            }
            self->coalesce_timer_armed_ = false;
            const bool drained = self->coalesce_try_drain_locked();
            if (!drained) {
                // Still backpressured — keep retrying on the timer.
                self->coalesce_arm_timer_locked();
            } else if (self->close_pending_) {
                // Buffer fully drained and a local close was deferred: it is
                // now safe to signal TUNNEL_CLOSE without it overtaking data.
                self->close_pending_ = false;
                if (self->close_pending_full_) {
                    self->close_pending_full_ = false;
                    emit_full_close = true;
                } else if (!self->local_close_sent_) {
                    self->local_close_sent_ = true;
                    self->local_stream_done_ = true;
                    emit_close = true;
                    finalize_after_drain = self->remote_close_received_;
                }
            } else if (self->remote_close_pending_) {
                self->remote_close_pending_ = false;
                finalize_after_drain = self->local_stream_done_;
            }
        }
        // emit_close_and_transition() sends through the Tox callback, so it
        // must run without coalesce_mutex_ held.
        if (emit_full_close) {
            self->emit_close_and_transition();
        }
        if (emit_close) {
            self->emit_local_close_only();
        }
        if (finalize_after_drain) {
            self->finalize_remote_close();
        }
    });
}

}  // namespace toxtunnel::tunnel
