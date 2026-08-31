#include "toxtunnel/tunnel/tunnel.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
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

/// Which backpressure log statement a throttle bucket belongs to. Packed into
/// the low half of the throttle key so distinct sites cannot share a budget;
/// see `backpressure_log_throttle()`.
///
/// Slice 2 of the outbound-send driver (issue #24) unified the two historical
/// emission paths (bypass/immediate and coalesce drain) behind one driver, so
/// today there is a single site. The keying mechanism stays: any future
/// second site must get its own budget, for the reasons recorded below.
enum class BackpressureSite : std::uint32_t {
    /// The emission driver in `run_emission_driver` — bytes held at the front
    /// of their cohort.
    CoalesceDrain = 1,
};

/// Shared rate limiter for the Tox-backpressure retry logs.
///
/// The coalesce retry timer re-arms at `tunnel.coalesce_max_delay_us` (200 us
/// by default) with no backoff, so a stalled Tox link makes the backpressure
/// site fire up to ~5 kHz. Measured: 5218 lines / 37 MB from a single
/// disconnect, which rolled three 5 MiB log files in under a minute and
/// discarded exactly the pre-failure history needed to diagnose it.
///
/// KEY CHOICE — `(friend_number, site)`, NOT tunnel id:
///
///  * Not per tunnel, because the flood is an aggregate property of *one
///    transport* being down: every tunnel on that friend stalls in the same
///    instant, so a per-tunnel budget would just multiply the volume by the
///    tunnel count (the pathology this throttle exists to stop). A tunnel id is
///    also only unique within its friend's `TunnelManager`, so keying on it
///    alone would merge genuinely different transports — two friends' tunnel 1
///    — into one bucket while splitting one transport across many.
///  * Per friend, because two friends stalling are two independent incidents,
///    and with a single process-wide bucket the second one's onset was
///    invisible: it landed in the first friend's `[+N suppressed]` tally. In a
///    multi-server client (failover) that is exactly the comparison — is the
///    fallback stalling too? — the line is being read for.
///  * Per site, because the two statements report different states (remainder
///    pushed into the coalesce buffer vs. bytes held at its front). Sharing one
///    budget meant whichever fired first silenced the other for the whole
///    second, so the log showed one path backpressured and said nothing about
///    the other.
///
/// Volume stays bounded at one line per second per (friend, site) — two per
/// stalled friend, against the ~5 kHz being defended — and 64 buckets caps it
/// absolutely regardless of friend count. A collision degrades that pair to the
/// old shared budget and never worse. Function-local `static` keeps the storage
/// out of the Tunnel header (and out of every Tunnel instance).
util::LogThrottle& backpressure_log_throttle(std::uint32_t friend_number, BackpressureSite site) {
    static util::KeyedLogThrottle<64> throttle{std::chrono::seconds(1)};
    return throttle.for_key(util::log_key(friend_number, static_cast<std::uint32_t>(site)));
}

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
      open_retry_timer_(io_ctx),
      friend_number_(friend_number),
      send_window_size_(send_window),
      last_activity_ns_(std::chrono::steady_clock::now().time_since_epoch().count()),
      coalesce_timer_(io_ctx),
      ack_retry_timer_(io_ctx),
      close_retry_timer_(io_ctx) {
    util::Logger::debug("Tunnel created: id={}, friend={}, window={}", tunnel_id_, friend_number_,
                        send_window_size_);
}

TunnelImpl::~TunnelImpl() {
    // Cancel pending timer waits; already-dispatched handlers capture weak_ptr
    // and bail out if destruction won the race.
    coalesce_timer_.cancel();
    ack_retry_timer_.cancel();
    open_retry_timer_.cancel();
    close_retry_timer_.cancel();
    // Backstop: a destroyed tunnel can no longer emit anything, whatever it may
    // still have owed. Without this an owner waiting on set_on_id_releasable()
    // would hold the id reserved forever.
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        if (close_frame_state_ == CloseFrameState::Owed ||
            close_frame_state_ == CloseFrameState::InFlight) {
            // A destroyed tunnel cannot emit anything, whatever it owed.
            close_frame_state_ = CloseFrameState::Abandoned;
        }
    }
    {
        std::function<void()> cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!id_releasable_notified_ && on_id_releasable_) {
                id_releasable_notified_ = true;
                cb = std::move(on_id_releasable_);
                on_id_releasable_ = nullptr;
            }
        }
        if (cb) {
            cb();
        }
    }
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

void TunnelImpl::notify_state_change(State new_state) {
    StateChangedCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = on_state_change_;
    }
    if (cb) {
        cb(new_state);
    }
}

bool TunnelImpl::transition_state_if(State expected, State desired) {
    State observed = expected;
    if (!state_.compare_exchange_strong(observed, desired, std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
        util::Logger::debug("Tunnel {} declined {} -> {}: state is {}", tunnel_id_,
                            to_string(expected), to_string(desired), to_string(observed));
        return false;
    }
    if (expected == desired) {
        return true;
    }

    util::Logger::debug("Tunnel {} state: {} -> {}", tunnel_id_, to_string(expected),
                        to_string(desired));
    notify_state_change(desired);
    maybe_notify_id_releasable();
    return true;
}

void TunnelImpl::transition_state(State new_state) {
    // A claim, not a blind store. The CAS-based writers — open(),
    // try_publish_connected(), transition_state_if() and force_close()'s
    // exchange — all arbitrate on this word, but the remaining writers reach it
    // through here, and a blind store from one of them silently undoes whatever
    // a concurrent resolver had already published. Two real cases:
    //
    //  * a graceful close beginning from Connected races force_close(): without
    //    this the close overwrites Closed with Disconnecting, resurrecting a
    //    tunnel whose socket is already gone;
    //  * an inbound TUNNEL_ACK loads Connecting, loses to force_close(), and
    //    then publishes Connected over the terminal state.
    //
    // Terminal states are therefore final: Closed and Error absorb every later
    // transition. Nothing legitimately leaves them — every path that reaches a
    // terminal state has already run notify_close_once() and booked its close.
    State current = state_.load(std::memory_order_acquire);
    for (;;) {
        if (current == State::Closed || current == State::Error) {
            if (current != new_state) {
                util::Logger::debug("Tunnel {} declined {} -> {}: already terminal", tunnel_id_,
                                    to_string(current), to_string(new_state));
            }
            return;
        }
        if (current == new_state) {
            return;
        }
        if (state_.compare_exchange_weak(current, new_state, std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            break;
        }
    }

    util::Logger::debug("Tunnel {} state: {} -> {}", tunnel_id_, to_string(current),
                        to_string(new_state));
    notify_state_change(new_state);
    maybe_notify_id_releasable();
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
    // empty). On a PERMANENT send failure we roll back to None so the caller can
    // release the id without the tunnel lingering in Connecting.
    //
    // Claiming the None -> Connecting edge and writing the target are ONE
    // critical section, and only the winner writes. Two concurrent open() calls
    // can both pass the fast-path state check above; if both wrote the target
    // and the loser then cleared it, the winner would serialize a TUNNEL_OPEN
    // for an empty or foreign host. The state check is only a fast path in the
    // other direction too: a close or force_close can resolve this tunnel
    // between it and here, which is why this is a compare-exchange rather than
    // a store. The state callback is fired afterwards, with the lock released
    // (H-01).
    bool claimed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        State expected = State::None;
        claimed = state_.compare_exchange_strong(
            expected, State::Connecting, std::memory_order_acq_rel, std::memory_order_acquire);
        if (claimed) {
            target_host_ = host;
            target_port_ = port;

            // The handshake-phase reset lives INSIDE the claim, so a losing
            // open() touches none of it. Resetting before the claim let a stale
            // loser overwrite the winner's Sending/Sent phase and only then lose
            // the CAS — after which cancel_open_retry() would read Pending and
            // suppress a TUNNEL_CLOSE the peer actually needed, because the
            // winner's OPEN had in fact gone out.
            //
            // A tunnel sitting in None may carry a resolved phase from an
            // earlier attempt that rolled back (PermanentFail); reopening is
            // legitimate, so the winner clears it. Ordering against
            // force_close(), which does NOT ignore None: if it lands before this
            // claim the CAS fails and nothing is reset; if it lands after, it
            // sets OpenPhase::Abandoned and attempt_open_send() declines.
            //
            // Lock order is mutex_ -> open_retry_mutex_. Nothing takes them the
            // other way round: attempt_open_send() acquires them one at a time,
            // never nested, and open_sent() takes only open_retry_mutex_.
            // cancel_open_retry() takes close_frame_mutex_ first and then
            // open_retry_mutex_ under it, which keeps the whole graph acyclic:
            // coalesce_mutex_ -> {mutex_, close_frame_mutex_} -> open_retry_mutex_.
            std::lock_guard<std::mutex> phase_lock(open_retry_mutex_);
            open_phase_ = OpenPhase::Pending;
            open_abandon_requested_ = false;
        }
    }
    if (!claimed) {
        util::Logger::debug("Tunnel {} open declined: resolved before the handshake started",
                            tunnel_id_);
        return false;
    }
    util::Logger::debug("Tunnel {} state: None -> Connecting", tunnel_id_);
    notify_state_change(State::Connecting);

    // attempt_open_send() reads the target back out under mutex_ and owns both
    // the retry decision and the question of whether this attempt may still
    // drive terminal state.
    const auto result = attempt_open_send(/*attempt=*/0);
    const auto outcome = result.outcome;

    if (outcome == SendOutcome::PermanentFail) {
        if (!result.owns_resolution) {
            // A close won the race and has already resolved this tunnel.
            // Rolling back to None here would overwrite its Closed. Report the
            // failed open and touch nothing.
            util::Logger::debug(
                "Tunnel {} open failed but was already resolved by a concurrent close", tunnel_id_);
            return false;
        }
        // Claiming the rollback edge is what makes the ownership atomic: the
        // phase claim above only excludes the *other* OPEN attempt, while a
        // close() that publishes Closed in the gap between that claim and this
        // transition is excluded here and nowhere else.
        if (!transition_state_if(State::Connecting, State::None)) {
            util::Logger::debug(
                "Tunnel {} open failed but was already resolved by a concurrent close", tunnel_id_);
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            target_host_.clear();
            target_port_ = 0;
        }
        // Back at None, so a later open() must be able to try again: clear the
        // Failed phase this attempt just recorded (see the reset at the top).
        {
            std::lock_guard<std::mutex> lock(open_retry_mutex_);
            open_phase_ = OpenPhase::Pending;
            open_abandon_requested_ = false;
        }
        util::Logger::warn("Tunnel {} open failed: initial TUNNEL_OPEN send rejected", tunnel_id_);
        return false;
    }

    if (!outcome) {
        // No attempt was made: a concurrent close resolved the tunnel between
        // the state transition above and the phase claim.
        util::Logger::debug("Tunnel {} open abandoned before TUNNEL_OPEN was attempted",
                            tunnel_id_);
        return false;
    }

    if (result.close_owed) {
        // A close landed while the OPEN was inside the transport. The OPEN is
        // now definitively on the wire, so the CLOSE can follow it — in that
        // order, which is the whole reason the obligation was deferred to here.
        (void)emit_close_frame_once();
        util::Logger::info("Tunnel {} opened and immediately closed; both frames sent in order",
                           tunnel_id_);
        return false;
    }

    if (outcome == SendOutcome::SendqFull) {
        // Transient backpressure is NOT a failure and NOT a delivery. The
        // tunnel keeps the frame, stays in Connecting, and retries on its own
        // timer (armed by attempt_open_send). Rolling back here would race the
        // caller into releasing an id whose OPEN is still on its way out;
        // reporting success would let the same caller believe the peer has been
        // told about a tunnel it has never heard of.
        util::Logger::info("Tunnel {} opening: {}:{} (TUNNEL_OPEN backpressured; retrying)",
                           tunnel_id_, host, port);
        return true;
    }

    util::Logger::info("Tunnel {} opening: {}:{}", tunnel_id_, host, port);
    return true;
}

bool TunnelImpl::try_publish_connected() {
    return transition_state_if(State::None, State::Connected);
}

bool TunnelImpl::open_sent() const noexcept {
    std::lock_guard<std::mutex> lock(open_retry_mutex_);
    return open_phase_ == OpenPhase::Sent;
}

TunnelImpl::OpenAttemptResult TunnelImpl::attempt_open_send(unsigned attempt) {
    {
        std::lock_guard<std::mutex> lock(open_retry_mutex_);
        if (open_phase_ != OpenPhase::Pending) {
            // Delivered, permanently failed, abandoned by a concurrent close,
            // or another attempt is already in flight. Nothing to do.
            return {};
        }
        // Also require the tunnel to still be Connecting. A force_close() that
        // claimed the state can be racing open()'s phase reset: if its
        // cancel_open_retry() ran before that reset, the reset would clear the
        // abandonment and this attempt would put a TUNNEL_OPEN on the wire for
        // a tunnel that is already Closed — with no CLOSE to follow it, because
        // force_close() had already decided the peer knew nothing. Checking the
        // state here means either we see Closed and send nothing, or
        // force_close() sees OpenPhase::Sending and announces the close.
        if (state_.load(std::memory_order_acquire) != State::Connecting) {
            return {};
        }
        open_phase_ = OpenPhase::Sending;
    }

    // OpenPhase::Sending is latched across a serialization and a callback, and
    // either can throw. Without this guard an exception leaves it latched
    // forever: no retry can start, cancel_open_retry() keeps answering
    // DeferredToSender for a CLOSE nobody will ever emit, and the tunnel id
    // stays reserved for the life of the manager. On an exceptional exit the
    // phase is resolved to Failed and any owed CLOSE is abandoned — the OPEN
    // demonstrably did not reach the peer, so nothing is owed.
    struct SendingPhaseGuard {
        TunnelImpl* self;
        bool resolved{false};
        ~SendingPhaseGuard() {
            if (resolved) {
                return;
            }
            try {
                bool owed = false;
                {
                    std::lock_guard<std::mutex> lock(self->open_retry_mutex_);
                    if (self->open_phase_ == OpenPhase::Sending) {
                        self->open_phase_ = OpenPhase::Failed;
                    }
                    owed = self->open_close_owed_;
                    self->open_close_owed_ = false;
                }
                if (owed) {
                    self->abandon_close_obligation();
                }
                self->maybe_notify_id_releasable();
            } catch (...) {
                // A destructor must not propagate. The phase write above is the
                // part that matters and has already happened or thrown trying.
            }
        }
    } phase_guard{this};

    std::string host;
    std::uint16_t port = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        host = target_host_;
        port = target_port_;
    }

    open_attempts_.fetch_add(1, std::memory_order_relaxed);
    auto frame = ProtocolFrame::make_tunnel_open(tunnel_id_, host, port);
    // No lock held: the send callback re-enters ToxAdapter and the manager, and
    // holding a tunnel lock across that deadlocks (H-01).
    const SendOutcome outcome = send_frame_to_tox_typed(frame);

    bool rearm = false;
    bool abandon_obligation = false;
    OpenAttemptResult result;
    result.outcome = outcome;
    {
        // ONE critical section decides the phase AND who owns the tunnel's
        // terminal state. Splitting them is what let this attempt overwrite a
        // resolution a concurrent close had already published: an abandoned
        // tunnel is Closed, and writing None (initial attempt) or Error plus a
        // second tunnels_closed sample (retry) on top of that is a real,
        // observable corruption, not just untidy bookkeeping.
        std::lock_guard<std::mutex> lock(open_retry_mutex_);
        if (outcome == SendOutcome::Sent) {
            // Record the truth even if a close is racing us: the frame really
            // did reach toxcore. No terminal action follows a Sent, so there is
            // nothing here that could overwrite the close's resolution, and
            // cancel_open_retry() has already answered "announce a CLOSE" for
            // exactly this case (it saw OpenPhase::Sending).
            open_phase_ = OpenPhase::Sent;
        } else if (open_abandon_requested_) {
            // A close ran while this send was in flight and owns the
            // resolution. Do not resurrect the OPEN behind it, and — the point
            // of checking this BEFORE the PermanentFail branch — do not let a
            // permanent failure drive a second terminal transition.
            open_phase_ = OpenPhase::Abandoned;
        } else if (outcome == SendOutcome::PermanentFail) {
            open_phase_ = OpenPhase::Failed;
            // Still ours: nobody else has resolved this tunnel, so the caller
            // may roll back (initial attempt) or terminate (retry).
            result.owns_resolution = true;
        } else {
            open_phase_ = OpenPhase::Pending;
            rearm = true;
        }

        // A close landed while we were inside the transport and deferred its
        // TUNNEL_CLOSE to us. Owe it only if the OPEN was actually accepted:
        // a backpressured or permanently failed OPEN never reached the peer,
        // so there is nothing to retract.
        if (open_close_owed_) {
            open_close_owed_ = false;
            // Owed only if the OPEN actually reached the peer. Otherwise there
            // is nothing to retract, and the obligation is released so the id
            // can be reused.
            result.close_owed = (outcome == SendOutcome::Sent);
            abandon_obligation = !result.close_owed;
        }
    }

    phase_guard.resolved = true;

    if (abandon_obligation) {
        abandon_close_obligation();
    }

    if (rearm) {
        arm_open_retry_timer(attempt);
    }
    return result;
}

void TunnelImpl::retry_open_send(unsigned attempt) {
    // Cheap pre-checks; attempt_open_send()'s phase CAS is the authoritative
    // one. A tunnel that left Connecting has been resolved by some other path
    // (ACK, error, close) and no longer wants its OPEN on the wire, and a
    // closed outbound gate means the whole session was abandoned.
    if (state_.load(std::memory_order_acquire) != State::Connecting || outbound_gate_closed()) {
        return;
    }

    const auto result = attempt_open_send(attempt);
    if (!result.outcome) {
        return;
    }
    if (*result.outcome == SendOutcome::Sent) {
        if (result.close_owed) {
            // See open(): the CLOSE is emitted here so it cannot overtake the
            // OPEN it retracts.
            (void)emit_close_frame_once();
        }
        util::Logger::debug("Tunnel {} TUNNEL_OPEN delivered on retry {}", tunnel_id_, attempt);
        return;
    }
    if (*result.outcome == SendOutcome::PermanentFail && result.owns_resolution) {
        // Unlike the initial attempt, there is no caller left holding this
        // tunnel's id to notice a rollback to None — open() has long since
        // returned true. Leaving it in Connecting would strand both the object
        // and the id (the idle reaper deliberately skips Connecting tunnels).
        // Drive a terminal state instead, which fires on_close_ and lets the
        // manager reclaim the id. No TUNNEL_CLOSE: the peer never saw the OPEN.
        //
        // Claim the edge: `owns_resolution` excludes the other OPEN attempt,
        // but a close() can still publish Closed between that claim and this
        // transition. Losing the compare-exchange means somebody else already
        // resolved this tunnel — do not overwrite their state and, just as
        // importantly, do not book a second tunnels_closed sample for it.
        if (!transition_state_if(State::Connecting, State::Error)) {
            util::Logger::debug("Tunnel {} TUNNEL_OPEN failed but was already resolved",
                                tunnel_id_);
            return;
        }
        util::Logger::warn("Tunnel {} TUNNEL_OPEN permanently failed on retry {}; giving up",
                           tunnel_id_, attempt);
        util::MetricsRegistry::instance().inc_tunnels_closed(
            util::MetricsRegistry::CloseReason::Error);
        notify_close_once();
        return;
    }
    // SendqFull: attempt_open_send() already re-armed the timer.
}

void TunnelImpl::arm_open_retry_timer(unsigned attempt) {
    std::weak_ptr<Tunnel> weak = weak_from_this();
    if (weak.expired()) {
        // Not owned by a shared_ptr (stack- or unique_ptr-constructed fixtures).
        // The handler could never resolve its weak_ptr, and the outstanding
        // async_wait would force the io_context destructor to service a pending
        // op — the hazard TunnelManager::arm_pending_drain_timer_locked()
        // documents for the Windows IOCP backend. Without an owner there is no
        // retry, so say so rather than failing silently.
        util::Logger::warn(
            "Tunnel {} cannot retry a backpressured TUNNEL_OPEN: tunnel is not shared-owned",
            tunnel_id_);
        return;
    }

    std::lock_guard<std::mutex> lock(open_retry_mutex_);
    if (open_retry_armed_ || open_abandon_requested_) {
        return;
    }
    open_retry_armed_ = true;
    const auto epoch = ++open_retry_epoch_;
    // Dedicated cadence, never coalesce_max_delay_us_ — that value is legally
    // 0 (the effective Windows default) and would spin. See sendq_retry.hpp.
    open_retry_timer_.expires_after(sendq_retry_delay(attempt));
    // async_wait stays inside the lock so every touch of open_retry_timer_ is
    // serialised against cancel_open_retry(); asio never runs the handler
    // inline, so no callback fires under this mutex.
    open_retry_timer_.async_wait([weak, epoch, attempt](const std::error_code& ec) {
        if (ec) {
            return;  // Cancelled.
        }
        auto self = std::static_pointer_cast<TunnelImpl>(weak.lock());
        if (!self) {
            return;  // Tunnel destroyed before the timer fired.
        }
        {
            std::lock_guard<std::mutex> lock(self->open_retry_mutex_);
            // Reject stale firings (cancel-and-rearm races).
            if (epoch != self->open_retry_epoch_) {
                return;
            }
            self->open_retry_armed_ = false;
        }
        self->retry_open_send(attempt + 1);
    });
}

TunnelImpl::CloseObligation TunnelImpl::cancel_open_retry() {
    std::lock_guard<std::mutex> close_lock(close_frame_mutex_);
    return cancel_open_retry_locked();
}

TunnelImpl::CloseObligation TunnelImpl::cancel_open_retry_locked() {
    std::lock_guard<std::mutex> lock(open_retry_mutex_);
    open_abandon_requested_ = true;
    ++open_retry_epoch_;  // Invalidate any handler already dispatched.
    open_retry_armed_ = false;
    open_retry_timer_.cancel();

    switch (open_phase_) {
        case OpenPhase::Pending:
            // The OPEN never reached toxcore and now never will.
            open_phase_ = OpenPhase::Abandoned;
            return CloseObligation::None;
        case OpenPhase::Sending:
            // A send is inside the transport on another thread. Emitting a
            // CLOSE here would race it onto the wire FIRST, leaving the OPEN
            // that follows unmatched — so hand the obligation to the thread
            // that can order it correctly. It also knows something we do not:
            // whether the OPEN was accepted at all.
            open_close_owed_ = true;
            // Recorded HERE, not by the caller. close() used to receive this
            // answer, drop open_retry_mutex_ and only then record it — long
            // enough for the sender to emit and resolve, after which the late
            // record pinned the id forever. force_close() received the same
            // answer and recorded nothing at all, so the id was recycled while
            // the sender still had a CLOSE to emit. Same split, opposite
            // failures; owning it here removes the split.
            note_close_owed_locked();
            return CloseObligation::DeferredToSender;
        case OpenPhase::Sent:
            return CloseObligation::Immediate;
        case OpenPhase::Abandoned:
        case OpenPhase::Failed:
            return CloseObligation::None;
    }
    return CloseObligation::None;
}

TunnelImpl::TerminalClaim TunnelImpl::claim_terminal() {
    TerminalClaim result;
    // Both writes under close_frame_mutex_, which is what makes the pair atomic
    // to every observer — see the declaration for the interleaving this closes.
    std::lock_guard<std::mutex> close_lock(close_frame_mutex_);

    // Terminal states are final: blindly exchanging used to turn Error into
    // Closed, overwriting a resolution another path had already published.
    State previous = state_.load(std::memory_order_acquire);
    while (previous != State::Closed && previous != State::Error) {
        if (state_.compare_exchange_weak(previous, State::Closed, std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            result.claimed = true;
            break;
        }
    }
    result.previous = previous;

    // Test seam. Deliberately INSIDE close_frame_mutex_: pausing here holds the
    // claimant still without opening the atomicity boundary, so a concurrent
    // id_releasable() observer blocks rather than sampling. See
    // set_terminal_claim_test_hook(). Null in production.
    if (terminal_claim_test_hook_) {
        terminal_claim_test_hook_();
    }

    // Stop any TUNNEL_OPEN retry and learn who owes the peer a CLOSE — still
    // holding close_frame_mutex_, so the answer is published with the claim.
    const CloseObligation obligation = cancel_open_retry_locked();

    // "Abrupt" is not a licence to strand the peer. If it can already know this
    // tunnel it is holding half of one (and its target fd) until its own reaper
    // fires, so it has to be told:
    //  * Connecting — the OPEN may have reached it; the obligation decides.
    //  * Connected  — it has the OPEN_ACK, so it definitely knows.
    // Disconnecting is excluded: our half-close is already on the wire, and
    // close_for_timeout() owns the "peer abandoned the handshake" case with a
    // TUNNEL_ERROR. DeferredToSender is excluded from *announcing* because that
    // send is still inside the transport and a CLOSE from here would overtake
    // the OPEN it retracts — but cancel_open_retry_locked() has already recorded
    // the obligation for it, so the id stays pinned until the sender emits.
    result.must_announce =
        result.claimed &&
        ((result.previous == State::Connecting && obligation == CloseObligation::Immediate) ||
         result.previous == State::Connected);
    if (result.must_announce) {
        note_close_owed_locked();
    }
    return result;
}

void TunnelImpl::cancel_close_retry() {
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        ++close_retry_epoch_;  // Invalidate any handler already dispatched.
        close_retry_armed_ = false;
        close_retry_timer_.cancel();
        // Fences an attempt that is already inside the transport: its verdict is
        // recorded under this same lock, and will see this.
        close_retry_cancelled_ = true;
        if (close_frame_state_ == CloseFrameState::Owed) {
            // Give the obligation up rather than pin the id on a retry that is
            // never going to run again.
            close_frame_state_ = CloseFrameState::Abandoned;
        }
    }
    maybe_notify_id_releasable();
}

void TunnelImpl::set_terminal_claim_test_hook(std::function<void()> hook) {
    std::lock_guard<std::mutex> lock(close_frame_mutex_);
    terminal_claim_test_hook_ = std::move(hook);
}

bool TunnelImpl::id_releasable() const {
    std::lock_guard<std::mutex> lock(close_frame_mutex_);
    return id_releasable_locked();
}

TunnelImpl::IdReleasableProbe TunnelImpl::probe_id_releasable() const {
    std::unique_lock<std::mutex> lock(close_frame_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
        return IdReleasableProbe::Blocked;
    }
    return id_releasable_locked() ? IdReleasableProbe::Releasable
                                  : IdReleasableProbe::NotReleasable;
}

bool TunnelImpl::emit_close_frame_once() {
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        if (close_retry_cancelled_) {
            // Shut down. With the outbound gate closed every send is a no-op
            // anyway, so there is nothing to gain by starting one.
            return false;
        }
        if (terminal_error_claimed_.load(std::memory_order_acquire)) {
            // The terminal ERROR replaces any CLOSE. Refusing HERE — at the
            // emission boundary, not only at the close()/EOF entry points —
            // is what closes the window where a thread passes an entry check,
            // stalls, and authorizes a fresh CLOSE between send_error()'s
            // seal and its close-retry fence (slice-3 follow-up P1: wire
            // order ERROR, CLOSE). An Owed obligation left behind is
            // abandoned by that same fence (cancel_close_retry) moments
            // later. Keyed on the ERROR claim, NOT the broader Abort seal: a
            // force_close teardown also publishes Abort, but the CLOSE an
            // in-flight OPEN's sender owes the peer after the handoff must
            // still go out behind that OPEN.
            return false;
        }
        if (close_frame_state_ != CloseFrameState::NotOwed &&
            close_frame_state_ != CloseFrameState::Owed) {
            // Already claimed, resolved or abandoned — there is only ever one.
            return false;
        }
        // InFlight pins the id for the whole transport call. It also discharges
        // any owed-ness in the same step, so no owner has to balance anything.
        close_frame_state_ = CloseFrameState::InFlight;
    }

    // Fallback for an exit that records no verdict — a throwing serializer or
    // callback. Retaining the frame there would pin the id forever, because the
    // same serialization would throw again on every retry, so this resolves.
    struct ClaimGuard {
        TunnelImpl* self;
        bool recorded{false};
        ~ClaimGuard() {
            if (recorded) {
                return;
            }
            try {
                {
                    std::lock_guard<std::mutex> lock(self->close_frame_mutex_);
                    if (self->close_frame_state_ == CloseFrameState::InFlight) {
                        self->close_frame_state_ = CloseFrameState::Resolved;
                    }
                }
                self->maybe_notify_id_releasable();
            } catch (...) {
                // A destructor must not propagate.
            }
        }
    } claim_guard{this};

    // Pre-transport recheck of the ERROR->CLOSE fence, mirroring the DATA
    // driver's pre-callback authorization: a terminal ERROR that won the race
    // between our InFlight claim above and this point must not be followed by
    // this CLOSE. The verdict is Abandoned — the ERROR replaced the CLOSE.
    // (The id is NOT recycled out from under the in-flight ERROR: see the
    // terminal_error_in_flight_ fence in id_releasable_locked.)
    //
    // RESIDUAL (interim): a thread that passes this check and stalls before
    // the transport call can still land its CLOSE after a concurrent ERROR.
    // The mechanism that eliminates this is the still-open CLOSE/ERROR
    // driver-ownership work (issue #24): with both frames serialized through
    // the single emission owner, an ERROR either queues behind an
    // already-authorised CLOSE or cancels one not yet selected, and no
    // check-then-send window exists at all. Until that lands, this recheck
    // narrows the window to the same allowance the design grants an
    // already-authorised DATA callback.
    if (terminal_error_claimed_.load(std::memory_order_acquire)) {
        {
            std::lock_guard<std::mutex> lock(close_frame_mutex_);
            close_frame_state_ = CloseFrameState::Abandoned;
        }
        claim_guard.recorded = true;
        maybe_notify_id_releasable();
        return false;
    }

    auto frame = ProtocolFrame::make_tunnel_close(tunnel_id_);
    // TYPED, not the bool wrapper. Collapsing the outcome here threw away the
    // one distinction eleven rounds of this slice exist to preserve: SendqFull
    // means the transport did NOT take the frame and this tunnel still owns it.
    // Resolving on it dropped the CLOSE and released the id, with no retry.
    const SendOutcome outcome = send_frame_to_tox_typed(frame);

    bool rearm = false;
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        if (close_retry_cancelled_) {
            // Teardown fenced this attempt while it was inside the transport.
            // Whatever the transport said, no further attempt may be armed — a
            // late SendqFull restoring Owed here would arm a fresh strong-self
            // timer after cancellation and keep this object alive past shutdown.
            close_frame_state_ = outcome == SendOutcome::Sent ? CloseFrameState::Resolved
                                                              : CloseFrameState::Abandoned;
        } else if (outcome == SendOutcome::SendqFull) {
            // Transient backpressure. Back to Owed, which keeps the id pinned,
            // and this tunnel is the retry owner — the same arrangement the
            // TUNNEL_OPEN driver uses, for the same reason (the manager's queue
            // carries no tunnel identity).
            close_frame_state_ = CloseFrameState::Owed;
            rearm = true;
        } else {
            // Sent, or PermanentFail: either way this object is done trying.
            close_frame_state_ = CloseFrameState::Resolved;
        }
    }
    claim_guard.recorded = true;

    if (rearm) {
        // Attempt counter advances across retries so the backoff actually grows;
        // re-arming from the handler with a fresh 0 would pin it at the base
        // delay forever.
        unsigned attempt = 0;
        {
            std::lock_guard<std::mutex> lock(close_frame_mutex_);
            attempt = close_retry_attempt_++;
        }
        arm_close_retry_timer(attempt);
    } else {
        maybe_notify_id_releasable();
    }
    return true;
}

void TunnelImpl::arm_close_retry_timer(unsigned attempt) {
    std::shared_ptr<Tunnel> self_ref;
    try {
        self_ref = shared_from_this();
    } catch (const std::bad_weak_ptr&) {
        // Not shared-owned; handled below exactly as an expired weak_ptr was.
    }
    if (!self_ref) {
        // Not shared-owned (stack / unique_ptr fixtures): the handler could
        // never resolve its weak_ptr, and an outstanding async_wait would force
        // the io_context destructor to service a pending op — the hazard
        // TunnelManager::arm_pending_drain_timer_locked() documents. Resolve
        // instead of pinning the id on a retry that can never run.
        util::Logger::warn(
            "Tunnel {} cannot retry a backpressured TUNNEL_CLOSE: tunnel is not shared-owned",
            tunnel_id_);
        {
            std::lock_guard<std::mutex> lock(close_frame_mutex_);
            if (close_frame_state_ == CloseFrameState::Owed) {
                close_frame_state_ = CloseFrameState::Resolved;
            }
        }
        maybe_notify_id_releasable();
        return;
    }

    std::lock_guard<std::mutex> lock(close_frame_mutex_);
    if (close_retry_cancelled_ || close_frame_state_ != CloseFrameState::Owed ||
        close_retry_armed_) {
        return;
    }
    close_retry_armed_ = true;
    const auto epoch = ++close_retry_epoch_;
    // Dedicated cadence, never coalesce_max_delay_us_ — see sendq_retry.hpp.
    close_retry_timer_.expires_after(sendq_retry_delay(attempt));
    // STRONG capture: the retry owner keeps itself alive until the obligation
    // resolves. A weak one let removal destroy the tunnel and silently drop the
    // frame. Released when the handler returns without re-arming.
    close_retry_timer_.async_wait([self_ref, epoch, attempt](const std::error_code& ec) {
        if (ec) {
            return;  // Cancelled — see cancel_close_retry().
        }
        auto self = std::static_pointer_cast<TunnelImpl>(self_ref);
        {
            std::lock_guard<std::mutex> lock(self->close_frame_mutex_);
            if (epoch != self->close_retry_epoch_) {
                return;  // Stale firing.
            }
            self->close_retry_armed_ = false;
        }
        // Re-claims from Owed and re-attempts. A further SendqFull re-arms
        // from inside emit_close_frame_once(), with the next backoff step.
        (void)attempt;
        (void)self->emit_close_frame_once();
    });
}

bool TunnelImpl::id_releasable_locked() const {
    if (terminal_error_in_flight_.load(std::memory_order_acquire)) {
        // The terminal ERROR is inside (or about to enter) the transport,
        // naming this id. Whatever the CLOSE-frame state says — including an
        // Abandoned verdict recorded by a concurrently-fenced CLOSE — the id
        // must not be recycled until that attempt settles, or the ERROR lands
        // on the replacement. send_error() re-notifies after clearing this.
        return false;
    }
    switch (close_frame_state_) {
        case CloseFrameState::Owed:
        case CloseFrameState::InFlight:
            // Somebody will emit, or is emitting right now. Either way a frame
            // naming this id can still appear on the wire.
            return false;
        case CloseFrameState::Resolved:
            // This object owes no further emission, whether or not the peer
            // got the frame. Scoped to this tunnel — a manager-parked copy is
            // not covered; see CloseFrameState::Resolved.
            return true;
        case CloseFrameState::NotOwed:
        case CloseFrameState::Abandoned:
            break;
    }
    // No CLOSE is coming — but only a terminal tunnel is finished with its id;
    // a live one can still start owing one. Read under the same lock as the
    // CLOSE state so the pair cannot be observed half-updated.
    const State current = state_.load(std::memory_order_acquire);
    return current == State::Closed || current == State::Error;
}

void TunnelImpl::note_close_owed() {
    std::lock_guard<std::mutex> lock(close_frame_mutex_);
    note_close_owed_locked();
}

void TunnelImpl::note_close_owed_locked() {
    if (close_frame_state_ != CloseFrameState::NotOwed) {
        // Any other state already pins the id (Owed/InFlight) or already
        // resolved it (Resolved/Abandoned); a second owner adds nothing,
        // because there is only ever one CLOSE.
        return;
    }
    if (close_retry_cancelled_) {
        // Cancelled. Recording Owed here would pin the id for the rest of this
        // object's life: emission is refused once fenced, so nothing could ever
        // discharge the obligation and only destruction would release the id.
        // A claim that arrives after teardown owes nothing.
        close_frame_state_ = CloseFrameState::Abandoned;
        return;
    }
    close_frame_state_ = CloseFrameState::Owed;
}

void TunnelImpl::abandon_close_obligation() {
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        if (close_frame_state_ != CloseFrameState::Owed) {
            // Only an owed-but-unclaimed CLOSE can be given up. An InFlight or
            // Resolved one has already been dealt with.
            return;
        }
        close_frame_state_ = CloseFrameState::Abandoned;
    }
    maybe_notify_id_releasable();
}

void TunnelImpl::set_on_id_releasable(std::function<void()> cb) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        on_id_releasable_ = std::move(cb);
    }
    maybe_notify_id_releasable();
}

void TunnelImpl::maybe_notify_id_releasable() {
    // Releasable once the CLOSE is on the transport, or once the tunnel is
    // terminal and owes none. Anything short of that and a frame naming this id
    // can still appear on the wire.
    {
        std::lock_guard<std::mutex> lock(close_frame_mutex_);
        if (!id_releasable_locked()) {
            return;
        }
    }

    std::function<void()> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Consume the latch ONLY when there is something to run. The condition
        // is typically already true by the time the owner installs its hook —
        // remove_tunnel_impl() installs it and then triggers the teardown that
        // emits the CLOSE — so burning the latch on an empty callback would
        // mean the owner is never told and the id is never released.
        if (id_releasable_notified_ || !on_id_releasable_) {
            return;
        }
        id_releasable_notified_ = true;
        cb = std::move(on_id_releasable_);
        on_id_releasable_ = nullptr;
    }
    cb();  // Outside the lock: it re-enters the manager (H-01).
}

void TunnelImpl::close() {
    // A terminal Abort (send_error / gate / force_close teardown) has already
    // sealed this tunnel's outbound side. The graceful close has nothing left
    // to do — and must not do it anyway: the seal can be observed before the
    // terminal state transition lands (send_error's transport callback can
    // re-enter here while the state still reads Connected), and emitting a
    // CLOSE then would put it on the wire AFTER the terminal ERROR,
    // downgrading Abort to graceful in violation of the monotonic ladder.
    if (outbound_abort_published_.load(std::memory_order_acquire)) {
        util::Logger::debug("Tunnel {} close ignored: outbound already aborted", tunnel_id_);
        return;
    }

    State current = state_.load(std::memory_order_acquire);

    // C-05: close requested while the open handshake is still in flight (the
    // local TCP side disconnected before the peer ACKed our TUNNEL_OPEN).
    // Without handling this, the tunnel stays in Connecting forever — the
    // reaper deliberately skips Connecting tunnels — leaking both the object
    // and its tunnel id. Move straight to Closed and notify so the manager
    // reclaims the id. No coalesce buffer can hold data here (send_data_to_tox
    // refuses while not Connected), so there is nothing to drain.
    if (current == State::Connecting) {
        // Stop any TUNNEL_OPEN retry and learn, atomically with stopping it,
        // who owes the peer a TUNNEL_CLOSE.
        const CloseObligation obligation = cancel_open_retry();

        if (obligation == CloseObligation::Immediate) {
            // The peer owns half a tunnel; it needs to be told to let go.
            (void)emit_close_frame_once();
        } else if (obligation == CloseObligation::DeferredToSender) {
            // A send is inside the transport; it will emit the CLOSE after its
            // OPEN, so that the two cannot reach the peer out of order. Until it
            // does, this id must not be reused — cancel_open_retry() has already
            // recorded that, under the same lock that decided it.
            util::Logger::debug(
                "Tunnel {} closed during handshake while its TUNNEL_OPEN was in flight; "
                "the sender will announce the close",
                tunnel_id_);
        } else {
            // The OPEN never reached toxcore, so this id means nothing to the
            // peer. Emitting TUNNEL_CLOSE anyway is not merely redundant: ids
            // are recycled per friend and notify_close_once() below releases
            // this one immediately, so a CLOSE still sitting in a retry queue
            // would be delivered against whichever tunnel inherits the id.
            util::Logger::debug(
                "Tunnel {} closed during handshake before TUNNEL_OPEN reached the peer; "
                "no TUNNEL_CLOSE emitted",
                tunnel_id_);
        }
        // Claim the terminal edge, for the same reason open()/retry_open_send()
        // do: an OPEN attempt that failed permanently may be about to roll this
        // tunnel back to None or drive it to Error. Exactly one of the three
        // wins, and only the winner books the close.
        if (!transition_state_if(State::Connecting, State::Closed)) {
            util::Logger::debug("Tunnel {} close during handshake: already resolved", tunnel_id_);
            return;
        }
        util::MetricsRegistry::instance().inc_tunnels_closed(local_close_reason());
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
    // observes every byte we accepted. The decision is made under
    // `coalesce_mutex_` FIRST: if anything is still pending — or an emitter is
    // mid-drain, whose deferred result must never be read as "drained" (see
    // EmitOutcome) — the TUNNEL_CLOSE is deferred and whichever driver
    // completes the drain emits it. Emitting it now would let it overtake
    // in-flight DATA, and the peer drops post-close frames as "unknown
    // tunnel" (the close-before-drain truncation bug).
    bool defer = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (coalesce_pending_locked() > 0 || driver_active_) {
            close_pending_ = true;
            close_pending_full_ = true;
            // close() is about to RETURN with the CLOSE still owed — the
            // driver that finishes the drain emits it. The id stays reserved
            // until then; releasing it on this return is what let a
            // replacement take an id the deferred CLOSE was still going to
            // name. Recorded inside this critical section, so no emit can
            // slip between the decision and the record.
            note_close_owed();
            defer = true;
        }
    }
    if (defer) {
        // Kick a drain in case no emitter is active any more; harmlessly
        // deferred if one is, and the retry timer takes over on backpressure.
        (void)run_emission_driver(DrainPolicy::FlushAll);
        util::Logger::debug("Tunnel {} close deferred until coalesce buffer drains", tunnel_id_);
        return;
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

    // Through the shared latch, not a bare send: a force_close() racing this
    // graceful close can already have announced, and a second TUNNEL_CLOSE
    // names an id that may by then belong to a different tunnel.
    if (should_send_close && emit_close_frame_once()) {
        util::MetricsRegistry::instance().inc_tunnels_closed(local_close_reason());
    }

    // Conditional, not a blind store: the emit above runs a transport
    // callback that can re-enter send_error() (target died mid-close) or
    // race a force_close(), either of which claims a TERMINAL state. A blind
    // Disconnecting store here would clobber that claim and resurrect a dead
    // tunnel into a half-open state.
    if (!transition_state_if(State::Connected, State::Disconnecting)) {
        util::Logger::debug("Tunnel {} close transition skipped: already {}", tunnel_id_,
                            to_string(state()));
    }

    util::Logger::info("Tunnel {} closing", tunnel_id_);

    // The buffer is fully drained and CLOSE has been emitted — it is now safe
    // for the owner to tear the tunnel down. Firing this only here (rather than
    // when close() is first requested) is what lets a backpressured tunnel
    // finish flushing its data before removal, instead of dropping it. The
    // callback is responsible for deferring the actual teardown (asio::post)
    // so it never destroys this tunnel mid-call.
    notify_close_once();
}

util::MetricsRegistry::CloseReason TunnelImpl::local_close_reason() const noexcept {
    // A close driven by the idle reaper / half-close cap is a timeout, not an
    // application-initiated close. Keeping them apart is the whole point of the
    // `reason` label: an operator alerting on reaper activity was previously
    // watching a label that could never be non-zero.
    return timeout_close_.load(std::memory_order_acquire)
               ? util::MetricsRegistry::CloseReason::Timeout
               : util::MetricsRegistry::CloseReason::Local;
}

void TunnelImpl::close_for_timeout() {
    timeout_close_.store(true, std::memory_order_release);

    if (state() == State::Disconnecting) {
        // The peer abandoned its side of the close handshake. Tell it plainly:
        // TUNNEL_ERROR drives the peer's tunnel to Error and through its normal
        // teardown (see handle_tunnel_error_frame), releasing its target fd.
        // Code 2, not 3. Its post-open timing means no SOCKS5 reply is riding on
        // it, but code 3 now means "the target refused the connection" and this
        // is a local linger timeout — leaving it at 3 would contradict the wire
        // contract even though nothing observable would break today.
        auto frame = ProtocolFrame::make_tunnel_error(tunnel_id_, 2, "half-close linger timeout");
        send_frame_to_tox(frame);
        util::MetricsRegistry::instance().inc_tunnels_closed(
            util::MetricsRegistry::CloseReason::Timeout);
        transition_state(State::Closed);
        util::Logger::info("Tunnel {} force-closed after half-close linger timeout; peer notified",
                           tunnel_id_);
        notify_close_once();
        return;
    }

    // Any other reapable state: the ordinary close path is correct (it emits
    // TUNNEL_CLOSE and drains buffered data first); only the accounting
    // differs, which timeout_close_ takes care of.
    close();
}

void TunnelImpl::emit_local_close_only() {
    // Shared single-shot latch; see emit_close_and_transition().
    if (emit_close_frame_once()) {
        util::MetricsRegistry::instance().inc_tunnels_closed(local_close_reason());
    }
    // Conditional for the same reason as emit_close_and_transition(): the
    // emit's transport callback can claim a terminal state re-entrantly, and
    // this transition must lose to it, not clobber it.
    (void)transition_state_if(State::Connected, State::Disconnecting);
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
            // the outbound cohorts' consumed-cursor scheme.
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
    // ONE step claims the terminal edge AND publishes whether a TUNNEL_CLOSE is
    // owed. They used to be two, in different synchronization domains, and the
    // instant between them was observable as "terminal, owes nothing" — which is
    // precisely the state that says the id is free. See claim_terminal().
    const TerminalClaim claim = claim_terminal();
    const bool claimed_terminal = claim.claimed;
    const bool announce = claim.must_announce;

    // The resource release is a SEPARATE one-shot, and the two are INDEPENDENT:
    // each gates only its own work, and it is taken AFTER the claim above so the
    // reservation is already published.
    //
    // Returning early on a lost resource latch was wrong, because the two can be
    // won by different threads. Thread A claims Connected -> Closed while thread
    // B wins the resource latch; A then bailed out, so nobody announced the
    // CLOSE and nobody published the state change — the peer was stranded and
    // every state observer missed the transition. Whoever wins the state claim
    // must always finish its announce and its notification, whether or not it
    // also owns the cleanup.
    const bool owns_resources = !resources_released_.exchange(true, std::memory_order_acq_rel);
    if (!claimed_terminal && !owns_resources) {
        // Pure duplicate call: another thread owns both halves.
        return;
    }

    // Best-effort flush BEFORE the CLOSE announcement, so any retained DATA
    // that can still be delivered reaches the wire ahead of the CLOSE — the
    // peer drops post-close frames as "unknown tunnel", so the old
    // announce-then-flush order reproduced exactly the close-before-drain
    // truncation the design doc records (slice-3 review finding). The flush
    // is skipped once the outbound gate is closed — the local-abandon path.
    //
    // On that guard: historically it was deadlock avoidance — the coalesced
    // data path used to call its Tox send callback while HOLDING
    // `coalesce_mutex_`, and `flush_pending_writes()` re-took that same plain
    // non-recursive mutex, so any route from inside a send callback back into
    // force_close() self-deadlocked the thread. Slice 2 of the outbound-send
    // driver (issue #24) removed the in-lock send: a re-entrant flush now
    // merely defers to the active emitter (`DeferredToActiveEmitter`) instead
    // of deadlocking. The guard STAYS regardless, per the design doc's
    // slice 5 — a flush from inside teardown still cannot *wait* for the
    // in-flight send, so removing the guard would not make the flush
    // meaningful, and skipping it costs nothing in that state: with the gate
    // closed every emit is rejected, and the buffered bytes are being
    // discarded either way.
    if (owns_resources && !outbound_gate_closed()) {
        flush_pending_writes();
    }

    if (announce && emit_close_frame_once()) {
        util::MetricsRegistry::instance().inc_tunnels_closed(local_close_reason());
    }

    if (owns_resources) {
        {
            // Whatever the best-effort flush could not deliver is abandoned
            // now: force_close() is the Abort level of the terminal-intent
            // ladder ("no graceful operation maps to Abort" — this is not a
            // graceful operation). Published AFTER the flush, so the flush
            // still delivers what it can; sealing admission here also stops
            // the retry timer from resurrecting the remainder against a
            // tunnel being destroyed.
            std::lock_guard<std::mutex> lock(coalesce_mutex_);
            publish_abort_locked();
        }

        // Close TCP connection if any. Runs even when another thread claimed the
        // state first: a tunnel driven to Error by send_error() never closed its
        // socket, so skipping the cleanup on terminality would leak the fd.
        std::lock_guard<std::mutex> lock(mutex_);
        if (tcp_conn_) {
            tcp_conn_->force_close();
            tcp_conn_.reset();
        }
    }

    // The state itself was published by the claim at the top; this is the
    // observer half of that transition, and only the claimant owes it.
    if (claimed_terminal) {
        notify_state_change(State::Closed);
    }
    maybe_notify_id_releasable();
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
    bool kick_drain = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        remote_close_received_ = true;
        if (!conn) {
            local_stream_done_ = true;
        }
        if (outbound_abort_published_.load(std::memory_order_relaxed)) {
            // Terminal Abort already sealed this tunnel: nothing drains, and
            // the terminal path (send_error / teardown) owns the state and
            // close notifications. Record the peer's close and stop — a
            // finalize here would transition an Error tunnel to Closed and
            // double-book the close metric.
        } else if (coalesce_pending_locked() > 0 || driver_active_) {
            // Outbound DATA accepted from local TCP is still draining (or an
            // emitter is mid-frame). Keep the tunnel alive until it is on the
            // wire; the driver that finishes the drain finalizes.
            remote_close_pending_ = true;
            kick_drain = true;
        } else if (local_stream_done_) {
            finalize_now = true;
        }
    }
    if (kick_drain) {
        (void)run_emission_driver(DrainPolicy::FlushAll);
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
    // only bound on the outbound FIFO and OOMing us.
    //
    // LOCK-FREE on purpose: a synchronous ACK round-trip (test harness, or any
    // in-process loopback) re-enters here on the very thread that is inside
    // the emission driver's send callback. The driver no longer holds
    // `coalesce_mutex_` across that callback (slice 2, issue #24), but this
    // path stays lock-free anyway: it needs no FIFO state, and taking the
    // mutex here would re-couple the ACK path to the emitter for nothing.
    // Correctness without the lock comes from causality: emit stores
    // total_bytes_emitted_ with release BEFORE the bytes go on the wire, and
    // the peer can only ACK bytes it received AFTER that send, so this
    // acquire-load always observes emitted >= the acked bytes — a legitimate
    // ACK is credited in full; only a forged over-ack is clamped.
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

    last_error_code_.store(payload->error_code, std::memory_order_release);
    {
        std::lock_guard lock(last_error_mutex_);
        last_error_description_ = payload->description;
    }

    // "Tunnel not found" is the peer's routine reply to frames that crossed
    // a close on the wire — one arrives per in-flight frame when a transfer
    // is aborted, so it flooded the log at error level. Log the first one
    // per tunnel at info; repeats (tunnel already in Error) and anything
    // arriving during teardown at debug. Real failures keep error. Match on
    // the description too: code 1 means a POLICY denial (rules, rate limit,
    // tunnel cap) and a policy denial must never be demoted to routine noise.
    //
    // Both codes are accepted because this is a MIXED-VERSION log path: a peer
    // running <= v0.4.11 sends this as code 1, a v0.4.12+ peer as code 2. If we
    // only matched the new code, an older peer's routine cross-on-the-wire
    // replies would go back to flooding the log at error level.
    const State prior_state = state();
    const bool teardown = prior_state == State::Disconnecting || prior_state == State::Closed ||
                          prior_state == State::Error;
    const bool routine_tunnel_not_found = (payload->error_code == 2 || payload->error_code == 1) &&
                                          payload->description == "Tunnel not found";
    if (routine_tunnel_not_found) {
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
    // See close(): after a terminal Abort the half-close CLOSE must not reach
    // the wire behind the terminal ERROR.
    if (outbound_abort_published_.load(std::memory_order_acquire)) {
        util::Logger::debug("Tunnel {} TCP EOF ignored: outbound already aborted", tunnel_id_);
        return;
    }

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

    bool defer = false;
    bool emit_close = false;
    bool finalize_now = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (coalesce_pending_locked() > 0 || driver_active_) {
            // Deferred: the driver that completes the drain emits the
            // directional CLOSE (a mid-drain emitter's result must never be
            // read as "drained" — see EmitOutcome).
            close_pending_ = true;
            defer = true;
        } else {
            if (!local_close_sent_) {
                local_close_sent_ = true;
                local_stream_done_ = true;
                emit_close = true;
            }
            finalize_now = remote_close_received_;
        }
    }
    if (defer) {
        (void)run_emission_driver(DrainPolicy::FlushAll);
        util::Logger::debug("Tunnel {} TCP EOF deferred until coalesce buffer drains", tunnel_id_);
        return;
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
    // Fast reject once the terminal Abort seal is published (send_error /
    // close_outbound_gate / force_close teardown): admission is closed, and
    // accepting bytes that could never drain would only grow a FIFO the
    // abandonment already emptied. The lock-free load can race a concurrent
    // seal; the authoritative re-check happens under `coalesce_mutex_` below,
    // before any append.
    if (outbound_abort_published_.load(std::memory_order_acquire)) {
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

    // Finding-1 (user-reported, 2026-05-21) + close-before-drain fix
    // (2026-05-25) lineage, now enforced by the emission driver: a Tox
    // SENDQ-full on the emit path is transient backpressure, not a fatal
    // error. The driver retains unsent bytes in their cohort and retries them
    // on the flush timer, keeping the lossless guarantee intact — and no send
    // callback ever runs under `coalesce_mutex_` (slice 2, issue #24).
    bool emit_immediate = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        // Authoritative admission check, atomic with the append: a seal
        // published between the lock-free fast check above and this lock
        // means the FIFO has been abandoned — appending now would strand
        // bytes admission promised to deliver. Refuse and refund the window
        // reservation taken above.
        if (outbound_abort_published_.load(std::memory_order_relaxed)) {
            // Saturating refund, mirroring the ACK release loop: a concurrent
            // reset_statistics() may have zeroed the counter between the CAS
            // reservation above and this refusal, and an unconditional
            // fetch_sub would underflow the unsigned counter and wedge
            // admission at "window full" forever.
            std::size_t used = send_window_used_.load(std::memory_order_relaxed);
            while (used > 0 &&
                   !send_window_used_.compare_exchange_weak(
                       used, used > data_size ? used - data_size : 0, std::memory_order_relaxed)) {
            }
            return false;
        }
        // `Bypass` policy and the legacy `max_delay_us == 0` path both want
        // each write on the wire immediately.
        emit_immediate = coalesce_max_delay_us_ == 0 || decision.policy == CoalescePolicy::Bypass;
        // Admission cap is a property of the WRITE, carried by its cohort:
        // bypass admits under the wire ceiling (one frame per unobstructed
        // write), batch/drain under the configured coalesce cap. Behind an
        // existing backlog the bytes simply queue in FIFO order — a bypass
        // write must not overtake a buffered remainder, and its cohort keeps
        // the bypass framing rather than inheriting the buffered cap.
        fifo_append_locked(data, emit_immediate ? kMaxTcpPayloadPerToxFrame
                                                : static_cast<std::size_t>(coalesce_max_bytes_));
        if (!emit_immediate && decision.policy != CoalescePolicy::Drain) {
            // Batch: the timer bounds how long a sub-cap remainder is held.
            // Armed at admission (as always) so the bound holds even when the
            // drive below is deferred to an emitter running another policy.
            coalesce_arm_timer_locked();
        }
    }

    // Statistics count ACCEPTED bytes only, so they come after the
    // authoritative admission check above.
    total_bytes_sent_.fetch_add(data_size, std::memory_order_relaxed);
    util::MetricsRegistry::instance().add_bytes_out(data_size);

    if (emit_immediate) {
        // Bypass keeps its latency by running the driver synchronously on
        // this thread when it is idle, and FlushAll puts a sub-MTU write on
        // the wire before this call returns. A write arriving mid-send queues
        // behind the active emitter — the FIFO serialization we want, no
        // worse than blocking on the old in-lock send.
        (void)run_emission_driver(DrainPolicy::FlushAll);
    } else if (decision.policy == CoalescePolicy::Drain) {
        // Drain: emit full frames on overflow only; the remainder waits for
        // overflow or an explicit flush, never the timer.
        (void)run_emission_driver(DrainPolicy::FullFramesOnly,
                                  /*arm_timer_on_remainder=*/false);
    } else {
        // Batch: emit whatever already amounts to full frames; the remainder
        // rides the timer armed above.
        (void)run_emission_driver(DrainPolicy::FullFramesOnly);
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
    // Slice-3 ordering (issue #24): ONE critical section seals admission,
    // abandons undelivered DATA, and claims the single terminal ERROR. The
    // abandonment matters beyond tidiness — without it the retained cohorts
    // kept riding the retry timer and could put TUNNEL_DATA on the wire
    // AFTER the TUNNEL_ERROR, which the peer then processes against a tunnel
    // it has already torn down.
    bool claimed = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        publish_abort_locked();
        if (!terminal_error_claimed_.load(std::memory_order_relaxed)) {
            // The releasability fence goes up INSIDE the winning claim's
            // critical section, BEFORE the claim becomes visible: a CLOSE
            // whose pre-transport recheck observes the claim (and records
            // Abandoned) must already find the id unreleasable, or a
            // force_close() publishing a terminal state in the gap would let
            // the id recycle under the ERROR this claim is about to send.
            terminal_error_in_flight_.store(true, std::memory_order_release);
            terminal_error_claimed_.store(true, std::memory_order_release);
            claimed = true;
        }
    }
    if (!claimed) {
        util::Logger::debug("Tunnel {} suppressed duplicate terminal error (code={}, desc='{}')",
                            tunnel_id_, error_code, description);
        return;
    }

    // Everything after the claim settles through an RAII guard, because any
    // of it can throw (the serializer, the transport callback, a state-change
    // callback) and the claim above is irrevocable — leaving the tunnel
    // un-transitioned, the fence up, or the CLOSE machinery unfenced would
    // strand the tunnel and pin its id for the life of the object. The guard
    // runs on every exit path:
    //  * lowers the releasability fence FIRST, then
    //  * cancel_close_retry() — abandons an Owed CLOSE and fences an
    //    InFlight attempt's verdict, so a late SendqFull cannot restore Owed
    //    and put a CLOSE retry on the wire after this ERROR; its
    //    maybe_notify runs with the fence already down, delivering any
    //    wakeup the fence deferred; then
    //  * notify_close_once().
    // Ordering rationale: the CLOSE fence and the id release both happen
    // only AFTER the ERROR's transport attempt (an id released earlier could
    // be recycled before the frame goes out, and the ERROR would then name
    // the replacement) and after the terminal transition
    // (id_releasable_locked() requires a terminal state, so an owner whose
    // on_id_releasable hook is already installed would otherwise miss its
    // only wakeup). Mirrors the ClaimGuard in emit_close_frame_once().
    struct TerminalSettleGuard {
        TunnelImpl* self;
        ~TerminalSettleGuard() {
            // Each step in its own try: a throwing timer cancellation inside
            // cancel_close_retry() must not skip the close notification, and
            // none of them may propagate out of a destructor.
            self->terminal_error_in_flight_.store(false, std::memory_order_release);
            try {
                self->cancel_close_retry();
            } catch (...) {
            }
            try {
                self->notify_close_once();
            } catch (...) {
            }
        }
    } settle_guard{this};

    // Transport and state/error callbacks run OUTSIDE the mutex — they
    // re-enter the manager, and the state callbacks can re-enter admission,
    // which the seal published above refuses instead of racing the
    // abandonment.
    try {
        auto frame = ProtocolFrame::make_tunnel_error(tunnel_id_, error_code, description);
        send_frame_to_tox(frame);
    } catch (...) {
        util::Logger::warn(
            "Tunnel {} terminal error frame failed to serialize or send; proceeding with "
            "terminal transition",
            tunnel_id_);
    }
    // Conditional, not blind: the ERROR transport callback can re-enter
    // force_close(), which legitimately claims Connected -> Closed before we
    // get here — a blind Error store would overwrite that claimed terminal
    // state. A LOOP rather than a fixed set of attempts: a concurrent
    // NON-terminal move (say Connecting -> Connected while we probe) must
    // not leave the claimed error stranded in a non-terminal state with the
    // id pinned — the claim owes a terminal state, so retry from the freshly
    // observed state until an Error edge lands or a racing terminal claim
    // absorbs it.
    for (;;) {
        const State current = state_.load(std::memory_order_acquire);
        if (current == State::Closed || current == State::Error) {
            util::Logger::debug("Tunnel {} terminal error: state already {}", tunnel_id_,
                                to_string(current));
            break;
        }
        if (transition_state_if(current, State::Error)) {
            break;
        }
        // Lost to a concurrent transition; re-read and try again.
    }

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
        const SendOutcome outcome = send_frame_to_tox_typed(frame);

        if (outcome == SendOutcome::SendqFull) {
            // Transient. Restore the whole outstanding credit — including the
            // part this frame would have carried — and retry from the
            // accumulator rather than replaying a serialized frame, so bytes
            // that arrive during the attempt simply add to it.
            bytes_received_since_ack_.fetch_add(bytes_to_ack, std::memory_order_relaxed);
            util::Logger::debug("Tunnel {} ACK send backpressured; {} bytes still pending",
                                tunnel_id_, bytes_to_ack);
            arm_ack_retry_timer();
            return false;
        }

        if (outcome == SendOutcome::PermanentFail) {
            // Abort WITHOUT restoration — the two non-Sent outcomes are not
            // interchangeable here. Restoring an unsendable credit leaves an
            // accumulator that can never be flushed: every later ACK attempt
            // re-reads it, fails again, restores again, and every
            // notify_tcp_writable() re-arms the retry timer for a peer that is
            // gone. Drop the credit instead. The tunnel itself is torn down by
            // the friend-disconnect path (this outcome means toxcore has no
            // route to the peer at all); publishing a terminal state from here
            // is slice 3's `Abort` machinery, not this one's.
            //
            // Report "nothing left pending" so TcpConnection stops re-arming
            // its low-water watermark on our behalf.
            util::Logger::warn("Tunnel {} ACK send failed permanently; dropping {} byte credit",
                               tunnel_id_, bytes_to_ack);
            return true;
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
// Outbound fence
// ===========================================================================

TunnelImpl::OutboundSnapshot::OutboundSnapshot(TunnelImpl& tunnel) {
    std::lock_guard<std::mutex> lock(tunnel.mutex_);
    // Relaxed is enough for the load: the store side is this very mutex.
    if (tunnel.outbound_gate_closed_.load(std::memory_order_relaxed)) {
        gate_closed_ = true;
        return;
    }
    span_cb_ = tunnel.on_send_to_tox_;
    owned_cb_ = tunnel.on_send_to_tox_owned_;
}

void TunnelImpl::close_outbound_gate() {
    // Stop the CLOSE retry first: it holds a strong self-reference, and with the
    // gate closed every send it could make is a no-op, so retrying could only
    // keep this object alive spinning. Done before taking mutex_ — it takes
    // close_frame_mutex_, and the lock order is mutex_ -> ... not the reverse.
    cancel_close_retry();

    // ONE critical section closes the gate AND publishes the terminal Abort
    // (slice 3, issue #24): one authority, not two. Splitting them was the
    // rejected shape — a window where the gate is closed but admission still
    // accepts (or vice versa) is exactly the kind of observable intermediate
    // state the terminal claim in force_close() had to eliminate. scoped_lock
    // acquires both mutexes deadlock-free; nothing else in this file holds
    // one while taking the other (the slice-2 driver removed the last
    // nesting).
    std::scoped_lock lock(mutex_, coalesce_mutex_);
    publish_abort_locked();
    outbound_gate_closed_.store(true, std::memory_order_release);
    // Belt and braces: drop the callbacks too, so any future code path that
    // forgets to take an OutboundSnapshot still finds nothing to call. The gate
    // — not this swap — is the authoritative check.
    on_send_to_tox_ = nullptr;
    on_send_to_tox_owned_ = nullptr;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

SendOutcome TunnelImpl::send_frame_to_tox_typed(const ProtocolFrame& frame) {
    // The snapshot fuses "is the gate open?" with "copy the callback" into one
    // critical section, so close_outbound_gate() can never slip between them.
    OutboundSnapshot snapshot(*this);
    if (snapshot.gate_closed()) {
        // Report success: SendqFull here would refund the send window and park
        // the frame for a retry that keeps this tunnel alive. See
        // close_outbound_gate().
        return SendOutcome::Sent;
    }

    const auto& cb = snapshot.span_callback();
    if (!cb) {
        return SendOutcome::PermanentFail;
    }
    auto wire = frame.serialize();
    // Called with NO lock held — the callback re-enters ToxAdapter and the
    // manager. The gate tested at snapshot time (not a lock) is what bounds
    // teardown: it stops later senders, not this one.
    return cb(std::span<const uint8_t>(wire.data(), wire.size()));
}

bool TunnelImpl::send_frame_to_tox(const ProtocolFrame& frame) {
    return send_frame_to_tox_typed(frame) == SendOutcome::Sent;
}

bool TunnelImpl::send_owned_data_to_tox(OwnedFrameBuffer buf) {
    OutboundSnapshot snapshot(*this);
    if (snapshot.gate_closed()) {
        return true;  // Discarded; see send_frame_to_tox_typed().
    }

    const auto& owned_cb = snapshot.owned_callback();
    const auto& span_cb = snapshot.span_callback();

    // TUNNEL_DATA only. SendqFull and PermanentFail both mean "not on the wire",
    // and the caller's response is identical for both: retain the bytes in the
    // coalesce buffer and retry on the flush timer. Collapsing them here loses
    // nothing.
    if (owned_cb) {
        return owned_cb(std::move(buf)) == SendOutcome::Sent;
    }
    // Fallback: surface the bytes through the span callback so a partially
    // configured tunnel (e.g. tests that only wire the legacy callback) still
    // works. The wire bytes here are header+payload minus the leading 0xA0
    // lossless prefix — the legacy callback expects exactly that.
    if (span_cb && !buf.empty()) {
        const auto wire = buf.wire_view();
        // Skip the lossless prefix byte that the legacy callback will re-prepend.
        if (wire.size() > 1) {
            return span_cb(std::span<const std::uint8_t>(wire.data() + 1, wire.size() - 1)) ==
                   SendOutcome::Sent;
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

namespace {

/// Refuse to hold a write longer than the operator asked for.
///
/// `tunnel.coalesce_max_delay_us` is a promise: "batch small writes, but never
/// sit on them for more than N microseconds". On Linux and macOS asio honours
/// a 200 us steady_timer to within ~60 us. On Windows it cannot: the timer
/// rides the system tick, and on a Windows 11 ARM64 VM a 200 us timer measured
/// **68 ms mean / 139 ms worst** by default (~4 ms even with
/// timeBeginPeriod(1)). Holding an SSH keystroke for 68 ms to save one frame
/// inverts the trade the setting exists to make, and silently breaks the
/// documented latency bound by two orders of magnitude.
///
/// So on Windows, a sub-tick delay is treated as 0 (emit immediately, the
/// documented "disabled" behaviour) instead of being rounded *up* by the OS.
/// Delays at or above the tick are honoured normally. Nothing changes on
/// POSIX. Raising the system timer resolution process-wide (timeBeginPeriod)
/// is deliberately not done: it is a global, power-consuming side effect, and
/// even then the granularity would not reach the requested microseconds.
[[nodiscard]] std::uint32_t clamp_coalesce_delay_to_platform(std::uint32_t max_delay_us) {
#if defined(_WIN32)
    constexpr std::uint32_t kWindowsTimerTickUs = kMinHonouredCoalesceDelayUs;
    if (max_delay_us > 0 && max_delay_us < kWindowsTimerTickUs) {
        static std::once_flag warned;
        std::call_once(warned, [max_delay_us] {
            util::Logger::warn(
                "tunnel.coalesce_max_delay_us={} is below the Windows timer tick (~{} us); "
                "small writes are emitted immediately instead of being held for tens of "
                "milliseconds. Set a delay >= {} us to actually batch on this platform.",
                max_delay_us, kWindowsTimerTickUs, kWindowsTimerTickUs);
        });
        return 0;
    }
#endif
    return max_delay_us;
}

}  // namespace

void TunnelImpl::configure_coalesce(std::uint32_t max_delay_us, std::uint32_t max_bytes) {
    // Clamp to the Tox-MTU ceiling so a single emitted frame always fits one
    // lossless custom packet.
    std::uint32_t clamped = max_bytes;
    if (clamped == 0 || clamped > kMaxTcpPayloadPerToxFrame) {
        clamped = static_cast<std::uint32_t>(kMaxTcpPayloadPerToxFrame);
    }

    max_delay_us = clamp_coalesce_delay_to_platform(max_delay_us);

    bool drain_now = false;
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        coalesce_max_delay_us_ = max_delay_us;
        coalesce_max_bytes_ = clamped;
        coalescer_.configure(clamped, max_delay_us);
        drain_now = coalesce_max_delay_us_ == 0 && coalesce_pending_locked() > 0;
    }
    // If coalescing was just disabled, drain whatever's queued so order is
    // preserved relative to subsequent direct writes. The driver chunks per
    // cohort cap, so an already-overflowed backlog never produces an
    // oversized frame; a backpressured remainder rides the retry timer.
    if (drain_now) {
        (void)run_emission_driver(DrainPolicy::FlushAll);
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
    // Best-effort full drain (force_close / explicit flush). On Tox
    // backpressure the bytes stay in the FIFO: force_close() is tearing the
    // tunnel down regardless, and the graceful close() path defers via the
    // driver's close bookkeeping.
    (void)run_emission_driver(DrainPolicy::FlushAll);
    // Cancel the flush timer ONLY when the drain actually completed. A
    // backpressured or deferred-to-active-emitter outcome leaves bytes in the
    // FIFO whose sole wakeup is that timer (armed by whichever emitter hit
    // the backpressure) — cancelling it unconditionally stranded them with no
    // driver and no timer, the exact "deferred means drained" conflation the
    // design doc warns about. Both conditions are re-read under the mutex, so
    // an emitter that is still active (and may yet arm the timer) blocks the
    // cancel too.
    std::lock_guard<std::mutex> lock(coalesce_mutex_);
    if (coalesce_pending_locked() == 0 && !driver_active_) {
        coalesce_timer_.cancel();
        coalesce_timer_armed_ = false;
    }
}

void TunnelImpl::publish_abort_locked() {
    outbound_abort_published_.store(true, std::memory_order_release);
    // Abort abandons undelivered DATA. The emission driver tolerates this
    // happening while one of its frames is in flight: the commit step finds
    // an empty FIFO and consumes nothing.
    outbound_fifo_.clear();
    outbound_fifo_pending_ = 0;
    // ...and abandons the close bookkeeping deferred behind that drain:
    // nothing will drain now, so leaving these set would make the next
    // empty-FIFO driver run emit a TUNNEL_CLOSE after the terminal ERROR, or
    // double-settle a close that force_close() already announced through the
    // close-frame latch.
    close_pending_ = false;
    close_pending_full_ = false;
    remote_close_pending_ = false;
}

void TunnelImpl::fifo_append_locked(std::span<const uint8_t> data, std::size_t cap) {
    if (!outbound_fifo_.empty() && outbound_fifo_.back().cap == cap) {
        auto& back = outbound_fifo_.back();
        // Reclaim the consumed prefix before growing, but only once it
        // dominates the live bytes (amortised O(1) per byte), and NEVER while
        // the driver is active: the driver's in-flight frame was selected
        // against this cohort's current offsets, and its consumption commit
        // does `consumed += frame_bytes` — compacting underneath it would
        // make that commit consume the wrong bytes.
        if (!driver_active_ && back.consumed > 0 && back.consumed >= back.pending()) {
            back.bytes.erase(back.bytes.begin(),
                             back.bytes.begin() + static_cast<std::ptrdiff_t>(back.consumed));
            back.consumed = 0;
        }
        back.bytes.insert(back.bytes.end(), data.begin(), data.end());
    } else {
        OutboundCohort cohort;
        cohort.cap = cap;
        cohort.bytes.assign(data.begin(), data.end());
        outbound_fifo_.push_back(std::move(cohort));
    }
    outbound_fifo_pending_ += data.size();
}

EmitOutcome TunnelImpl::run_emission_driver(DrainPolicy policy, bool arm_timer_on_remainder) {
    {
        std::lock_guard<std::mutex> lock(coalesce_mutex_);
        if (policy == DrainPolicy::FlushAll) {
            driver_flush_all_requested_ = true;
        }
        if (driver_active_) {
            // Another thread owns the drain. Its per-iteration re-read of
            // `driver_flush_all_requested_` (under this same mutex) picks up
            // the latched intent, and its exit decision happens under this
            // mutex too, so the request cannot fall between the cracks.
            return EmitOutcome::DeferredToActiveEmitter;
        }
        driver_active_ = true;
    }

    EmitOutcome outcome = EmitOutcome::RequestSatisfied;
    bool emit_full_close = false;
    bool emit_close = false;
    bool finalize_after_drain = false;

    for (;;) {
        // Which outbound path is active. Snapshotted OUTSIDE coalesce_mutex_
        // (the old drain nested mutex_ inside coalesce_mutex_; the driver
        // never holds both).
        bool zero_copy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            zero_copy = static_cast<bool>(on_send_to_tox_owned_);
        }

        // ---- Select one frame under the lock. Nothing is consumed yet:
        // cohort bytes must never be gone from the FIFO while the frame that
        // carries them can still fail and need a retry. ----
        OwnedFrameBuffer owned_frame;
        std::optional<ProtocolFrame> span_frame;
        std::size_t frame_bytes = 0;
        {
            std::lock_guard<std::mutex> lock(coalesce_mutex_);
            while (!outbound_fifo_.empty() && outbound_fifo_.front().pending() == 0) {
                outbound_fifo_.pop_front();
            }
            if (outbound_fifo_.empty()) {
                // Drain complete. Perform the deferred-close bookkeeping that
                // used to live in the flush-timer handler — whichever emitter
                // finishes the drain owes it, or a close deferred behind a
                // backlog another thread happened to drain would never fire.
                if (close_pending_) {
                    close_pending_ = false;
                    // A remote CLOSE deferred behind this same drain is
                    // discharged by this same completion. Leaving the flag set
                    // let a later empty-FIFO driver run (the Batch timer armed
                    // at admission fires regardless) take the remote branch
                    // and finalize a SECOND time — double-counting the
                    // remote-close metric even though notify_close_once()
                    // protects the callback.
                    const bool remote_deferred = remote_close_pending_;
                    remote_close_pending_ = false;
                    if (close_pending_full_) {
                        close_pending_full_ = false;
                        emit_full_close = true;
                        // Peer already closed its side while we drained: our
                        // CLOSE completes the handshake in both directions, so
                        // finalize right after emitting it instead of leaving
                        // the tunnel parked in Disconnecting for the
                        // half-close cap to reap.
                        finalize_after_drain = remote_deferred;
                    } else if (!local_close_sent_) {
                        local_close_sent_ = true;
                        local_stream_done_ = true;
                        emit_close = true;
                        finalize_after_drain = remote_close_received_;
                    } else if (remote_deferred) {
                        // Our CLOSE was already emitted earlier; only the
                        // deferred remote side is left to settle.
                        finalize_after_drain = local_stream_done_;
                    }
                } else if (remote_close_pending_) {
                    remote_close_pending_ = false;
                    finalize_after_drain = local_stream_done_;
                }
                driver_flush_all_requested_ = false;
                driver_active_ = false;
                break;
            }
            auto& front = outbound_fifo_.front();
            if (front.pending() >= front.cap) {
                frame_bytes = front.cap;
            } else if (driver_flush_all_requested_) {
                frame_bytes = front.pending();
            } else {
                // FullFramesOnly with a sub-cap remainder: satisfied by
                // contract (`RequestSatisfied` is deliberately not "Drained").
                // The remainder flushes on the timer — except for the Drain
                // coalesce policy, which holds it for overflow or an explicit
                // flush.
                if (arm_timer_on_remainder) {
                    coalesce_arm_timer_locked();
                }
                driver_active_ = false;
                break;
            }
            const std::span<const std::uint8_t> payload(front.bytes.data() + front.consumed,
                                                        frame_bytes);
            // One payload memcpy out of the cohort into the frame buffer: the
            // bytes were buffered before the final emission boundary was
            // known. The Wave B win — skipping the secondary lossless-prefix
            // allocation in the send callback — is preserved.
            if (zero_copy) {
                owned_frame = OwnedFrameBuffer::with_payload(payload);
                util::MetricsRegistry::instance().inc_outbound_buffer_allocs();
                ProtocolFrame::serialize_tunnel_data_in_place(owned_frame, tunnel_id_);
            } else {
                span_frame.emplace(ProtocolFrame::make_tunnel_data(tunnel_id_, payload));
            }
        }

        // ---- Pre-callback authorization. A terminal Abort published after
        // frame selection (the lock is released) abandoned the FIFO; letting
        // this frame START its send would put DATA on the wire after the
        // terminal ERROR. The design's "a DATA callback already authorised is
        // allowed to return" covers only a callback past this check — the
        // narrow residual between this load and the callback entry is that
        // allowance. ----
        if (outbound_abort_published_.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(coalesce_mutex_);
            driver_flush_all_requested_ = false;
            driver_active_ = false;
            break;  // Abandoned: nothing left that this driver may emit.
        }

        // ---- Emit with NO lock held. Count as emitted BEFORE the (inline,
        // synchronous) send callback: a same-thread ACK round-trip can
        // re-enter handle_tunnel_ack_frame before the send returns, and its
        // acquire-load of total_bytes_emitted_ must already include these
        // bytes or a legitimate ACK is under-credited. Undone on failure. ----
        total_bytes_emitted_.fetch_add(frame_bytes, std::memory_order_release);
        const bool sent = zero_copy ? send_owned_data_to_tox(std::move(owned_frame))
                                    : send_frame_to_tox(*span_frame);

        // ---- Commit or roll back under the lock. The front cohort is stable
        // across the unlocked send: only the driver consumes or pops from the
        // front, and fifo_append_locked never compacts while the driver is
        // active. ----
        {
            std::lock_guard<std::mutex> lock(coalesce_mutex_);
            if (sent) {
                // A terminal Abort (publish_abort_locked) may have abandoned
                // the FIFO while this frame was in flight — the frame reached
                // the transport first and there is nothing left to consume.
                if (!outbound_fifo_.empty()) {
                    auto& front = outbound_fifo_.front();
                    front.consumed += frame_bytes;
                    outbound_fifo_pending_ -= frame_bytes;
                    if (front.consumed == front.bytes.size()) {
                        outbound_fifo_.pop_front();
                    }
                }
                continue;
            }
            // Tox lossless SENDQ is full (transient transport backpressure).
            // NOT a drop point: a lossless tunnel must never lose bytes to a
            // momentarily-full send queue. RETAIN the bytes at the front of
            // their cohort and keep the send window charged so upstream TCP
            // reads pause; the retry timer re-runs the driver. (Earlier
            // revisions erased + refunded here, silently truncating any
            // transfer large/fast enough to outrun the Tox congestion window
            // — observed as a hard ~85-90 KiB cap with the remainder lost.)
            //
            // NOTE: deliberately no "backpressure cleared" line on the success
            // path. A half-full Tox SENDQ makes sends alternate fail/succeed
            // at the retry cadence, so a recovery line would itself flood at
            // kHz rates; the once-per-second throttled line below already
            // reports the burst size via its `[+N suppressed]` suffix.
            total_bytes_emitted_.fetch_sub(frame_bytes, std::memory_order_release);
            util::Logger::debug_throttled(
                backpressure_log_throttle(friend_number_, BackpressureSite::CoalesceDrain),
                "Tunnel {} Tox backpressured; holding {} bytes for retry", tunnel_id_, frame_bytes);
            coalesce_arm_timer_locked();
            driver_flush_all_requested_ = false;
            driver_active_ = false;
            outcome = EmitOutcome::Backpressured;
            break;
        }
    }

    // Deferred-close actions run with no lock held — each of these sends
    // through the Tox callback and/or re-enters the manager.
    if (emit_full_close) {
        emit_close_and_transition();
    }
    if (emit_close) {
        emit_local_close_only();
    }
    if (finalize_after_drain) {
        finalize_remote_close();
    }
    return outcome;
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
        {
            std::lock_guard<std::mutex> lock(self->coalesce_mutex_);
            // Reject stale firings (cancel-and-reset races).
            if (epoch != self->coalesce_timer_epoch_) {
                return;
            }
            self->coalesce_timer_armed_ = false;
        }
        // The timer's job is a full flush; the driver performs the drain with
        // no lock held across any send, re-arms itself on backpressure, and —
        // when the FIFO empties — runs the deferred-close bookkeeping that
        // used to live here. A `DeferredToActiveEmitter` result is fine: the
        // FlushAll intent is latched for the active emitter.
        (void)self->run_emission_driver(DrainPolicy::FlushAll);
    });
}

}  // namespace toxtunnel::tunnel
