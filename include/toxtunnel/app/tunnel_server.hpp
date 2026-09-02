#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/app/rate_limiter.hpp"
#include "toxtunnel/app/rules_engine.hpp"
#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/tox/tox_watchdog.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::app {

/// Pure offset-reconciliation check for tunnel resume (H-07). Given the local
/// side's sent/received byte counts and the peer's reported sent/received
/// counts, returns true if there is a gap — bytes one side transmitted that the
/// other never received. Because there is no app-level retransmit buffer, a gap
/// cannot be filled, so callers either close (on_gap=close) or accept a hole
/// (on_gap=passthrough). Pure — extracted for unit testing.
[[nodiscard]] inline bool resume_offsets_have_gap(uint64_t local_send, uint64_t peer_recv,
                                                  uint64_t local_recv,
                                                  uint64_t peer_send) noexcept {
    return local_send > peer_recv || peer_send > local_recv;
}

/// Pure decision helpers, extracted from TunnelServer so they can be unit
/// tested without standing up a Tox stack. They are in `detail` to say plainly
/// that they are an internal seam, not part of the server's API: nothing
/// outside TunnelServer and its tests should call them, and their signatures
/// may change with the implementation they describe.
namespace detail {

/// What a friend-`connected` callback must do with this friend's TunnelManager.
enum class ConnectedManagerAction {
    KeepExisting,  ///< A live manager is already installed — must NOT be replaced.
    Resurrect,     ///< A manager is parked in held_managers_ (resume) — revive it.
    CreateFresh,   ///< Nothing known about this friend — build a new manager.
};

/// Decide how to service a friend-`connected` event, given the state of the
/// server's two manager maps.
///
/// toxcore does not guarantee that every `connected` transition is preceded by a
/// matching `disconnected` one: after a long outage the friend-connection
/// callback is observed jumping straight back to `connected`. The pre-fix server
/// unconditionally assigned a freshly built manager into `managers_`, so such an
/// unpaired event destroyed the still-live manager — and with it every open
/// tunnel and every target TCP connection — with no log above debug level. The
/// client's subsequent TUNNEL_RESUME_REQUEST then met "no held tunnel; declined".
///
/// Keeping the live manager is always the correct answer: its tunnels and target
/// sockets are intact, its send handler captured the (stable) friend_number, and
/// `handle_resume_request` resolves against `managers_` — so resume works
/// through this branch exactly as it does through a resurrection.
///
/// Pure — extracted for unit testing (see tunnel_resume_test.cpp).
[[nodiscard]] inline ConnectedManagerAction classify_connected_event(bool live_manager_present,
                                                                     bool held_manager_present,
                                                                     bool resume_enabled) noexcept {
    if (live_manager_present) {
        return ConnectedManagerAction::KeepExisting;
    }
    if (resume_enabled && held_manager_present) {
        return ConnectedManagerAction::Resurrect;
    }
    return ConnectedManagerAction::CreateFresh;
}

/// Compute which rules-file public keys still need to be added to the Tox friend
/// list, given the keys already present in it.
///
/// Both inputs are hex public keys in any case; the result is canonical
/// uppercase, de-duplicated, and contains only well-formed 64-char keys. Keys
/// already in @p existing_friend_public_keys are omitted, which is what makes
/// the caller idempotent across repeated startups and hot reloads.
///
/// Pure — extracted for unit testing (see test_tunnel_manager.cpp).
[[nodiscard]] std::vector<std::string> friend_keys_to_preseed(
    const std::vector<std::string>& rule_public_keys,
    const std::vector<std::string>& existing_friend_public_keys);

/// True for inbound frame types that must NOT queue behind a friend's
/// byte-throttle backlog.
///
/// The throttle preserves per-friend arrival order, because a TUNNEL_CLOSE that
/// overtook deferred TUNNEL_DATA would tear the tunnel down and strand those
/// bytes — silent truncation, the exact failure the deferral exists to avoid.
/// Three frame classes are exempt because they carry no stream position and
/// delaying them causes real harm:
///  * PING / PONG — the liveness channel. Held behind a throttled stream, the
///    keepalive would declare a perfectly healthy peer dead and tear down every
///    tunnel it has, losing far more than the throttle ever saved.
///  * TUNNEL_ACK — send-window credit for the *opposite* direction. Deferring
///    it would throttle server->client traffic as collateral of a
///    client->server limit.
///  * INFO_REQUEST / INFO_REPLY and unrecognised opcodes — per-friend control
///    with no tunnel ordering to preserve.
[[nodiscard]] bool frame_bypasses_byte_throttle(tunnel::FrameType type) noexcept;

/// Order-preserving admission gate for one friend's inbound TUNNEL_DATA bytes.
///
/// This is the mechanism that makes `rate_limit.bytes_per_sec` real. A tunnel
/// carries TCP semantics, so an over-budget frame can neither be dropped (that
/// corrupts a lossless stream) nor waited on in place (that would block the
/// shared Tox thread and the inbound strand). Instead the frame is parked in a
/// FIFO and replayed once the bucket refills.
///
/// The queue is self-limiting, which is why deferral is safe: a parked frame is
/// never handed to its tunnel, so no TUNNEL_ACK is generated for it, so the
/// peer's send window fills and the peer stops sending. The throttle therefore
/// propagates all the way back to the origin TCP socket instead of being
/// absorbed here — the same receiver-side backpressure the C-03 slow-target
/// path already relies on.
///
/// TWO RAILS BOUND HOW FAR DEFERRAL CAN GO, and both of them FAIL OPEN — they
/// release the backlog early rather than dropping it or killing the peer,
/// because "the configured rate was briefly exceeded" is a far better outcome
/// than either a corrupted stream or a disconnected friend:
///
///  * `max_backlog_bytes` bounds memory, for a peer that ignores flow control
///    and keeps sending past its unacknowledged window. It is deliberately NOT
///    treated as proof of misbehaviour: a friend with a high
///    `max_concurrent_tunnels` can reach it legitimately (200 tunnels x a
///    256 KiB seed window is already 50 MiB), so closing its tunnels on the
///    strength of this number would punish ordinary traffic.
///  * A per-frame **release deadline** bounds how long a frame may sit. This
///    one is not a nicety: the idle reaper and the half-close linger cap judge
///    a tunnel by when it last saw TUNNEL_DATA, and a parked frame has not
///    reached its tunnel, so deferring makes an actively-receiving tunnel look
///    idle. The reaper would then close it and release its id — and the replay
///    would deliver bytes to a tunnel that no longer exists, or worse, to a
///    recycled id.
///
///    The deadline is supplied per frame by the caller (see
///    `TunnelServer::inbound_deferral_budget`), because "how long is safe" is a
///    property of the frame's TUNNEL, not of the queue: a tunnel that was
///    ALREADY nearly idle when the frame arrived can afford almost no wait,
///    while a busy one can afford the full budget. The throttle keeps the
///    EARLIEST deadline any queued frame asked for and releases the whole
///    backlog at that point — a frame near the back of the queue is exactly the
///    one whose tunnel may be closest to being reaped, so taking the minimum
///    (rather than judging by the head) is what makes the bound sound.
///
/// NOT thread-safe by design: `TunnelServer` owns one per friend and touches it
/// exclusively from `inbound_strand_` handlers, so it needs no lock of its own
/// and — crucially for H-01 — holds none while the caller re-enters the manager
/// to dispatch.
class InboundByteThrottle {
   public:
    /// Memory rail on deferred bytes per friend. See the class comment: this
    /// bounds the queue, it does not accuse the peer of anything.
    static constexpr std::size_t kDefaultMaxBacklogBytes = 32u * 1024u * 1024u;

    /// Fallback deferral ceiling used when no reaper timeout is configured to
    /// derive one from. Generous — nothing forces a release at this point
    /// except the principle that an unboundedly lagging stream is worse than a
    /// briefly unenforced budget.
    static constexpr std::chrono::seconds kDefaultMaxDeferral{60};

    enum class Admission : std::uint8_t {
        Dispatch,  ///< Within budget (or exempt): route this packet now.
        Parked,    ///< Deferred in arrival order; arm a timer for `retry_after()`.
        /// Deferred, AND a rail was hit: the caller must drain immediately
        /// instead of waiting. The drain ignores the budget until the backlog
        /// is empty, so ordering and loss-freedom both hold.
        Release,
    };

    InboundByteThrottle(RateLimiter& limiter, std::string friend_pk,
                        std::size_t max_backlog_bytes = kDefaultMaxBacklogBytes)
        : limiter_(&limiter),
          friend_pk_(std::move(friend_pk)),
          max_backlog_bytes_(max_backlog_bytes) {}

    /// Whether this friend's effective spec engages a byte budget. Recomputed
    /// on connect and after every rules reload, so the (overwhelmingly common)
    /// unlimited friend never touches the limiter's mutex on the data path.
    void set_active(bool active) noexcept { active_ = active; }
    [[nodiscard]] bool active() const noexcept { return active_; }

    /// Override the monotonic clock (nanoseconds) used for release deadlines,
    /// so tests can assert the deadline rail without sleeping.
    void set_clock(std::function<std::int64_t()> now) { clock_ = std::move(now); }

    /// Decide what to do with one inbound packet.
    ///
    /// @param packet      The whole lossless packet, prefix byte included, so a
    ///                    replay goes through the same decode as a live one.
    ///                    Copied only when the packet is actually parked.
    /// @param type        The decoded frame type.
    /// @param data_bytes  TUNNEL_DATA payload size, 0 for every other type.
    /// @param max_wait    Longest this packet may safely be deferred — the
    ///                    caller's judgement of when its tunnel becomes
    ///                    reapable. Tightens the queue's release deadline; see
    ///                    the class comment.
    [[nodiscard]] Admission admit(std::span<const std::uint8_t> packet, tunnel::FrameType type,
                                  std::size_t data_bytes,
                                  std::chrono::nanoseconds max_wait = kDefaultMaxDeferral);

    /// Move the next packet out of the backlog if its bytes now fit the budget
    /// (or if a rail has forced the backlog open). Returns false when the
    /// backlog is empty or its head is still short — in the latter case
    /// `retry_after()` has been refreshed.
    [[nodiscard]] bool next_ready(std::vector<std::uint8_t>& out);

    [[nodiscard]] std::chrono::nanoseconds retry_after() const noexcept { return retry_after_; }
    [[nodiscard]] bool empty() const noexcept { return backlog_.empty(); }
    [[nodiscard]] std::size_t backlog_bytes() const noexcept { return backlog_bytes_; }
    [[nodiscard]] std::size_t backlog_frames() const noexcept { return backlog_.size(); }
    /// True while a rail has forced the backlog open. Cleared once it drains.
    [[nodiscard]] bool releasing() const noexcept { return releasing_; }

    /// Time left before the release deadline, or `nanoseconds::max()` when the
    /// queue is empty. The caller's retry timer MUST NOT sleep past this — a
    /// timer scheduled purely from `retry_after()` (which only knows about the
    /// refill rate) would happily wait a second while a tunnel whose deadline
    /// is 50 ms away gets reaped.
    [[nodiscard]] std::chrono::nanoseconds time_until_release() const;

    /// True once since the deadline rail last latched; reading it clears the
    /// notice. The caller logs from this rather than from `releasing()`,
    /// because a drain that empties the queue clears the latch before it
    /// returns — so by the time the caller looks, `releasing()` is false again
    /// and the release would go unreported.
    [[nodiscard]] bool take_deadline_release_notice() noexcept;

    /// Non-consuming peek at the same notice, so the caller can tell which rail
    /// produced an `Admission::Release` before it drains.
    [[nodiscard]] bool deadline_release_pending() const noexcept {
        return deadline_release_notice_;
    }

    /// Drop the backlog. Used when the friend goes away: the packets belong to
    /// a session the peer has abandoned. Bytes discarded here are NOT lost
    /// silently — they were never acknowledged, so the peer still counts them
    /// as unsent, and tunnel resume's offset reconciliation reports the gap.
    void clear() noexcept;

   private:
    struct Deferred {
        std::vector<std::uint8_t> packet;
        std::size_t data_bytes;
    };

    [[nodiscard]] std::int64_t now_nanos() const;

    RateLimiter* limiter_;
    std::string friend_pk_;
    std::size_t max_backlog_bytes_;
    /// Earliest moment any queued packet asked to be released by; 0 when the
    /// queue is empty. Only ever tightened while the queue is non-empty — a
    /// popped packet's (later) deadline is not given back, which errs towards
    /// releasing early, the safe direction.
    std::int64_t release_deadline_ns_{0};
    std::function<std::int64_t()> clock_;
    bool active_{false};
    /// Latched by either rail; cleared when the backlog empties. Latching (as
    /// opposed to re-testing per packet) is what guarantees the whole queue
    /// drains in one pass instead of releasing the head and re-parking the rest.
    bool releasing_{false};
    /// Set when the deadline rail latches; consumed by
    /// `take_deadline_release_notice()`.
    bool deadline_release_notice_{false};
    std::deque<Deferred> backlog_;
    std::size_t backlog_bytes_{0};
    std::chrono::nanoseconds retry_after_{0};
};

// ---------------------------------------------------------------------------
// Server tunnel publication / abandonment
// ---------------------------------------------------------------------------
//
// Everything below exists because of one asymmetry: the OPEN_ACK gate
// deliberately leaves a server tunnel in `Tunnel::State::None` until its ACK is
// on the wire, and `Tunnel::close()` is a documented no-op in `None`. So every
// teardown that routes through `close()` — including `TunnelManager::
// remove_tunnel()` and `close_all()` — silently does nothing for an unpublished
// tunnel, leaving its target socket open and its accounting unbalanced. These
// helpers own the two transitions out of that state explicitly, and are free
// functions rather than lambdas inside `wire_tcp_to_tunnel()` so they can be
// tested against a real socket.

/// Whether the server's `tunnels_active` gauge has been counted for a tunnel.
///
/// The gauge is incremented at publication (inside the gate's commit) but
/// decremented from a state-change callback that can fire at any time,
/// including before publication ever happens. A plain "already decremented"
/// latch therefore gets it wrong in both directions: it decrements a gauge that
/// was never incremented when a tunnel is abandoned, and it misses the
/// decrement when a terminal transition beats the increment.
enum class ActiveGaugeState : std::uint8_t {
    NotCounted,  ///< Never published.
    Counted,     ///< Published; the gauge owes one decrement.
    Released,    ///< Settled — no further increment or decrement may happen.
};

/// The latch guards the metric SIDE EFFECT, not just the state word.
///
/// A lock-free version of this was wrong in a way that only shows up under
/// concurrency: after the compare-exchange published `Counted`, a release could
/// run before the matching increment had happened. Its decrement saturated at
/// zero and did nothing, and the delayed increment then left the gauge stuck at
/// +1 with nobody left to give it back. Ordering the state word is not enough —
/// the increment and decrement have to be inside the same critical section as
/// the transition that authorises them. The mutex is only ever held across a
/// lock-free atomic counter update, never across a tunnel or manager callback.
struct ActiveGauge {
    std::mutex mutex;
    ActiveGaugeState state{ActiveGaugeState::NotCounted};
};

using ActiveGaugeLatch = std::shared_ptr<ActiveGauge>;

[[nodiscard]] inline ActiveGaugeLatch make_active_gauge_latch() {
    return std::make_shared<ActiveGauge>();
}

/// Current latch state. Test observability only — production code must act
/// through count/release so the side effect stays serialised.
[[nodiscard]] ActiveGaugeState active_gauge_state(const ActiveGaugeLatch& latch);

/// Count this tunnel as active, at most once and never after release.
/// @return true if this call incremented the gauge.
bool active_gauge_count(const ActiveGaugeLatch& latch);

/// Settle the latch, decrementing only if it had actually been counted. Safe to
/// call on a tunnel that was never published; safe to call repeatedly.
void active_gauge_release(const ActiveGaugeLatch& latch);

/// Install every hook that must settle a server tunnel's active-gauge count.
///
/// There are two, and both are needed. A terminal transition covers the paths
/// that reach `Closed`/`Error` directly. `on_close_` covers the one that does
/// not: a graceful close of a published tunnel stops at `Disconnecting`, fires
/// `on_close_`, and then waits for the peer — so a release wired only to
/// terminal states holds the count for as long as the tunnel sits half-closed,
/// and forever when the half-close reaper is disabled.
///
/// @param extra_on_close  The caller's own on_close work, run after the gauge
///                        is settled. May be null.
void wire_active_gauge(tunnel::TunnelImpl& tunnel, ActiveGaugeLatch gauge,
                       std::function<void()> extra_on_close);

/// What `commit_open_ack()` did.
enum class OpenAckCommit : std::uint8_t {
    Published,  ///< Connected, gauge counted, read loop started.
    Detached,   ///< The manager no longer owns this tunnel; resources released.
    Gone,       ///< The tunnel or its socket had already been destroyed.
};

/// Publish a server tunnel, now that its OPEN_ACK is on the wire.
///
/// Verifies that @p weak_manager still owns *this exact tunnel* before
/// publishing anything. A concurrent `close_all()` / `remove_tunnel()` can
/// detach an unpublished tunnel while the ACK is still in flight, and because
/// `close()` no-ops in `None` that detachment leaves the tunnel un-torn-down —
/// so committing afterwards would strand a `Connected` tunnel nobody routes to,
/// with a leaked active-gauge count, an open target socket and a read loop
/// delivering into a manager that has forgotten it. On that path this releases
/// the local resources instead of publishing.
[[nodiscard]] OpenAckCommit commit_open_ack(
    const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
    const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
    const std::weak_ptr<core::TcpConnection>& weak_tcp, std::uint16_t tunnel_id,
    std::uint32_t friend_number, const ActiveGaugeLatch& gauge);

/// Resolve a server tunnel whose OPEN_ACK DID reach the peer but which could
/// not be published after all (detached or destroyed mid-flight).
///
/// Deliberately separate from `abandon_open_ack()`, because the obligation is
/// different. Before the ACK the peer is still in `Connecting` and has never
/// been told the tunnel exists; after it, the peer believes it has a working
/// tunnel and will wait on it indefinitely. Silence is therefore not an option
/// here — the peer has to be told the tunnel is over, with an identity-checked
/// removal so a replacement that recycled the id is untouched.
void abort_open_ack_after_send(const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
                               const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
                               const std::weak_ptr<core::TcpConnection>& weak_tcp,
                               std::uint16_t tunnel_id, std::uint32_t friend_number,
                               const ActiveGaugeLatch& gauge);

/// Resolve a server tunnel whose OPEN_ACK will never be delivered, or whose
/// target died before it was.
///
/// Sends the terminal TUNNEL_ERROR the waiting client needs (a TUNNEL_CLOSE
/// does not complete its `Connecting` state), then releases the local resources
/// EXPLICITLY rather than via `remove_tunnel()` — which would delegate to
/// `close()` and no-op on an unpublished tunnel, leaving the target socket open
/// for as long as the target keeps it open.
void abandon_open_ack(const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
                      const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
                      const std::weak_ptr<core::TcpConnection>& weak_tcp, std::uint16_t tunnel_id,
                      std::uint32_t friend_number, const ActiveGaugeLatch& gauge);

/// Causal barrier between the server's OPEN_ACK and everything that means
/// "this tunnel is usable".
///
/// THE BUG THIS EXISTS TO PREVENT
///
/// The server used to publish the tunnel as `Connected`, count it opened, and
/// call `start_read()` on the target socket immediately after handing the
/// OPEN_ACK to `TunnelManager::send_frame()` — whose bool return says "queued",
/// not "sent". If toxcore was backpressured, the ACK went into the manager's
/// retry queue while TCP reads started at once, and TUNNEL_DATA travels the
/// *per-tunnel* path, not that queue. So data could reach the peer before the
/// ACK that opens it. The client, still in `Connecting`, discards TUNNEL_DATA
/// (see TunnelImpl::handle_tunnel_data_frame) — silent data loss at connection
/// setup, presenting as a peer bug.
///
/// Delaying only `start_read()` while still publishing `Connected` early was
/// considered and rejected: `Connected` is itself an admission signal (it is
/// what lets `send_data_to_tox` accept bytes, and what the resume path reads to
/// decide a tunnel is live), so it has to sit behind the same edge. Everything
/// here is therefore driven by ONE transition: the OPEN_ACK actually being
/// accepted by toxcore.
///
/// The gate holds no strong references — the caller wires it with weak handles
/// — because the connection it is arming owns the callback that owns the gate.
///
/// Thread safety: `start()` runs on the caller's thread, retries on an
/// io_context thread, and `target_gone()` on the TCP strand. All three resolve
/// through one mutex-guarded phase, and no callback is invoked while that mutex
/// is held (H-01).
class OpenAckGate : public std::enable_shared_from_this<OpenAckGate> {
   public:
    /// One attempt to hand the OPEN_ACK to the transport.
    using AckSender = std::function<tunnel::SendOutcome()>;

    /// Publish the tunnel: `Connected`, the open metrics, and `start_read()`.
    /// Invoked at most once, and only after the ACK reached toxcore.
    ///
    /// Returns false when publication did not happen after all — the tunnel was
    /// detached or destroyed while the ACK was in flight. The gate must not then
    /// report itself `Committed`: nothing was published, so a later target death
    /// has no live tunnel for the ordinary close path to act on. A failed commit
    /// has already released its own resources, so the gate does not additionally
    /// run the abandon callback (and the ACK did reach the peer, so there is no
    /// undelivered handshake left to report).
    using CommitFn = std::function<bool()>;

    /// The ACK will never arrive, or the target died before it did. Resolve the
    /// waiting client with a terminal TUNNEL_ERROR and drop the tunnel.
    /// Invoked at most once, and never together with the commit.
    using AbandonFn = std::function<void()>;

    /// Run the ordinary graceful close of an already-published tunnel.
    ///
    /// Needed for exactly one situation: the target died while the commit
    /// callback was still running. `target_gone()` cannot truthfully answer
    /// "the tunnel is live, run your close" at that instant — the tunnel may
    /// still be in `None`, where `Tunnel::close()` is a no-op, and the commit
    /// would then go on to publish `Connected` and start reading a socket that
    /// is already dead. So the gate defers, and calls this once commit has
    /// actually finished.
    using PostCommitCloseFn = std::function<void()>;

    OpenAckGate(asio::io_context& io_ctx, AckSender send_ack, CommitFn commit, AbandonFn abandon,
                PostCommitCloseFn post_commit_close);

    OpenAckGate(const OpenAckGate&) = delete;
    OpenAckGate& operator=(const OpenAckGate&) = delete;
    OpenAckGate(OpenAckGate&&) = delete;
    OpenAckGate& operator=(OpenAckGate&&) = delete;

    /// Attempt the OPEN_ACK now, and keep retrying on the SENDQ backoff
    /// schedule (tunnel/sendq_retry.hpp — deliberately not the coalesce delay,
    /// which is legally 0) until it is sent, permanently fails, or the target
    /// goes away.
    void start();

    /// The target TCP connection died. Returns true when the gate has taken
    /// ownership of the teardown — i.e. the tunnel was never published, so the
    /// caller must NOT run its ordinary `Tunnel::close()` path. Returns false
    /// once the tunnel is live, where the ordinary close is exactly right.
    bool target_gone();

    /// True once the tunnel has been published. Test observability.
    [[nodiscard]] bool committed() const;

    /// OPEN_ACK send attempts made so far (initial + retries). Test
    /// observability: asserts that the retry cadence is not a spin.
    [[nodiscard]] unsigned attempts() const noexcept {
        return attempts_.load(std::memory_order_relaxed);
    }

   private:
    /// Both intermediate phases exist because a resolution is not instantaneous
    /// and the gap is observable to `target_gone()` running on the TCP strand.
    ///
    ///  * `Sending` — a send is inside the transport. Resolving to `Abandoned`
    ///    here would let that send emit an OPEN_ACK *after* the TUNNEL_ERROR
    ///    and after the tunnel was removed, so the peer would see an ACK for a
    ///    tunnel it had just been told had failed. The sender resolves instead.
    ///  * `Committing` — the commit callback is running but has not finished.
    ///    Reporting `Committed` here would send the caller down the ordinary
    ///    close path against a tunnel that is still `None`, where close() is a
    ///    no-op — and commit would then publish `Connected` and start reading a
    ///    dead socket.
    enum class Phase : std::uint8_t {
        Pending,     ///< Idle between attempts; a retry may be armed.
        Sending,     ///< An ACK send is in flight on some thread right now.
        Committing,  ///< ACK accepted; the commit callback is running.
        Committed,   ///< Commit finished; the tunnel is published.
        Abandoned,   ///< Resolved with a TUNNEL_ERROR instead.
    };

    void attempt(unsigned retry);
    void arm_retry(unsigned retry);

    /// Drop every callback and cancel the retry timer. Caller holds `mutex_`.
    void release_callbacks_locked();

    asio::steady_timer timer_;
    mutable std::mutex mutex_;
    Phase phase_{Phase::Pending};
    /// Set when `target_gone()` arrives during `Sending` or `Committing`; the
    /// thread that owns that phase consumes it when it finishes.
    bool target_gone_requested_{false};
    AckSender send_ack_;
    CommitFn commit_;
    AbandonFn abandon_;
    PostCommitCloseFn post_commit_close_;
    std::atomic<unsigned> attempts_{0};
};

/// The `TUNNEL_ERROR` a failed target connect should produce.
struct OpenFailureReason {
    std::uint8_t code{};
    std::string description;
};

/// Classify a failed `async_connect` into a wire error code plus description.
///
/// NUMERIC, NOT TEXTUAL. The predecessor of this code grepped `ec.message()`
/// for "refused", which is not portable: C++ only requires `message()` to
/// describe the error — no guaranteed wording, casing or language — and on
/// Windows asio obtains it through `FormatMessage`, whose language follows the
/// machine locale. On a non-English Windows host the genuine refusal was
/// therefore misclassified. Comparing against `asio::error::connection_refused`
/// is exact on every platform, because asio builds both codes the same way.
///
/// The refused branch still emits the fixed lowercase literal
/// "TCP connection refused: " ahead of the platform message. That is not
/// decoration: clients <= v0.4.11 identify a refusal by substring, so appending
/// only `ec.message()` would carry the locale bug into every deployed old
/// client. See tunnel_open_outcome_for().
///
/// PRECONDITION: @p ec comes from an asio operation, so it carries asio's
/// system category. A `std::errc::connection_refused` built in the *generic*
/// category does not compare equal to `asio::error::connection_refused` and
/// would fall to code 2. That is not a portability gap in the comparison —
/// asio's own error is what the caller passes, and it matches on every
/// platform (guarded by a real refused-connect test, not a synthesised code).
[[nodiscard]] inline OpenFailureReason open_failure_for_connect_error(const std::error_code& ec) {
    if (ec == asio::error::connection_refused) {
        return {3, "TCP connection refused: " + ec.message()};
    }
    return {2, "TCP connect failed: " + ec.message()};
}

}  // namespace detail

/// Server application that accepts Tox friend connections and tunnels
/// their traffic to local TCP targets based on access control rules.
///
/// TunnelServer orchestrates all components: IoContext for async I/O,
/// ToxAdapter for Tox network communication, RulesEngine for access
/// control, and per-friend TunnelManagers for tunnel lifecycle.
///
/// Typical usage:
/// @code
///   Config config = Config::default_server();
///   TunnelServer server;
///   auto result = server.initialize(config);
///   if (!result) { /* handle error */ }
///   server.start();
///   // ... server runs until stop() is called ...
///   server.stop();
/// @endcode
// Grants tests access to the private resume machinery (issue #31) without a
// live toxcore link. Defined only in the test binary.
class TunnelServerResumeTestAccess;

class TunnelServer {
   public:
    friend class TunnelServerResumeTestAccess;

    TunnelServer();
    ~TunnelServer();

    // Non-copyable, non-movable.
    TunnelServer(const TunnelServer&) = delete;
    TunnelServer& operator=(const TunnelServer&) = delete;
    TunnelServer(TunnelServer&&) = delete;
    TunnelServer& operator=(TunnelServer&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Initialize the server with the given configuration.
    ///
    /// Loads access rules, configures and initializes the ToxAdapter.
    ///
    /// @param config  Server configuration.
    /// @return An empty Expected on success, or an error description.
    [[nodiscard]] util::Expected<void, std::string> initialize(const Config& config);

    /// Start the server: run the IoContext, start the ToxAdapter,
    /// bootstrap DHT, and log the Tox ID.
    void start();

    /// Stop the server: close all tunnel managers, stop the ToxAdapter,
    /// and stop the IoContext.
    void stop();

    /// Return true if the server is currently running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Hot-reload the reloadable subset of the configuration. Currently:
    ///   - `server.rules_file` contents (re-read + atomic RulesEngine swap)
    ///   - `logging.level` (forwarded to `spdlog::set_level`)
    ///
    /// Non-reloadable fields are rejected via `util::check_reloadable`. The
    /// caller is expected to have already re-read and validated the new
    /// `Config` from disk. On any error the running server keeps its previous
    /// state — this is a strict no-op-on-failure contract so SIGHUP cannot
    /// brick the daemon.
    ///
    /// Thread-safe: safe to call from a signal handler thread; rules are
    /// swapped under a writer lock that briefly blocks concurrent
    /// `RulesEngine::evaluate()` callers on the IO pool.
    [[nodiscard]] util::Expected<void, std::string> reload(const Config& new_config);

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the Tox ID as a hex string.
    ///
    /// @pre initialize() has been called successfully.
    [[nodiscard]] std::string get_tox_address() const;

   private:
    // -----------------------------------------------------------------
    // Callback handlers
    // -----------------------------------------------------------------

    /// Handle incoming friend requests by auto-accepting them.
    void on_friend_request(const tox::PublicKeyArray& public_key, std::string_view message);

    /// Handle friend connection status changes.
    /// Creates a TunnelManager when a friend comes online,
    /// destroys it when the friend goes offline.
    void on_friend_connection(uint32_t friend_number, bool connected);

    /// Handle incoming lossless packets.
    /// Deserializes the ProtocolFrame and routes it to the
    /// friend's TunnelManager.
    void on_lossless_packet(uint32_t friend_number, const uint8_t* data, std::size_t length);

    /// Handle self connection status changes (DHT connectivity).
    void on_self_connection(bool connected);

    // -----------------------------------------------------------------
    // Inbound byte throttle (rate_limit.bytes_per_sec)
    // -----------------------------------------------------------------

    /// Route one decoded inbound frame: OPEN, RESUME_REQUEST, or the friend's
    /// TunnelManager. Split out of `on_lossless_packet()` so a frame the byte
    /// throttle deferred is replayed through exactly the same path it would
    /// have taken had it arrived within budget.
    ///
    /// Runs on `inbound_strand_` with no server lock held (H-01).
    void dispatch_inbound_frame(uint32_t friend_number, const tunnel::ProtocolFrame& frame);

    /// Replay a friend's deferred packets as its byte bucket refills, then
    /// re-arm the retry timer if any remain. Strand-confined.
    void drain_inbound_backlog(uint32_t friend_number);

    /// Schedule the next backlog drain for a friend, if one is not already
    /// scheduled. Strand-confined.
    void arm_inbound_retry(uint32_t friend_number);

    /// Longest one inbound frame may safely sit in a friend's throttle backlog.
    ///
    /// Computed per frame from ITS tunnel's remaining reaper slack — the
    /// idle-reaper and half-close timeouts minus how long that tunnel has
    /// already been idle, minus reaper-tick margin — because a tunnel that was
    /// nearly idle when the frame arrived can afford almost no wait. A fixed
    /// budget cannot express that, and getting it wrong means the reaper closes
    /// a tunnel with bytes still queued for it.
    [[nodiscard]] std::chrono::nanoseconds inbound_deferral_budget(uint32_t friend_number,
                                                                   uint16_t tunnel_id) const;

    /// Recompute `active()` on every known friend's throttle from the current
    /// limiter specs. Posted onto `inbound_strand_` after a rules reload so a
    /// newly added (or removed) byte budget takes effect without a reconnect.
    void refresh_inbound_throttles();

    /// Apply the v0.4 adaptive coalescer mode + BDP flow control config to a
    /// freshly-built server-side tunnel.
    void apply_coalesce_and_flow_control(tunnel::TunnelImpl& tunnel);

    /// Push the rules engine's rate-limit configuration (defaults + per-
    /// friend specs) into the process-wide RateLimiter. Idempotent; called
    /// after every rules load / reload.
    void sync_rate_limiter();

    /// Apply the friend's effective `rate_limit.max_concurrent_tunnels` to a
    /// manager's tunnel ceiling (0 => the default 100, else clamped to
    /// RateLimiter::kAbsoluteTunnelCap). MUST be called without managers_mutex_
    /// held: it resolves the friend pk via the Tox thread, which itself takes
    /// managers_mutex_ on the inbound path.
    /// `pk_hex` lets a caller that already has the friend's public key hand it
    /// in. Resolving it here marshals to the Tox thread and blocks until its
    /// next tick, which is fine on the reload path but not on the lifecycle
    /// strand — that strand also carries inbound frames, so a blocked handler
    /// stalls data, not just the connect event.
    void apply_tunnel_cap(tunnel::TunnelManager& manager, uint32_t friend_number,
                          std::string_view pk_hex = {});

    /// Re-apply per-friend `rate_limit.max_concurrent_tunnels` to every live and
    /// held TunnelManager, so a hot-reloaded rules_file takes effect immediately
    /// instead of only on the next reconnect. setup_tunnel_manager() applies the
    /// cap to fresh and resurrected managers; this covers the already-connected ones.
    void reapply_tunnel_caps();

    /// Add every public key named in the access rules to the Tox friend list
    /// (`tox_friend_add_norequest`), skipping the ones already there.
    ///
    /// Without this, `on_friend_request()` is the server's ONLY path into the
    /// friend list, and it refuses any key that is not yet in rules.yaml. That
    /// makes the most common first-run ordering mistake — start the client, then
    /// add its key to rules.yaml — stick: the client has already persisted the
    /// server in its own `tox_save.dat`, so toxcore never re-sends the friend
    /// request, and no amount of reloading or restarting on either side
    /// produces one. It is recoverable only by intervening on the *client*
    /// (delete its saved friendship, or its whole identity, so a fresh request
    /// is sent) — which is not something the server operator can do or would
    /// guess. Pre-seeding closes the hole by treating rules.yaml as the
    /// authoritative allowlist in both directions.
    ///
    /// Called at the end of `initialize()` and after every successful
    /// `reload()`. Idempotent: an already-present key is skipped, so no
    /// duplicate-add error is logged and no redundant `tox_save.dat` write
    /// happens. Removing a key from rules.yaml deliberately does NOT remove the
    /// friend — see the implementation comment.
    ///
    /// Thread-safe: `ToxAdapter::get_friend_info_list()` and
    /// `add_friend_norequest()` both marshal onto the Tox thread themselves
    /// (`run_on_tox_thread`), so this may be called from the main/signal thread.
    /// MUST be called with no lock on `rules_mutex_` held — it blocks on the Tox
    /// thread, which takes that lock on the inbound-frame path.
    void preseed_friends_from_rules();

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Set up a TunnelManager for a newly connected friend.
    /// `pk_hex` is threaded through from on_friend_connection(), which resolves
    /// it cheaply on the Tox thread; see apply_tunnel_cap().
    void setup_tunnel_manager(uint32_t friend_number, std::string_view pk_hex = {});

    /// Tear down the TunnelManager for a disconnected friend.
    void teardown_tunnel_manager(uint32_t friend_number);

    /// Handle a TUNNEL_OPEN request: check access rules,
    /// create TcpConnection, and wire data flow.
    void handle_tunnel_open(uint32_t friend_number, const tunnel::ProtocolFrame& frame);

    /// Handle an inbound TUNNEL_RESUME_REQUEST (H-07). When resume is enabled,
    /// the friend's prior manager was held across the disconnect and resurrected
    /// in setup_tunnel_manager(), so the prior tunnel (+ its target TCP) is still
    /// present: reconcile byte offsets via resume_offsets_have_gap() and either
    /// continue the stream (RESUME_ACK Ok) or, on a gap with on_gap=close, reply
    /// a decline and drop the tunnel. When resume is disabled or the hold has
    /// expired, reply with a decline so the client re-opens. Never silently
    /// drops the frame.
    void handle_resume_request(uint32_t friend_number, const tunnel::ProtocolFrame& frame);

    /// Send a TUNNEL_RESUME_ACK to a friend (H-07 helper).
    void send_resume_ack(uint32_t friend_number, uint16_t tunnel_id, uint64_t server_recv_offset,
                         uint64_t server_send_offset, tunnel::TunnelResumeStatus status);

    /// Wire a TCP connection to a tunnel for bidirectional data flow.
    void wire_tcp_to_tunnel(uint32_t friend_number, uint16_t tunnel_id,
                            std::shared_ptr<core::TcpConnection> tcp_conn);

    /// Get the hex public key string for a friend number.
    [[nodiscard]] std::string get_friend_pk_hex(uint32_t friend_number) const;

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// Configuration snapshot.
    Config config_;

    /// Async I/O thread pool.
    std::unique_ptr<core::IoContext> io_context_;

    /// Serializes inbound lossless-packet dispatch on top of io_context_'s
    /// pool. Without this, frames a friend sends back-to-back (e.g. ACK
    /// then DATA, or several DATA chunks) can be picked up by different
    /// worker threads and processed out of order — DATA arriving before
    /// the receiver has transitioned the tunnel into Connected is silently
    /// dropped. The strand preserves arrival order while keeping the rest
    /// of the IO pool parallel.
    std::optional<asio::strand<asio::any_io_executor>> inbound_strand_;

    /// Per-friend inbound byte-throttle state.
    ///
    /// STRAND-CONFINED, not mutex-protected: every member is created, read,
    /// mutated and destroyed inside an `inbound_strand_` handler. That is what
    /// lets the data-path gate run without acquiring any server lock, so it
    /// cannot participate in the re-entrancy H-01 warns about.
    struct FriendInbound {
        detail::InboundByteThrottle throttle;
        /// Cached hex public key. Resolved once on the friend-connected event
        /// (where the lookup runs inline on the Tox thread) rather than per
        /// frame: `get_friend_pk_hex()` marshals to the Tox thread and blocks
        /// until its next tick, which on the data path would cost ~50 ms per
        /// frame and stall the whole strand.
        std::string pk_hex;
        std::shared_ptr<asio::steady_timer> retry_timer;
        /// True while a drain is scheduled. Re-arming a pending timer would
        /// cancel it, and the cancelled handler would then clear this flag
        /// after the new arm set it.
        bool retry_armed{false};
        /// Whether this friend's mode is `enforce` (as opposed to `report`,
        /// which meters but never defers). Only an enforcing friend can park a
        /// frame, so only it needs a release deadline computed — and computing
        /// one costs a managers_mutex_ lookup per frame.
        bool enforcing{false};
    };
    std::unordered_map<uint32_t, FriendInbound> inbound_;

    /// Tox network adapter.
    std::unique_ptr<tox::ToxAdapter> tox_adapter_;

    /// Tox-thread watchdog. Optional; constructed at start() when
    /// `config_.watchdog.enabled` is true.
    std::unique_ptr<tox::ToxWatchdog> watchdog_;

    /// Access control engine. Reads (`evaluate()`) take a shared lock,
    /// SIGHUP reload (`reload()`) takes a unique lock to swap the engine in
    /// place. Without the shared_mutex, a concurrent IO-thread read during
    /// reload would race with the move-assignment.
    RulesEngine rules_engine_;
    mutable std::shared_mutex rules_mutex_;

    /// Map of friend_number -> TunnelManager.
    ///
    /// shared_ptr (not unique_ptr): callbacks running on the io_context
    /// strand routinely retrieve a manager pointer under
    /// `managers_mutex_`, release the lock, then call into the manager.
    /// A concurrent `on_friend_connection(offline)` on the Tox thread
    /// could erase the unique_ptr between the lookup and the call. The
    /// shared_ptr lets each call site copy the handle inside the lock
    /// and keep the manager alive across the unlocked call (T1/C-1/C-2
    /// in the 2026-05-20 review).
    std::unordered_map<uint32_t, std::shared_ptr<tunnel::TunnelManager>> managers_;

    /// A manager held alive across a brief friend disconnect so its tunnels +
    /// target TCP connections can be reattached on reconnect (H-07 resume).
    /// `prune_timer` closes the held tunnels after resume.max_age_seconds if
    /// the friend never comes back.
    struct HeldManager {
        std::shared_ptr<tunnel::TunnelManager> manager;
        std::shared_ptr<asio::steady_timer> prune_timer;
    };
    /// friend_number -> held manager (resume hold). Guarded by managers_mutex_.
    std::unordered_map<uint32_t, HeldManager> held_managers_;

    /// Seam for sending a serialized RESUME_ACK (issue #31 testability). Null in
    /// production (send_resume_ack falls back to the toxcore lossless send); a
    /// test installs a capture to drive handle_resume_request() without
    /// toxcore. Args: friend number, prefixed packet bytes.
    std::function<void(std::uint32_t, const std::vector<std::uint8_t>&)> resume_ack_sender_;

    /// Protects managers_ map AND held_managers_. Recursive to avoid
    /// self-deadlock when callbacks (e.g., on_disconnect) re-enter while the
    /// lock is held.
    mutable std::recursive_mutex managers_mutex_;

    /// Whether the server is running.
    std::atomic<bool> running_{false};

    /// Local IPC server backing `toxtunnel inspect`.
    std::unique_ptr<InspectServer> inspect_server_;

    /// Optional Prometheus /metrics HTTP server (only when config.metrics.enabled).
    std::unique_ptr<util::MetricsServer> metrics_server_;
};

}  // namespace toxtunnel::app
