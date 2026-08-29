#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace toxtunnel {

/// Arithmetic ceiling on `bytes_per_sec` / `bytes_burst`.
///
/// The refill maths multiplies a budget by 1e9 (nanoseconds per second) in
/// `std::int64_t`; `__int128` is not available on MSVC, so the only defence
/// against a wrapped-to-negative refill is to keep the operands small enough
/// that the product fits. 1e9 leaves the largest product at 1e18, comfortably
/// under INT64_MAX. It is also ~1 GB/s, three orders of magnitude past what a
/// Tox tunnel can carry, so no reachable configuration is affected.
inline constexpr std::uint64_t kMaxByteBudget = 1'000'000'000ULL;

/// Floor applied to an *engaged* `bytes_burst` (one that is non-zero, i.e. the
/// operator did not opt out).
///
/// A token bucket cannot admit an item larger than its capacity, and the
/// TUNNEL_DATA payload can be up to `kMaxPayloadSize` (65535) bytes. A burst
/// below that would leave such a frame permanently unservable: the throttle
/// would defer it forever and the tunnel would stall with no error and no
/// timeout. Raising the capacity to one maximum-size frame makes progress
/// unconditional — every frame the wire can carry fits once the bucket fills.
inline constexpr std::uint64_t kMinActiveByteBurst = 65'535ULL;

// ---------------------------------------------------------------------------
// RateLimitMode
// ---------------------------------------------------------------------------

/// What to do when a friend exceeds its rate limit.
enum class RateLimitMode : std::uint8_t {
    /// Disable rate limiting for this friend (or globally if set as default).
    Off = 0,
    /// Track usage and increment counters but do not deny.
    Report = 1,
    /// Enforce the limits.
    ///
    /// Two different enforcement shapes, because the two budgets guard
    /// different things:
    ///  * `open_per_sec` / `max_concurrent_tunnels` govern a *request*, which
    ///    can be refused outright — an over-budget TUNNEL_OPEN receives
    ///    TUNNEL_ERROR and no tunnel is created.
    ///  * `bytes_per_sec` / `bytes_burst` govern a *stream*, which cannot.
    ///    Refusing a TUNNEL_DATA frame would punch a hole in a lossless byte
    ///    stream, so the server instead defers the frame in arrival order and
    ///    replays it once the bucket refills. Deferral withholds the frame's
    ///    TUNNEL_ACK too, so the peer's send window closes and it stops
    ///    sending — the throttle propagates back to the origin socket rather
    ///    than being absorbed by an unbounded queue. No byte is ever dropped.
    Enforce = 2,
};

[[nodiscard]] constexpr std::string_view to_string(RateLimitMode m) noexcept {
    switch (m) {
        case RateLimitMode::Off:
            return "off";
        case RateLimitMode::Report:
            return "report";
        case RateLimitMode::Enforce:
            return "enforce";
    }
    return "unknown";
}

/// Parse a YAML string-typed rate-limit mode. Returns true on success.
[[nodiscard]] bool parse_rate_limit_mode(std::string_view s, RateLimitMode& out) noexcept;

// ---------------------------------------------------------------------------
// RateLimitSpec — resolved configuration for one friend (or the defaults).
// ---------------------------------------------------------------------------

/// Fully resolved rate-limit configuration for one friend. This is what the
/// buckets are driven from: every field carries a concrete value, and 0 means
/// "no limit" (there is no "unset" state here — see `RateLimitOverride`).
///
/// Maps directly to the top-level YAML `rate_limit_defaults:` block; a
/// per-friend `rate_limit:` block parses into a `RateLimitOverride` that is
/// merged onto these defaults.
struct RateLimitSpec {
    RateLimitMode mode = RateLimitMode::Off;
    /// Token refill rate for `TUNNEL_OPEN` (frames/sec). 0 = unlimited.
    std::uint32_t open_per_sec = 0;
    /// Token bucket capacity for `TUNNEL_OPEN`. 0 = no burst budget.
    std::uint32_t open_burst = 0;
    /// Byte refill rate for inbound `TUNNEL_DATA` payload (bytes/sec).
    /// 0 = unlimited. Enforced by deferring over-budget frames — see the note
    /// on `RateLimitMode::Enforce`. Clamped to `kMaxByteBudget` when stored.
    ///
    /// Like `open_per_sec`/`open_burst`, the rate and the burst BOTH have to be
    /// non-zero for the bucket to engage: a rate with no capacity can hold no
    /// tokens, so the pair is treated as "not configured".
    std::uint64_t bytes_per_sec = 0;
    /// Byte bucket capacity. 0 = no burst budget (limiting off, see
    /// `bytes_per_sec`). A non-zero value is raised to `kMinActiveByteBurst`
    /// and clamped to `kMaxByteBudget` when stored.
    std::uint64_t bytes_burst = 0;
    /// Hard ceiling on concurrent tunnels per friend. 0 means "use the
    /// hard-coded default" (100, matching the v0.3.0 ceiling).
    std::uint32_t max_concurrent_tunnels = 0;

    /// Provenance bit, not a limit: true when this spec was materialised from
    /// a `rate_limit_defaults:` key that actually appears in the rules
    /// document (see `convert<RateLimitSpec>::decode`).
    ///
    /// It exists because the *values* cannot distinguish "the operator wrote
    /// `rate_limit_defaults: {mode: off}`" from "there is no defaults block at
    /// all" — both are `mode == Off` with every counter 0, i.e. `empty()`.
    /// `merged_onto` needs that distinction: an absent block gets the
    /// backwards-compatible "a per-friend block turns limiting on" fallback,
    /// while a present block must be inherited verbatim, `mode: off`
    /// included. Conflating the two silently re-enabled enforcement on an
    /// operator who had explicitly switched it off.
    ///
    /// Deliberately excluded from `empty()` (which is about limit values) but
    /// included in `operator==`, so a spec that came from a real block never
    /// compares equal to a synthesised one.
    bool defaults_present = false;

    [[nodiscard]] bool empty() const noexcept {
        return mode == RateLimitMode::Off && open_per_sec == 0 && open_burst == 0 &&
               bytes_per_sec == 0 && bytes_burst == 0 && max_concurrent_tunnels == 0;
    }

    /// True when any byte-bucket field carries a value. Note this is weaker
    /// than "byte limiting is engaged", which additionally needs BOTH fields
    /// non-zero and a mode other than `Off`.
    [[nodiscard]] bool has_byte_limits() const noexcept {
        return bytes_per_sec != 0 || bytes_burst != 0;
    }

    /// True when this spec actually shapes TUNNEL_DATA — i.e. the server must
    /// meter that friend's inbound bytes. `Report` counts as engaged: it never
    /// defers, but it has to account so the throttle counter moves.
    [[nodiscard]] bool byte_limiting_engaged() const noexcept {
        return mode != RateLimitMode::Off && bytes_per_sec != 0 && bytes_burst != 0;
    }

    bool operator==(const RateLimitSpec& other) const = default;
};

/// Bring a spec's byte budgets into the range the bucket arithmetic can
/// actually service: clamp both fields to `kMaxByteBudget` (overflow rail) and
/// raise an engaged `bytes_burst` to `kMinActiveByteBurst` (livelock rail).
///
/// Applied wherever a spec is *stored* into the limiter, so `effective_spec()`
/// reports the budget the daemon really enforces rather than the one the
/// operator wrote. Every other field is passed through untouched.
[[nodiscard]] RateLimitSpec normalise_byte_budgets(RateLimitSpec spec) noexcept;

// ---------------------------------------------------------------------------
// RateLimitOverride — a per-friend `rate_limit:` block, field-by-field.
// ---------------------------------------------------------------------------

/// Sparse form of `RateLimitSpec`: only the fields the operator actually wrote
/// in a friend's `rate_limit:` block are engaged.
///
/// The distinction matters because `RateLimitSpec` overloads `0` to mean both
/// "unlimited" and "not configured". Storing a per-friend block as a plain
/// spec therefore made every unwritten field read as an explicit "unlimited"
/// and wiped out `rate_limit_defaults` wholesale — tightening one field
/// (`max_concurrent_tunnels: 2`) silently switched the friend's OPEN limiting
/// *off*. Keeping the written-ness here lets `merged_onto` layer the override
/// on top of the defaults per field, and lets an explicit `open_per_sec: 0`
/// mean "this friend is exempt from the default OPEN rate".
struct RateLimitOverride {
    std::optional<RateLimitMode> mode;
    std::optional<std::uint32_t> open_per_sec;
    std::optional<std::uint32_t> open_burst;
    std::optional<std::uint64_t> bytes_per_sec;
    std::optional<std::uint64_t> bytes_burst;
    std::optional<std::uint32_t> max_concurrent_tunnels;

    /// True when the operator wrote no fields at all (an absent or empty
    /// `rate_limit:` block) — such a friend simply inherits the defaults.
    [[nodiscard]] bool empty() const noexcept {
        return !mode && !open_per_sec && !open_burst && !bytes_per_sec && !bytes_burst &&
               !max_concurrent_tunnels;
    }

    /// True when a byte-bucket field was explicitly written to a non-zero
    /// value. An explicit `bytes_per_sec: 0` is an opt-*out*, not a request
    /// for byte limiting.
    [[nodiscard]] bool has_byte_limits() const noexcept {
        return bytes_per_sec.value_or(0) != 0 || bytes_burst.value_or(0) != 0;
    }

    /// Layer this override onto `base`, field by field.
    [[nodiscard]] RateLimitSpec merged_onto(const RateLimitSpec& base) const noexcept;

    /// Build an override in which every field is explicitly written. Used by
    /// callers that genuinely mean "replace the whole spec".
    [[nodiscard]] static RateLimitOverride from_spec(const RateLimitSpec& spec);

    bool operator==(const RateLimitOverride& other) const = default;
};

// ---------------------------------------------------------------------------
// RateLimiter — runtime per-friend token buckets.
// ---------------------------------------------------------------------------

/// Per-friend rate-limit enforcement. Built on lazy-refill token buckets so
/// the hot path is one atomic CAS per inbound TUNNEL_OPEN / TUNNEL_DATA.
///
/// Friends are keyed by the hex-encoded public key (case-insensitive). On
/// first use the limiter clones the default spec (set via
/// `set_default_spec`) into a per-friend slot; an explicit per-friend
/// `set_friend_spec` is remembered as a sparse `RateLimitOverride` and
/// re-merged onto the defaults whenever either side changes.
///
/// Thread safety: all public methods are safe to call from any thread.
class RateLimiter {
   public:
    /// Hard process-wide upper bound on `max_concurrent_tunnels` — a safety
    /// rail against a typo that would otherwise lead to unbounded memory
    /// growth on a single friend.
    static constexpr std::uint32_t kAbsoluteTunnelCap = 10000;

    RateLimiter() = default;

    /// Monotonic time source, in nanoseconds. Defaults to `steady_clock`.
    using NowNanosFn = std::function<std::int64_t()>;

    /// Replace the clock the token buckets refill against.
    ///
    /// Exists for tests: byte enforcement is a *rate*, and the only honest way
    /// to assert a rate is to control the passage of time. Sleeping instead
    /// would make the assertions hostage to scheduler jitter — fatal on the
    /// Windows ARM CI runner, whose timer granularity is ~15.6 ms. Production
    /// never calls this.
    ///
    /// Any pending refill cursors are reset, so the new clock's epoch does not
    /// read as a colossal elapsed time and instantly refill every bucket.
    void set_clock(NowNanosFn now);

    /// Set / clear the default spec applied to friends without an explicit
    /// per-friend entry. Live buckets have their effective spec recomputed
    /// (defaults re-merged with any stored override) because an override is
    /// only meaningful relative to the defaults it layers onto. Accumulated
    /// token counts survive *this call*, clamped down to any shrunken burst —
    /// the design doc's "tightening doesn't reach in" rule applies to token
    /// state, not to the spec itself.
    ///
    /// That in-place preservation is NOT what a rules reload does, and this
    /// comment used to imply otherwise. `TunnelServer::sync_rate_limiter()`
    /// goes through `replace_all`, which drops every bucket first (it has to:
    /// a friend dropped from the new rules must not keep its old bucket), so
    /// after a SIGHUP every friend starts from a full bucket with zeroed
    /// rejection counters. Preservation here only matters to callers that move
    /// the defaults without a surrounding clear.
    void set_default_spec(const RateLimitSpec& spec);

    /// Install a per-friend override. The `friend_pk` is canonicalised to
    /// lowercase before lookup. Only the fields the override engages are
    /// applied; the rest keep their `set_default_spec` values. Passing an
    /// `empty()` override removes the entry so the friend falls back to the
    /// plain defaults.
    void set_friend_spec(std::string_view friend_pk, const RateLimitOverride& override_spec);

    /// Convenience overload for callers that mean "replace every field":
    /// equivalent to `set_friend_spec(pk, RateLimitOverride::from_spec(spec))`.
    /// An `empty()` spec removes the entry.
    void set_friend_spec(std::string_view friend_pk, const RateLimitSpec& spec);

    /// Drop every per-friend override AND destroy every bucket, token counts
    /// and rejection counters included, so no stale token state survives for a
    /// friend removed from the new rules (or whose override has been removed).
    /// After this call, all friends fall back to the default spec; the caller
    /// is expected to re-install any per-friend specs from the new rules.
    ///
    /// PREFER `replace_all` for a rules reload. This method is the clear step
    /// on its own, and the interval between it and the caller's re-install is
    /// visible to a concurrent `try_consume_open` — see `replace_all`, which is
    /// what `TunnelServer::sync_rate_limiter()` uses. Kept public for tests and
    /// for callers that genuinely only want to wipe state.
    ///
    /// Consequence worth stating plainly, because it is the reload semantics
    /// operators actually get: reloading rules refills every friend's bucket
    /// and resets `open_rejected` / `bytes_throttled` to 0. A friend that is
    /// mid-flood therefore gets a fresh burst allowance on every SIGHUP, and
    /// `toxtunnel inspect`'s per-friend rejection counts restart. This is
    /// deliberate — the alternative is carrying token state across a spec
    /// change that may have removed the friend entirely — but it means the
    /// limiter is not a defence against an attacker who can also trigger
    /// reloads. (Process-wide metrics counters are unaffected: they live in
    /// `MetricsRegistry`, not in the buckets.)
    void clear_all_friend_specs();

    /// One entry of a `replace_all` batch: a friend public key (any case) and
    /// the sparse `rate_limit:` block that friend's rule carried.
    using FriendOverride = std::pair<std::string, RateLimitOverride>;

    /// Atomically install a whole new rules generation: drop every bucket, set
    /// @p defaults, and re-install @p overrides — all under a single hold of
    /// `mu_`.
    ///
    /// WHY THIS EXISTS: a rules reload is *one* logical transition, but
    /// expressing it as `clear_all_friend_specs()` + `set_default_spec()` +
    /// N × `set_friend_spec()` takes and releases the lock 2 + N times. Every
    /// gap is a window in which a concurrent `try_consume_open()` on the Tox
    /// thread sees a half-applied generation and makes a decision no rules file
    /// ever described: after the clear it sees the *old* defaults with the new
    /// per-friend specs missing (a friend whose override tightens the limit is
    /// briefly governed by looser defaults, or vice versa), and between the
    /// clear and the last `set_friend_spec` a friend can be admitted or
    /// rejected against defaults that the very next microsecond replaces.
    /// Doing the whole swap under one lock means a consumer observes either the
    /// entire old generation or the entire new one, never a blend.
    ///
    /// SEMANTICS ARE UNCHANGED from the three-call sequence, deliberately:
    /// every bucket is destroyed, so after a reload each friend starts from a
    /// full burst with `open_rejected` / `bytes_throttled` back at 0. That
    /// reset is the documented behaviour (see `clear_all_friend_specs`) and its
    /// operational consequence — whoever can trigger a reload can refresh their
    /// own burst budget — is called out in `docs/CONFIGURATION.md`. This method
    /// makes the swap atomic; it does not make it token-preserving.
    ///
    /// Entries whose override is `empty()` are skipped (they would inherit the
    /// defaults anyway); a duplicated key keeps the last entry, matching what
    /// repeated `set_friend_spec` calls would have done.
    void replace_all(const RateLimitSpec& defaults, const std::vector<FriendOverride>& overrides);

    /// Look up the effective spec for the given friend public key: the
    /// defaults with any per-friend override merged in field by field.
    [[nodiscard]] RateLimitSpec effective_spec(std::string_view friend_pk) const;

    /// Attempt to consume one TUNNEL_OPEN token. Returns true if the friend
    /// is allowed to proceed (no limit, mode Off/Report, or token available);
    /// false only when the bucket is empty AND the mode is Enforce.
    ///
    /// `Report` mode always returns true but still increments the rejection
    /// counter so operators can see shadow data. It is *count-only*: it never
    /// drives the token bucket negative (see `try_consume_bytes` for the same
    /// contract on the data path).
    [[nodiscard]] bool try_consume_open(std::string_view friend_pk);

    /// Attempt to consume `bytes` from the data-bytes bucket. Returns true if
    /// the friend is within budget. When the request exceeds the available
    /// tokens in `Enforce` mode this returns false.
    ///
    /// Called on the server's inbound-frame strand for every TUNNEL_DATA frame
    /// belonging to a friend whose spec is `byte_limiting_engaged()`. A `false`
    /// return means "defer this frame", never "drop it" — see
    /// `app::detail::InboundByteThrottle`, which owns the deferral queue.
    ///
    /// `Report` mode is *count-only*, mirroring `try_consume_open`: when the
    /// request is short it increments the throttle counter, clamps the bucket
    /// at zero (never negative / never into debt), and returns true.
    ///
    /// A request larger than the whole bucket capacity is charged at capacity
    /// rather than being refused forever. Unreachable from the data path
    /// (`kMinActiveByteBurst` guarantees a maximum-size frame fits), but the
    /// method is public, and a caller that could never be served is a livelock,
    /// not a limit.
    [[nodiscard]] bool try_consume_bytes(std::string_view friend_pk, std::size_t bytes);

    /// Whether a refusal should move the throttle counters.
    ///
    /// A deferred frame is re-offered every time its retry timer fires, and
    /// each of those is a refusal. Counting them all would turn
    /// `toxtunnel_rate_limit_bytes_throttled_total` into "polling attempts",
    /// where one frame parked for a second contributes hundreds — the counter
    /// would then track the retry cadence rather than the traffic. Callers
    /// count a frame once, on first judgement, and re-ask silently.
    enum class ThrottleAccounting : std::uint8_t {
        Count,   ///< First time this payload is judged.
        Silent,  ///< A retry of a payload already counted.
    };

    /// As above, but also reports how long the caller should wait before
    /// retrying. Set to zero on success and in `Report` mode; on an `Enforce`
    /// refusal it is the time the bucket needs to accrue the shortfall,
    /// rounded up so it is never zero (a zero would turn the caller's retry
    /// timer into a busy loop).
    [[nodiscard]] bool try_consume_bytes(std::string_view friend_pk, std::size_t bytes,
                                         std::chrono::nanoseconds& retry_after,
                                         ThrottleAccounting accounting = ThrottleAccounting::Count);

    /// Record that a payload was throttled, without judging it against the
    /// bucket or spending any tokens.
    ///
    /// For a frame the caller deferred because something AHEAD of it is short:
    /// it never reached the bucket, but the budget is exactly why it was
    /// delayed, so it belongs in the count. Without this the counter would
    /// report one frame per congestion episode — the one that found the bucket
    /// empty — rather than the traffic actually held back.
    ///
    /// No-op when the friend's spec has byte limiting off, so a deactivated
    /// throttle draining its residue cannot inflate the counter.
    void note_bytes_throttled(std::string_view friend_pk);

    /// Read-only metric / inspect snapshots. Numbers are eventually
    /// consistent.
    struct State {
        RateLimitSpec spec;
        std::int64_t open_tokens = 0;
        std::int64_t bytes_tokens = 0;
        std::uint64_t open_rejected = 0;
        std::uint64_t bytes_throttled = 0;
    };
    [[nodiscard]] State state(std::string_view friend_pk) const;

   private:
    /// Per-friend bucket state. Atomics so the data-path consumer doesn't
    /// take the rules mutex.
    struct Bucket {
        std::atomic<std::int64_t> open_tokens{0};
        std::atomic<std::int64_t> bytes_tokens{0};
        /// Per-bucket refill cursors (0 = never refilled yet).
        ///
        /// Separate, and advanced only by the time actually converted into
        /// whole tokens, because the byte bucket is now consulted on the data
        /// path. A single shared cursor stamped to `now` on every call
        /// discarded the sub-token remainder, so a caller polling faster than
        /// one token per call — trivially true for a 1362-byte frame against a
        /// modest bytes_per_sec — accrued nothing and starved permanently. The
        /// OPEN bucket never hit this only because opens are rare.
        std::atomic<std::int64_t> open_refill_ns{0};
        std::atomic<std::int64_t> bytes_refill_ns{0};
        std::atomic<std::uint64_t> open_rejected{0};
        std::atomic<std::uint64_t> bytes_throttled{0};
        /// Effective spec — `override_spec.merged_onto(default_spec_)`.
        RateLimitSpec spec;
        /// The friend's own `rate_limit:` block, kept sparse so the merge can
        /// be redone if the defaults change.
        RateLimitOverride override_spec;
    };

    /// Body of `set_friend_spec`, minus the locking. Caller holds `mu_` and has
    /// already run @p key through `normalise_key`. Shared with `replace_all` so
    /// the batch path and the single-key path cannot drift apart.
    void install_friend_spec_locked(const std::string& key, const RateLimitOverride& override_spec);

    Bucket& get_or_create_bucket(const std::string& key) const;
    Bucket* find_bucket(const std::string& key) const;
    void refill(Bucket& b) const;
    /// Current time in nanoseconds from the (possibly injected) clock. Caller
    /// holds `mu_` — `clock_` is swappable.
    [[nodiscard]] std::int64_t now_nanos() const;
    /// Accrue tokens for one bucket. Advances `cursor_ns` by the elapsed time
    /// it actually converted into whole tokens, never past `now_ns`.
    static void refill_one(std::atomic<std::int64_t>& tokens, std::atomic<std::int64_t>& cursor_ns,
                           std::int64_t per_sec, std::int64_t burst, std::int64_t now_ns);
    /// Install `spec` on `b`, clamping any token count down to a shrunken
    /// burst. Caller holds `mu_`.
    static void apply_spec(Bucket& b, const RateLimitSpec& spec);
    static std::string normalise_key(std::string_view friend_pk);

    mutable std::mutex mu_;
    NowNanosFn clock_;
    RateLimitSpec default_spec_;
    mutable std::unordered_map<std::string, std::unique_ptr<Bucket>> buckets_;
};

/// Process-wide singleton for convenience wiring from TunnelServer (which
/// constructs an instance) into TunnelManager (which consults it on every
/// TUNNEL_OPEN). The owner can swap the active instance via `set_instance`.
RateLimiter& rate_limiter_instance();

}  // namespace toxtunnel
