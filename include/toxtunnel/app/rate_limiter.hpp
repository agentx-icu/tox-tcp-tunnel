#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace toxtunnel {

// ---------------------------------------------------------------------------
// RateLimitMode
// ---------------------------------------------------------------------------

/// What to do when a friend exceeds its rate limit.
enum class RateLimitMode : std::uint8_t {
    /// Disable rate limiting for this friend (or globally if set as default).
    Off = 0,
    /// Track usage and increment counters but do not deny.
    Report = 1,
    /// Enforce the limits: rejected OPENs receive TUNNEL_ERROR.
    ///
    /// NOTE: enforcement currently covers the TUNNEL_OPEN path and
    /// `max_concurrent_tunnels` only. The byte buckets
    /// (`bytes_per_sec` / `bytes_burst`) are parsed and refilled but the
    /// data path never consults them — `try_consume_bytes` has no caller
    /// outside the unit tests — so byte limits do not shape traffic. The
    /// rules loader warns when they are configured.
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
    /// Byte refill rate for `TUNNEL_DATA` payload (bytes/sec). 0 = unlimited.
    /// NOT ENFORCED — see the note on `RateLimitMode::Enforce`.
    std::uint64_t bytes_per_sec = 0;
    /// Byte bucket capacity. 0 = no burst budget.
    /// NOT ENFORCED — see the note on `RateLimitMode::Enforce`.
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

    /// True when any byte-bucket field is configured. Used by the rules loader
    /// to warn that the setting has no effect.
    [[nodiscard]] bool has_byte_limits() const noexcept {
        return bytes_per_sec != 0 || bytes_burst != 0;
    }

    bool operator==(const RateLimitSpec& other) const = default;
};

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
    /// value. An explicit `bytes_per_sec: 0` is an opt-*out* and needs no
    /// "not implemented" warning.
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
    /// NOT WIRED UP. The bucket mechanics below are complete and tested, but
    /// no production code path calls this: TUNNEL_DATA is forwarded without
    /// consulting the byte budget, so `bytes_per_sec` / `bytes_burst` shape
    /// nothing and `toxtunnel_rate_limit_bytes_throttled_total` stays at 0.
    /// Connecting it needs a backpressure story on the data path (deferring
    /// reads rather than dropping frames, which would break the stream), which
    /// is deliberately out of scope here — the loader warns instead of
    /// pretending the limit works.
    ///
    /// `Report` mode is *count-only*, mirroring `try_consume_open`: when the
    /// request is short it increments the throttle counter, clamps the bucket
    /// at zero (never negative / never into debt), and returns true.
    [[nodiscard]] bool try_consume_bytes(std::string_view friend_pk, std::size_t bytes);

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
        std::atomic<std::int64_t> last_refill_ns{0};
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
    /// Install `spec` on `b`, clamping any token count down to a shrunken
    /// burst. Caller holds `mu_`.
    static void apply_spec(Bucket& b, const RateLimitSpec& spec);
    static std::string normalise_key(std::string_view friend_pk);

    mutable std::mutex mu_;
    RateLimitSpec default_spec_;
    mutable std::unordered_map<std::string, std::unique_ptr<Bucket>> buckets_;
};

/// Process-wide singleton for convenience wiring from TunnelServer (which
/// constructs an instance) into TunnelManager (which consults it on every
/// TUNNEL_OPEN). The owner can swap the active instance via `set_instance`.
RateLimiter& rate_limiter_instance();

}  // namespace toxtunnel
