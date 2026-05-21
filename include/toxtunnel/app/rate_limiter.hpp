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
    /// Enforce the limits: rejected OPENs receive TUNNEL_ERROR; data above
    /// the byte limit is throttled at the friend level via deferred reads.
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
// RateLimitSpec — schema-level configuration for one friend (or defaults).
// ---------------------------------------------------------------------------

/// Per-friend rate-limit configuration. Maps directly to the YAML
/// `rate_limit:` block under a friend entry, or `rate_limit_defaults:` at the
/// top level. All fields are optional; absent / zero values mean "no limit".
struct RateLimitSpec {
    RateLimitMode mode = RateLimitMode::Off;
    /// Token refill rate for `TUNNEL_OPEN` (frames/sec). 0 = unlimited.
    std::uint32_t open_per_sec = 0;
    /// Token bucket capacity for `TUNNEL_OPEN`. 0 = no burst budget.
    std::uint32_t open_burst = 0;
    /// Byte refill rate for `TUNNEL_DATA` payload (bytes/sec). 0 = unlimited.
    std::uint64_t bytes_per_sec = 0;
    /// Byte bucket capacity. 0 = no burst budget.
    std::uint64_t bytes_burst = 0;
    /// Hard ceiling on concurrent tunnels per friend. 0 means "use the
    /// hard-coded default" (100, matching the v0.3.0 ceiling).
    std::uint32_t max_concurrent_tunnels = 0;

    [[nodiscard]] bool empty() const noexcept {
        return mode == RateLimitMode::Off && open_per_sec == 0 && open_burst == 0 &&
               bytes_per_sec == 0 && bytes_burst == 0 && max_concurrent_tunnels == 0;
    }

    bool operator==(const RateLimitSpec& other) const = default;
};

// ---------------------------------------------------------------------------
// RateLimiter — runtime per-friend token buckets.
// ---------------------------------------------------------------------------

/// Per-friend rate-limit enforcement. Built on lazy-refill token buckets so
/// the hot path is one atomic CAS per inbound TUNNEL_OPEN / TUNNEL_DATA.
///
/// Friends are keyed by the hex-encoded public key (case-insensitive). On
/// first use the limiter clones the default spec (set via
/// `set_default_spec`) into a per-friend slot, unless an explicit per-friend
/// `set_friend_spec` was made. Specs are looked up under a shared_mutex so
/// the rules-engine reload path (writer) does not contend with the data path
/// (reader-heavy).
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
    /// per-friend entry. Existing per-friend state is not retroactively
    /// adjusted (the design doc's "tightening doesn't reach in" rule).
    void set_default_spec(const RateLimitSpec& spec);

    /// Install a per-friend override. The `friend_pk` is canonicalised to
    /// lowercase before lookup. Passing an `empty()` spec removes the
    /// override.
    void set_friend_spec(std::string_view friend_pk, const RateLimitSpec& spec);

    /// Drop every per-friend override and reset all bucket counters. Used
    /// on rules-reload to avoid leaving stale token state for a friend
    /// that has been removed from the new rules (or whose previous
    /// override has been removed). After this call, all friends fall
    /// back to the default spec; the caller is expected to re-install
    /// any per-friend specs from the new rules.
    void clear_all_friend_specs();

    /// Look up the effective spec for the given friend public key. Returns
    /// the per-friend override if installed, otherwise the default.
    [[nodiscard]] RateLimitSpec effective_spec(std::string_view friend_pk) const;

    /// Attempt to consume one TUNNEL_OPEN token. Returns true if the friend
    /// is allowed to proceed (no limit, mode Off/Report, or token available);
    /// false if the bucket is empty AND the mode is Enforce.
    ///
    /// `Report` mode always returns true but still increments the rejection
    /// counter so operators can see shadow data.
    [[nodiscard]] bool try_consume_open(std::string_view friend_pk);

    /// Attempt to consume `bytes` from the data-bytes bucket. Returns true if
    /// the friend is within budget. When the bucket goes negative in
    /// `Enforce` mode this returns false; the data path uses the result to
    /// decide whether to drop the read or apply backpressure.
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
        RateLimitSpec spec;
    };

    Bucket& get_or_create_bucket(const std::string& key) const;
    Bucket* find_bucket(const std::string& key) const;
    void refill(Bucket& b) const;
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
