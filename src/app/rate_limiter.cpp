#include "toxtunnel/app/rate_limiter.hpp"

#include <algorithm>
#include <cctype>

#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel {

bool parse_rate_limit_mode(std::string_view s, RateLimitMode& out) noexcept {
    if (s == "off") {
        out = RateLimitMode::Off;
        return true;
    }
    if (s == "report") {
        out = RateLimitMode::Report;
        return true;
    }
    if (s == "enforce") {
        out = RateLimitMode::Enforce;
        return true;
    }
    return false;
}

RateLimitSpec RateLimitOverride::merged_onto(const RateLimitSpec& base) const noexcept {
    RateLimitSpec out = base;
    if (open_per_sec) {
        out.open_per_sec = *open_per_sec;
    }
    if (open_burst) {
        out.open_burst = *open_burst;
    }
    if (bytes_per_sec) {
        out.bytes_per_sec = *bytes_per_sec;
    }
    if (bytes_burst) {
        out.bytes_burst = *bytes_burst;
    }
    if (max_concurrent_tunnels) {
        out.max_concurrent_tunnels = *max_concurrent_tunnels;
    }
    if (mode) {
        out.mode = *mode;
        return out;
    }
    // No explicit per-friend mode: inherit the base's mode (already copied by
    // `out = base`). The fallback below only applies when there is genuinely
    // nothing to inherit from.
    //
    // "Nothing to inherit" means BOTH: the rules file carried no
    // `rate_limit_defaults:` block (`defaults_present`), and the base has no
    // configured values either (`empty()`). Testing `empty()` alone was a
    // release blocker: `rate_limit_defaults: {mode: off}` is `empty()` by
    // value, so an operator who had explicitly *disabled* rate limiting saw
    // every friend with a per-friend block flipped to `Enforce` — the exact
    // opposite of what they wrote. `defaults_present` is what tells the two
    // cases apart.
    //
    // With no defaults block at all we keep the pre-merge rule "configuring a
    // limit turns it on", otherwise a rules file whose only rate-limit config
    // is a per-friend block would resolve to mode Off and silently do nothing.
    if (!base.defaults_present && base.empty() && !out.empty()) {
        out.mode = RateLimitMode::Enforce;
    }
    return out;
}

RateLimitOverride RateLimitOverride::from_spec(const RateLimitSpec& spec) {
    RateLimitOverride out;
    out.mode = spec.mode;
    out.open_per_sec = spec.open_per_sec;
    out.open_burst = spec.open_burst;
    out.bytes_per_sec = spec.bytes_per_sec;
    out.bytes_burst = spec.bytes_burst;
    out.max_concurrent_tunnels = spec.max_concurrent_tunnels;
    return out;
}

std::string RateLimiter::normalise_key(std::string_view friend_pk) {
    std::string out(friend_pk);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

void RateLimiter::apply_spec(Bucket& b, const RateLimitSpec& spec) {
    b.spec = spec;
    // Loosening takes effect immediately; tightening is observed lazily on the
    // next consume + refill cycle, except that a bucket already holding more
    // than the new capacity is clamped down so a shrunken burst cannot be
    // spent all at once.
    if (b.open_tokens.load(std::memory_order_relaxed) >
        static_cast<std::int64_t>(spec.open_burst)) {
        b.open_tokens.store(static_cast<std::int64_t>(spec.open_burst), std::memory_order_relaxed);
    }
    if (b.bytes_tokens.load(std::memory_order_relaxed) >
        static_cast<std::int64_t>(spec.bytes_burst)) {
        b.bytes_tokens.store(static_cast<std::int64_t>(spec.bytes_burst),
                             std::memory_order_relaxed);
    }
}

void RateLimiter::set_default_spec(const RateLimitSpec& spec) {
    std::lock_guard<std::mutex> lock(mu_);
    default_spec_ = spec;
    // An override only says what it changes, so every live bucket's effective
    // spec has to be recomputed against the new defaults — including buckets
    // with no override, which were seeded from the previous defaults.
    for (auto& entry : buckets_) {
        Bucket& b = *entry.second;
        apply_spec(b, b.override_spec.merged_onto(default_spec_));
    }
}

void RateLimiter::clear_all_friend_specs() {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.clear();
}

void RateLimiter::replace_all(const RateLimitSpec& defaults,
                              const std::vector<FriendOverride>& overrides) {
    std::lock_guard<std::mutex> lock(mu_);
    // Order matters even inside the lock: the buckets must be gone before
    // `default_spec_` moves, otherwise the loop in `set_default_spec` would
    // re-merge overrides that are about to be thrown away anyway. Doing the
    // clear first also means every `install_friend_spec_locked` below takes the
    // create path, i.e. seeds a full bucket — the token reset the three-call
    // sequence produced, preserved verbatim.
    buckets_.clear();
    default_spec_ = defaults;
    for (const auto& [friend_pk, override_spec] : overrides) {
        install_friend_spec_locked(normalise_key(friend_pk), override_spec);
    }
}

void RateLimiter::install_friend_spec_locked(const std::string& key,
                                             const RateLimitOverride& override_spec) {
    if (override_spec.empty()) {
        buckets_.erase(key);
        return;
    }
    const RateLimitSpec resolved = override_spec.merged_onto(default_spec_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        auto bucket = std::make_unique<Bucket>();
        bucket->override_spec = override_spec;
        bucket->spec = resolved;
        bucket->open_tokens.store(resolved.open_burst, std::memory_order_relaxed);
        bucket->bytes_tokens.store(static_cast<std::int64_t>(resolved.bytes_burst),
                                   std::memory_order_relaxed);
        buckets_[key] = std::move(bucket);
        return;
    }
    it->second->override_spec = override_spec;
    apply_spec(*it->second, resolved);
}

void RateLimiter::set_friend_spec(std::string_view friend_pk,
                                  const RateLimitOverride& override_spec) {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    install_friend_spec_locked(key, override_spec);
}

void RateLimiter::set_friend_spec(std::string_view friend_pk, const RateLimitSpec& spec) {
    if (spec.empty()) {
        set_friend_spec(friend_pk, RateLimitOverride{});
        return;
    }
    set_friend_spec(friend_pk, RateLimitOverride::from_spec(spec));
}

RateLimitSpec RateLimiter::effective_spec(std::string_view friend_pk) const {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    auto it = buckets_.find(key);
    if (it != buckets_.end()) {
        return it->second->spec;
    }
    return default_spec_;
}

RateLimiter::Bucket& RateLimiter::get_or_create_bucket(const std::string& key) const {
    // Caller holds mu_. Used by both consume paths after acquiring the lock.
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        auto bucket = std::make_unique<Bucket>();
        bucket->spec = default_spec_;
        bucket->open_tokens.store(default_spec_.open_burst, std::memory_order_relaxed);
        bucket->bytes_tokens.store(static_cast<std::int64_t>(default_spec_.bytes_burst),
                                   std::memory_order_relaxed);
        it = buckets_.emplace(key, std::move(bucket)).first;
    }
    return *it->second;
}

RateLimiter::Bucket* RateLimiter::find_bucket(const std::string& key) const {
    auto it = buckets_.find(key);
    return it == buckets_.end() ? nullptr : it->second.get();
}

void RateLimiter::refill(Bucket& b) const {
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto prev = b.last_refill_ns.exchange(now_ns, std::memory_order_relaxed);
    if (prev == 0) {
        return;
    }
    const auto elapsed_ns = now_ns - prev;
    if (elapsed_ns <= 0) {
        return;
    }
    // Compute integer refill amounts. Tokens are scaled to the bucket's burst
    // cap so the bucket never exceeds capacity.
    //
    // S25 / H-4 (2026-05-20 review): `per_sec * elapsed_ns` overflows int64
    // for any bucket that's been idle long enough (per_sec up to 2^32-1,
    // elapsed_ns unbounded). The old code wrapped to a negative `add` and
    // starved the friend permanently.
    //
    // CI-pedantic-fix follow-up (2026-05-21): the first fix used __int128
    // which MSVC doesn't have. Replace with the observation that once a
    // bucket has been idle for `burst / per_sec` seconds it's already
    // saturated at `burst` regardless of any more elapsed time — so we
    // can short-circuit and skip the dangerous multiplication entirely.
    // `burst * 1e9` is safe (burst is at most uint32_t -> 4.3e9 * 1e9 =
    // 4.3e18 < INT64_MAX). Below that idle threshold, `per_sec *
    // elapsed_ns` is itself bounded by `burst * 1e9` and therefore safe
    // too.
    const auto compute_add = [](std::int64_t per_sec_val, std::int64_t elapsed,
                                std::int64_t burst) -> std::int64_t {
        if (per_sec_val <= 0 || elapsed <= 0 || burst <= 0) {
            return 0;
        }
        const std::int64_t ns_to_full = (burst * 1'000'000'000LL) / per_sec_val;
        if (elapsed >= ns_to_full) {
            return burst;
        }
        return (per_sec_val * elapsed) / 1'000'000'000LL;
    };

    if (b.spec.open_per_sec > 0 && b.spec.open_burst > 0) {
        const std::int64_t add = compute_add(b.spec.open_per_sec, elapsed_ns, b.spec.open_burst);
        if (add > 0) {
            auto cur = b.open_tokens.load(std::memory_order_relaxed);
            auto next =
                std::min<std::int64_t>(cur + add, static_cast<std::int64_t>(b.spec.open_burst));
            b.open_tokens.store(next, std::memory_order_relaxed);
        }
    }
    if (b.spec.bytes_per_sec > 0 && b.spec.bytes_burst > 0) {
        const std::int64_t add = compute_add(b.spec.bytes_per_sec, elapsed_ns, b.spec.bytes_burst);
        if (add > 0) {
            auto cur = b.bytes_tokens.load(std::memory_order_relaxed);
            auto next =
                std::min<std::int64_t>(cur + add, static_cast<std::int64_t>(b.spec.bytes_burst));
            b.bytes_tokens.store(next, std::memory_order_relaxed);
        }
    }
}

bool RateLimiter::try_consume_open(std::string_view friend_pk) {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    auto& b = get_or_create_bucket(key);
    refill(b);

    if (b.spec.mode == RateLimitMode::Off || b.spec.open_per_sec == 0 || b.spec.open_burst == 0) {
        return true;
    }

    auto cur = b.open_tokens.load(std::memory_order_relaxed);
    if (cur <= 0) {
        // M-03: Report mode is count-only and never goes into debt. When the
        // bucket is empty we increment the shadow counter and allow, leaving
        // open_tokens clamped at its floor (already <= 0 here, so no deduction
        // is needed). This is the same count-only contract the bytes path
        // (`try_consume_bytes`) now follows.
        b.open_rejected.fetch_add(1, std::memory_order_relaxed);
        util::MetricsRegistry::instance().inc_rate_limit_open_rejected();
        if (b.spec.mode == RateLimitMode::Report) {
            return true;
        }
        return false;
    }
    b.open_tokens.store(cur - 1, std::memory_order_relaxed);
    return true;
}

bool RateLimiter::try_consume_bytes(std::string_view friend_pk, std::size_t bytes) {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    auto& b = get_or_create_bucket(key);
    refill(b);

    if (b.spec.mode == RateLimitMode::Off || b.spec.bytes_per_sec == 0 || b.spec.bytes_burst == 0) {
        return true;
    }

    const auto need = static_cast<std::int64_t>(bytes);
    auto cur = b.bytes_tokens.load(std::memory_order_relaxed);
    if (cur < need) {
        // M-03: Report mode is count-only. It increments the metric so
        // operators can see what *would* be throttled, but it never denies
        // and never drives the bucket negative. This matches the open path
        // (`try_consume_open`): when short, count + allow, leave bookkeeping
        // clamped at the floor. The previous code subtracted into debt only
        // on the bytes path, which made the two paths' bucket semantics
        // diverge (and could leave the bucket permanently negative under a
        // sustained over-budget flow).
        b.bytes_throttled.fetch_add(1, std::memory_order_relaxed);
        util::MetricsRegistry::instance().inc_rate_limit_bytes_throttled();
        if (b.spec.mode == RateLimitMode::Report) {
            // Drain whatever is available (clamp to zero) and allow.
            b.bytes_tokens.store(cur > 0 ? 0 : cur, std::memory_order_relaxed);
            return true;
        }
        return false;
    }
    b.bytes_tokens.store(cur - need, std::memory_order_relaxed);
    return true;
}

RateLimiter::State RateLimiter::state(std::string_view friend_pk) const {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    auto* b = find_bucket(key);
    State out;
    out.spec = b ? b->spec : default_spec_;
    out.open_tokens = b ? b->open_tokens.load(std::memory_order_relaxed) : 0;
    out.bytes_tokens = b ? b->bytes_tokens.load(std::memory_order_relaxed) : 0;
    out.open_rejected = b ? b->open_rejected.load(std::memory_order_relaxed) : 0;
    out.bytes_throttled = b ? b->bytes_throttled.load(std::memory_order_relaxed) : 0;
    return out;
}

RateLimiter& rate_limiter_instance() {
    static RateLimiter global;
    return global;
}

}  // namespace toxtunnel
