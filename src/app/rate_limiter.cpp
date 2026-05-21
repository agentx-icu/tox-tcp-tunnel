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

std::string RateLimiter::normalise_key(std::string_view friend_pk) {
    std::string out(friend_pk);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

void RateLimiter::set_default_spec(const RateLimitSpec& spec) {
    std::lock_guard<std::mutex> lock(mu_);
    default_spec_ = spec;
}

void RateLimiter::clear_all_friend_specs() {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.clear();
}

void RateLimiter::set_friend_spec(std::string_view friend_pk, const RateLimitSpec& spec) {
    const auto key = normalise_key(friend_pk);
    std::lock_guard<std::mutex> lock(mu_);
    if (spec.empty()) {
        buckets_.erase(key);
        return;
    }
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        auto bucket = std::make_unique<Bucket>();
        bucket->spec = spec;
        bucket->open_tokens.store(spec.open_burst, std::memory_order_relaxed);
        bucket->bytes_tokens.store(static_cast<std::int64_t>(spec.bytes_burst),
                                   std::memory_order_relaxed);
        buckets_[key] = std::move(bucket);
    } else {
        // Loosening takes effect immediately; tightening is observed lazily
        // on the next consume + refill cycle. Match the design doc.
        it->second->spec = spec;
        // Cap the current bucket to the new burst if it shrank.
        if (it->second->open_tokens.load(std::memory_order_relaxed) >
            static_cast<std::int64_t>(spec.open_burst)) {
            it->second->open_tokens.store(static_cast<std::int64_t>(spec.open_burst),
                                          std::memory_order_relaxed);
        }
        if (it->second->bytes_tokens.load(std::memory_order_relaxed) >
            static_cast<std::int64_t>(spec.bytes_burst)) {
            it->second->bytes_tokens.store(static_cast<std::int64_t>(spec.bytes_burst),
                                           std::memory_order_relaxed);
        }
    }
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
        b.bytes_throttled.fetch_add(1, std::memory_order_relaxed);
        util::MetricsRegistry::instance().inc_rate_limit_bytes_throttled();
        if (b.spec.mode == RateLimitMode::Report) {
            // Account against the bucket but don't deny.
            b.bytes_tokens.store(cur - need, std::memory_order_relaxed);
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
