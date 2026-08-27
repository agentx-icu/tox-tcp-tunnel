#include "toxtunnel/util/logger.hpp"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <chrono>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace toxtunnel::util {

namespace {

/// Guards one-time initialisation and sink mutations.
std::mutex g_mutex;

/// Name used when creating the logger.
std::string g_logger_name = "toxtunnel";

/// Cached shared pointer to the underlying spdlog logger.
/// Once initialised this is only read, so concurrent logging is safe.
std::shared_ptr<spdlog::logger> g_logger;

/// Collect all sinks so we can rebuild the logger when sinks are added.
std::vector<spdlog::sink_ptr> g_sinks;

/// (Re-)create the internal logger using the current set of sinks.
/// Caller must hold g_mutex.
void rebuild_logger_locked() {
    auto level = spdlog::level::info;
    std::string pattern;

    // Preserve settings from the previous logger instance.
    if (g_logger) {
        level = g_logger->level();
        spdlog::drop(g_logger_name);
    }

    g_logger = std::make_shared<spdlog::logger>(g_logger_name, g_sinks.begin(), g_sinks.end());
    g_logger->set_level(level);
    // Without this, the rotating_file_sink's stdio buffer (BUFSIZ, 4-8 KB) holds
    // every line written below the threshold until it fills. Operators tailing
    // the log see stale state for minutes during quiet periods and lose the
    // last buffered window when the daemon is killed. flush_on(info) keeps the
    // file roughly in sync with steady-state events; spdlog::flush_every below
    // catches the trace/debug tail.
    g_logger->flush_on(spdlog::level::info);

    if (!pattern.empty()) {
        g_logger->set_pattern(pattern);
    }

    spdlog::set_default_logger(g_logger);
}

}  // anonymous namespace

// =========================================================================
// LogThrottle
// =========================================================================

bool LogThrottle::allow_impl(std::int64_t gate_now, Decision& decision) noexcept {
    total_.fetch_add(1, std::memory_order_relaxed);

    std::int64_t next = next_emit_ns_.load(std::memory_order_relaxed);
    if (gate_now < next) {
        suppressed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Re-read the clock before claiming the slot.
    //
    // WHY: `gate_now` was sampled before the load above, and nothing stops the
    // scheduler from parking this thread in between for longer than one whole
    // interval. Deriving the next deadline from that stale reading would push
    // `next_emit_ns_` to an instant that is *already in the past*, so the very
    // next call would be admitted too and the site emits two lines back to
    // back. The extra clock read only ever happens on the candidate-admission
    // path (at most once per interval per thread, and never on the suppressed
    // path this class exists to keep cheap), so it costs nothing measurable.
    // It also makes `window_ms` describe when the line was actually emitted
    // rather than when the caller happened to look at the clock.
    const std::int64_t emit_at = now_ns();

    // Claim the emission slot. Only the thread that swings `next_emit_ns_`
    // forward gets to log; concurrent losers count themselves as suppressed.
    // A CAS is cheaper than any lock and keeps the "one line per interval"
    // guarantee exact even when several threads share one call site.
    if (!next_emit_ns_.compare_exchange_strong(
            next, emit_at + interval_ns_, std::memory_order_relaxed, std::memory_order_relaxed)) {
        suppressed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    decision.suppressed = suppressed_.exchange(0, std::memory_order_relaxed);
    decision.window_ms = record_emission(emit_at);
    return true;
}

std::uint64_t LogThrottle::record_emission(std::int64_t emit_ns) noexcept {
    // Winning the slot CAS and publishing the timestamp are two separate steps,
    // and a winner can be descheduled between them. By the time it resumes, a
    // *later* window's winner may already have published a newer timestamp. A
    // plain `exchange` would then rewind `last_emit_ns_` to the older value and
    // the next window would measure itself against a stale anchor.
    //
    // Defence 1 — keep the field monotonic. A relaxed CAS still reads the
    // latest value in this atomic's modification order, so the loop cannot
    // "miss" a newer publication and cannot install an older one.
    std::int64_t last = last_emit_ns_.load(std::memory_order_relaxed);
    while (last < emit_ns &&
           !last_emit_ns_.compare_exchange_weak(last, emit_ns, std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
    }

    // Defence 2 — saturate the subtraction. Monotonicity protects future
    // readers, but the late winner above is itself holding a `last` that is
    // *newer* than its own `emit_ns`; `emit_ns - last` is negative there, and
    // widening that to std::uint64_t printed the notorious
    // `[+3 suppressed in 18446744073709551615ms]`. Both defences are one
    // comparison each and each covers a case the other does not, so keep both.
    if (last == 0 || last >= emit_ns) {
        return 0;
    }
    return static_cast<std::uint64_t>((emit_ns - last) / 1000000);
}

// =========================================================================
// Initialisation & configuration
// =========================================================================

void Logger::init(std::string_view name) {
    std::lock_guard<std::mutex> lock(g_mutex);

    g_logger_name = std::string(name);
    g_sinks.clear();

    // Default sink: coloured stderr so stdout can safely carry tunneled data.
    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    g_sinks.push_back(console_sink);

    rebuild_logger_locked();

    // Periodic flush as a fallback for messages below the flush_on threshold
    // (debug/trace under low traffic). 2s is a compromise between log-tail
    // freshness and the wasted fsync churn from a tighter cadence.
    // spdlog::flush_every is global and idempotent on repeated calls.
    spdlog::flush_every(std::chrono::seconds(2));
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_logger) {
        g_logger->flush();
    }
    spdlog::shutdown();
    g_logger.reset();
    g_sinks.clear();
}

void Logger::set_level(LogLevel level) {
    get()->set_level(to_spdlog_level(level));
}

LogLevel Logger::get_level() {
    return from_spdlog_level(get()->level());
}

void Logger::set_pattern(std::string_view pattern) {
    get()->set_pattern(std::string(pattern));
}

void Logger::add_file_sink(const std::string& filename, std::size_t max_size_bytes,
                           std::size_t max_files) {
    std::lock_guard<std::mutex> lock(g_mutex);

    auto file_sink =
        std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, max_size_bytes, max_files);
    g_sinks.push_back(file_sink);

    rebuild_logger_locked();
}

void Logger::flush() {
    get()->flush();
}

// =========================================================================
// Raw access
// =========================================================================

std::shared_ptr<spdlog::logger> Logger::get() {
    // `g_logger` is a plain shared_ptr guarded by `g_mutex`; reading it
    // without the lock would be a data race against `init()`/`shutdown()`.
    // spdlog has its own per-sink locking, so the extra mutex hop here is
    // dominated by the logging work itself.
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_logger) {
            return g_logger;
        }
    }
    // Auto-init with defaults. `init()` itself takes `g_mutex`, so it must
    // run without the lock held here.
    init();
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_logger;
}

// =========================================================================
// Helpers
// =========================================================================

void Logger::emit_throttled(spdlog::level::level_enum level, const LogThrottle::Decision& decision,
                            const std::string& message) {
    auto logger = get();
    if (!logger->should_log(level)) {
        return;
    }
    if (decision.suppressed == 0) {
        logger->log(level, "{}", message);
        return;
    }
    // The tally is the whole point of throttling rather than demoting: the
    // operator still learns the burst happened *and* how big it was.
    logger->log(level, "{} [+{} suppressed in {}ms]", message, decision.suppressed,
                decision.window_ms);
}

spdlog::level::level_enum Logger::to_spdlog_level(LogLevel level) {
    return static_cast<spdlog::level::level_enum>(static_cast<int>(level));
}

LogLevel Logger::from_spdlog_level(spdlog::level::level_enum level) {
    return static_cast<LogLevel>(static_cast<int>(level));
}

}  // namespace toxtunnel::util
