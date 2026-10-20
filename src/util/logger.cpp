#include "toxtunnel/util/logger.hpp"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#if !defined(_WIN32)
#include <spdlog/sinks/syslog_sink.h>
#include <syslog.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <vector>

#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/resilient_file_sink.hpp"

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

/// The file sink, for Logger::file_sink_state(). Guarded by g_mutex.
std::weak_ptr<ResilientFileSink> g_file_sink;

/// Next steady-clock tick (ns) at which the error handler may print to stderr.
std::atomic<std::int64_t> g_next_stderr_report_ns{0};

/// Replaces spdlog's default handler on every logger we build. That one prints
/// to stderr once a second — which, for a daemon whose stderr is the same
/// revoked descriptor as its log, is a second silent failure. This one counts
/// every report (so /metrics and `inspect status` show it) and still prints,
/// throttled to once a minute. It must never call Logger: it can run while
/// shutdown() holds g_mutex, and from inside a sink.
void on_logger_error(const std::string& msg) noexcept {
    MetricsRegistry::instance().inc_log_sink_errors();
    const auto now_ns = [] {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    };
    auto next = g_next_stderr_report_ns.load(std::memory_order_relaxed);
    if (now_ns() < next) {
        return;
    }
    // Re-read the clock before claiming the slot, as LogThrottle does: a
    // thread parked between the first read and here would otherwise publish a
    // deadline already in the past and let the next report through at once.
    const auto deadline = now_ns() + std::chrono::nanoseconds(std::chrono::minutes(1)).count();
    if (!g_next_stderr_report_ns.compare_exchange_strong(next, deadline,
                                                         std::memory_order_relaxed)) {
        return;
    }
    std::fprintf(stderr, "[toxtunnel] log error: %s\n", msg.c_str());
}

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
    // Before publication, on every rebuild: add_file_sink() rebuilds the
    // logger, and a fresh spdlog::logger starts with the default handler.
    g_logger->set_error_handler(on_logger_error);
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
    g_file_sink.reset();

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
    g_file_sink.reset();
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

    // The inner sinks are single-threaded on purpose: ResilientFileSink's own
    // mutex serialises every access to them.
    ResilientFileSink::SinkFactory fallback;
#if !defined(_WIN32)
    fallback = []() -> spdlog::sink_ptr {
        // Formatted with the file sink's pattern, so the configured context
        // (logger name, level, thread) survives the switch; syslog adds its
        // own timestamp on top. On macOS syslog(3) lands in the unified log.
        return std::make_shared<spdlog::sinks::syslog_sink_st>("toxtunnel", LOG_PID, LOG_DAEMON,
                                                               /*enable_formatting=*/true);
    };
#endif
    auto file_sink = std::make_shared<ResilientFileSink>(
        [filename, max_size_bytes, max_files]() -> spdlog::sink_ptr {
            return std::make_shared<spdlog::sinks::rotating_file_sink_st>(filename, max_size_bytes,
                                                                          max_files);
        },
        std::move(fallback));
    g_file_sink = file_sink;
    g_sinks.push_back(file_sink);

    rebuild_logger_locked();
}

void Logger::flush() {
    get()->flush();
}

std::optional<LogSinkState> Logger::file_sink_state() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (auto sink = g_file_sink.lock()) {
        return sink->state();
    }
    return std::nullopt;
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
