#pragma once

#include <spdlog/spdlog.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace toxtunnel::util {

/// Log severity levels, mirroring spdlog levels.
enum class LogLevel {
    Trace = SPDLOG_LEVEL_TRACE,
    Debug = SPDLOG_LEVEL_DEBUG,
    Info = SPDLOG_LEVEL_INFO,
    Warn = SPDLOG_LEVEL_WARN,
    Error = SPDLOG_LEVEL_ERROR,
    Critical = SPDLOG_LEVEL_CRITICAL,
    Off = SPDLOG_LEVEL_OFF,
};

/// Rate limiter for a single high-frequency log site.
///
/// WHY THIS EXISTS: a few log statements sit on retry loops that spin at the
/// timer cadence (hundreds to thousands of iterations per second) whenever the
/// transport stalls. Measured during a single Tox disconnect: 5218 lines /
/// 37 MB from one site, enough to roll three 5 MiB log files inside a minute
/// and destroy the pre-failure history that is the actual evidence an operator
/// needs. Demoting those sites to `trace` would hide them entirely; throttling
/// keeps the signal ("this is happening, and here is how often") while capping
/// the volume at one line per interval.
///
/// The limiter is deliberately lock-free. Its callers run on the Tox iterate
/// thread and on the tunnel data path, so a mutex here would put contention
/// directly on the hot path it is meant to protect. The suppressed path costs
/// one steady_clock read, one relaxed load and one relaxed fetch_add; no
/// allocation, no formatting, and (crucially) no trip through
/// `Logger::get()`'s global mutex.
///
/// Counters are `relaxed` on purpose: they carry no data dependency, and an
/// occasional off-by-a-few in a "suppressed" tally is worth strictly less than
/// the fences it would cost on the data path. Note that relaxed *read-modify-
/// write* operations still observe the latest value in the object's
/// modification order, which is all the monotonicity guarantees below need.
///
/// GRANULARITY: one `LogThrottle` is one bucket. Every event routed through it
/// shares a single interval and a single suppression tally, so if a call site
/// covers several distinct conditions (different peers, different error codes,
/// two neighbouring log statements), the tally aggregates them and a burst from
/// one condition can hide the onset of another. Where that distinction matters,
/// use `KeyedLogThrottle` below and derive a key from whatever identifies the
/// condition.
class LogThrottle {
   public:
    /// Snapshot handed back when an emission is admitted.
    struct Decision {
        /// Events dropped since the previously admitted one.
        std::uint64_t suppressed = 0;
        /// Milliseconds since the previously admitted one (0 for the first).
        std::uint64_t window_ms = 0;
    };

    /// @param interval Minimum spacing between admitted messages.
    explicit LogThrottle(std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
        : interval_ns_(static_cast<std::int64_t>(interval.count()) * 1000000) {}

    LogThrottle(const LogThrottle&) = delete;
    LogThrottle& operator=(const LogThrottle&) = delete;

    /// Return true if the caller may emit now, filling @p decision with the
    /// tally of everything dropped since the last admitted message.
    /// Exactly one caller wins per interval, even under concurrent access.
    bool allow(Decision& decision) noexcept { return allow_impl(now_ns(), decision); }

    /// Number of events dropped since the last admitted message. Cheap enough
    /// (one relaxed load) to poll from a success path that wants to emit a
    /// "condition cleared" summary.
    std::uint64_t pending_suppressed() const noexcept {
        return suppressed_.load(std::memory_order_relaxed);
    }

    /// Total events seen since construction (admitted + suppressed).
    std::uint64_t total() const noexcept { return total_.load(std::memory_order_relaxed); }

    /// Drop the pending-suppressed tally, returning its previous value. Used
    /// by a recovery log line that reports the burst size once it is over.
    std::uint64_t take_suppressed() noexcept {
        return suppressed_.exchange(0, std::memory_order_relaxed);
    }

    /// Nanoseconds on the steady clock, the time base this class works in.
    static std::int64_t now_ns() noexcept {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    // -----------------------------------------------------------------
    // Test seams
    // -----------------------------------------------------------------
    //
    // The two interleavings this class defends against both involve a thread
    // being descheduled *inside* `allow()`, which a test cannot produce by
    // spawning threads and hoping. These entry points let a test drive the
    // individual steps with the timings the scheduler would otherwise have to
    // hand it. Production code calls `allow()` and nothing else.

    /// `allow()` with the *gate's* clock reading injected. Models a caller
    /// that read the clock, lost the CPU for longer than one interval, and
    /// only reaches the slot claim much later: pass a deliberately stale
    /// @p gate_now to reproduce that.
    bool allow_with_stale_now_for_test(std::int64_t gate_now, Decision& decision) noexcept {
        return allow_impl(gate_now, decision);
    }

    /// Publish @p emit_ns as the newest admitted timestamp and return the
    /// resulting window length in milliseconds. `allow()` runs this after
    /// winning its slot; calling it directly is the only way to reproduce a
    /// *late* winner publishing an *older* timestamp, because via `allow()`
    /// `next_emit_ns_` always sits an interval ahead of `last_emit_ns_`.
    std::uint64_t record_emission_for_test(std::int64_t emit_ns) noexcept {
        return record_emission(emit_ns);
    }

    /// The instant before which no further emission is admitted.
    std::int64_t next_emit_ns_for_test() const noexcept {
        return next_emit_ns_.load(std::memory_order_relaxed);
    }

    /// The instant of the newest admitted emission (0 if none yet).
    std::int64_t last_emit_ns_for_test() const noexcept {
        return last_emit_ns_.load(std::memory_order_relaxed);
    }

   private:
    bool allow_impl(std::int64_t gate_now, Decision& decision) noexcept;

    /// Monotonically publish @p emit_ns into `last_emit_ns_` and return the
    /// window length in ms, saturated at 0.
    std::uint64_t record_emission(std::int64_t emit_ns) noexcept;

    const std::int64_t interval_ns_;
    /// steady-clock timestamp before which no emission is admitted.
    std::atomic<std::int64_t> next_emit_ns_{0};
    std::atomic<std::int64_t> last_emit_ns_{0};
    std::atomic<std::uint64_t> suppressed_{0};
    std::atomic<std::uint64_t> total_{0};
};

/// Compose a throttle bucket key from two 32-bit identifiers.
///
/// The usual shape at a call site is "this peer, this failure reason":
/// `log_key(friend_number, error_code)`. Keeping the halves in distinct 32-bit
/// lanes means neither can alias the other before `KeyedLogThrottle` mixes it.
constexpr std::uint64_t log_key(std::uint32_t high, std::uint32_t low) noexcept {
    return (static_cast<std::uint64_t>(high) << 32) | static_cast<std::uint64_t>(low);
}

/// A fixed array of `LogThrottle`s indexed by a caller-supplied key.
///
/// WHY THIS EXISTS: a single process-wide `LogThrottle` per call site is too
/// coarse for sites that are per-peer or that cover several failure reasons.
/// One noisy peer then consumes the whole budget and a second peer failing at
/// the same time is silently folded into its `[+N suppressed]` tally — exactly
/// the correlation an operator is reading the log to find. Bucketing by key
/// gives each condition its own interval and its own tally.
///
/// Buckets are a compile-time-sized array of independent throttles, so there is
/// no allocation, no registry, no lock, and no growth: `allow()` costs a hash
/// plus the same relaxed-atomic path as the single throttle. The price is
/// collisions — two keys landing in one bucket share a budget, degrading to
/// exactly the single-throttle behaviour for that pair and never worse. Size
/// `Buckets` a few times larger than the number of distinct keys you expect.
///
/// Usage keeps the existing Logger API; `for_key()` hands back a plain
/// `LogThrottle&`:
/// @code
///   static KeyedLogThrottle<32> throttle{std::chrono::seconds(1)};
///   Logger::warn_throttled(throttle.for_key(log_key(friend_number, err)),
///                          "send failed on friend {}: {}", friend_number, err);
/// @endcode
template <std::size_t Buckets = 16>
class KeyedLogThrottle {
    static_assert(Buckets > 0, "KeyedLogThrottle needs at least one bucket");

   public:
    using Decision = LogThrottle::Decision;

    explicit KeyedLogThrottle(std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
        : KeyedLogThrottle(interval, std::make_index_sequence<Buckets>{}) {}

    KeyedLogThrottle(const KeyedLogThrottle&) = delete;
    KeyedLogThrottle& operator=(const KeyedLogThrottle&) = delete;

    /// The throttle owning @p key. Stable for the lifetime of this object.
    LogThrottle& for_key(std::uint64_t key) noexcept { return buckets_[bucket_index(key)]; }

    /// Convenience wrapper: throttle @p key's bucket directly.
    bool allow(std::uint64_t key, Decision& decision) noexcept {
        return for_key(key).allow(decision);
    }

    static constexpr std::size_t bucket_count() noexcept { return Buckets; }

    /// splitmix64's finalizer. Keys here are small integers and packed
    /// bitfields (`log_key`), whose raw low bits are badly distributed: a
    /// plain `key % Buckets` on `friend << 32 | code` would ignore the friend
    /// entirely and collapse every peer onto one bucket. The finalizer is a
    /// handful of ALU ops with no memory traffic, cheap enough for the data
    /// path it protects.
    static std::size_t bucket_index(std::uint64_t key) noexcept {
        std::uint64_t hash = key + 0x9e3779b97f4a7c15ULL;
        hash = (hash ^ (hash >> 30)) * 0xbf58476d1ce4e5b9ULL;
        hash = (hash ^ (hash >> 27)) * 0x94d049bb133111ebULL;
        hash ^= hash >> 31;
        return static_cast<std::size_t>(hash % Buckets);
    }

   private:
    // `LogThrottle` is neither copyable nor movable, so the array is built by
    // in-place aggregate initialisation from prvalues (guaranteed elision).
    template <std::size_t... I>
    KeyedLogThrottle(std::chrono::milliseconds interval, std::index_sequence<I...>)
        : buckets_{((void)I, LogThrottle(interval))...} {}

    std::array<LogThrottle, Buckets> buckets_;
};

/// A thin facade around spdlog providing console and optional file logging.
///
/// Typical usage:
/// @code
///   Logger::init("toxtunnel");
///   Logger::set_level(LogLevel::Debug);
///   Logger::add_file_sink("/var/log/toxtunnel.log");
///
///   Logger::info("listening on port {}", port);
///   Logger::error("connection failed: {}", ec.message());
/// @endcode
///
/// The class is entirely static; there is no need to instantiate it.
/// Thread safety is guaranteed by spdlog.
class Logger {
   public:
    Logger() = delete;

    // -----------------------------------------------------------------
    // Initialisation & configuration
    // -----------------------------------------------------------------

    /// Initialise the global logger with a console (stderr) sink.
    /// Must be called once before any logging.
    /// @param name  Logger name shown in log output.
    static void init(std::string_view name = "toxtunnel");

    /// Shut down and flush all sinks.  Optional; spdlog also flushes on
    /// process exit.
    static void shutdown();

    /// Set the minimum log level.  Messages below this level are discarded.
    static void set_level(LogLevel level);

    /// Return the current minimum log level.
    static LogLevel get_level();

    /// Set the log pattern (spdlog pattern syntax).
    /// @see https://github.com/gabime/spdlog/wiki/3.-Custom-formatting
    static void set_pattern(std::string_view pattern);

    /// Add a rotating-file sink.
    /// @param filename       Path to the log file.
    /// @param max_size_bytes Maximum size of a single file before rotation
    ///                       (default 5 MiB).
    /// @param max_files      Number of rotated files to keep (default 3).
    static void add_file_sink(const std::string& filename,
                              std::size_t max_size_bytes = 5 * 1024 * 1024,
                              std::size_t max_files = 3);

    /// Immediately flush all sinks.
    static void flush();

    // -----------------------------------------------------------------
    // Logging methods
    // -----------------------------------------------------------------

    template <typename... Args>
    static void trace(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->trace(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void debug(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->debug(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void info(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->info(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void warn(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->warn(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void error(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->error(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void critical(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        get()->critical(fmt, std::forward<Args>(args)...);
    }

    // -----------------------------------------------------------------
    // Rate-limited logging
    // -----------------------------------------------------------------
    //
    // Use these for statements that live on a retry loop or a per-packet data
    // path, where a stalled transport turns one event into thousands of
    // identical lines. The throttle object must outlive the call and be shared
    // by every invocation of that one site (a function-local `static` is the
    // usual form). When messages are dropped the next admitted line carries a
    // `[+N suppressed in Mms]` suffix, so the scale of the burst survives even
    // though the individual lines do not.
    //
    // NOTE: the throttle is consulted *before* the level check, so the cheap
    // atomic path also short-circuits the mutex inside `get()`. The only
    // consequence is that suppression tallies keep accumulating while the
    // level filters the site out, which is harmless.

    template <typename... Args>
    static void trace_throttled(LogThrottle& throttle, spdlog::format_string_t<Args...> fmt_str,
                                Args&&... args) {
        log_throttled(spdlog::level::trace, throttle, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void debug_throttled(LogThrottle& throttle, spdlog::format_string_t<Args...> fmt_str,
                                Args&&... args) {
        log_throttled(spdlog::level::debug, throttle, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void info_throttled(LogThrottle& throttle, spdlog::format_string_t<Args...> fmt_str,
                               Args&&... args) {
        log_throttled(spdlog::level::info, throttle, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void warn_throttled(LogThrottle& throttle, spdlog::format_string_t<Args...> fmt_str,
                               Args&&... args) {
        log_throttled(spdlog::level::warn, throttle, fmt_str, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void error_throttled(LogThrottle& throttle, spdlog::format_string_t<Args...> fmt_str,
                                Args&&... args) {
        log_throttled(spdlog::level::err, throttle, fmt_str, std::forward<Args>(args)...);
    }

    // -----------------------------------------------------------------
    // Raw access
    // -----------------------------------------------------------------

    /// Return the underlying spdlog logger.
    /// Useful when a library or subsystem expects an `std::shared_ptr<spdlog::logger>`.
    static std::shared_ptr<spdlog::logger> get();

   private:
    template <typename... Args>
    static void log_throttled(spdlog::level::level_enum level, LogThrottle& throttle,
                              spdlog::format_string_t<Args...> fmt_str, Args&&... args) {
        LogThrottle::Decision decision;
        if (!throttle.allow(decision)) {
            return;
        }
        // Formatting only happens on an admitted line (<= 1 per interval), so
        // the throttled site costs nothing measurable while it is firing hot.
        emit_throttled(level, decision,
                       spdlog::fmt_lib::format(fmt_str, std::forward<Args>(args)...));
    }

    /// Emit one admitted throttled message, appending the suppression tally.
    static void emit_throttled(spdlog::level::level_enum level,
                               const LogThrottle::Decision& decision, const std::string& message);

    /// Convert our LogLevel enum to the matching spdlog enum value.
    static spdlog::level::level_enum to_spdlog_level(LogLevel level);

    /// Convert spdlog enum value back to our LogLevel.
    static LogLevel from_spdlog_level(spdlog::level::level_enum level);
};

}  // namespace toxtunnel::util
