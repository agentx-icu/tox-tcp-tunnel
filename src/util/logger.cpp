#include "toxtunnel/util/logger.hpp"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

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

    if (!pattern.empty()) {
        g_logger->set_pattern(pattern);
    }

    spdlog::set_default_logger(g_logger);
}

}  // anonymous namespace

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

spdlog::level::level_enum Logger::to_spdlog_level(LogLevel level) {
    return static_cast<spdlog::level::level_enum>(static_cast<int>(level));
}

LogLevel Logger::from_spdlog_level(spdlog::level::level_enum level) {
    return static_cast<LogLevel>(static_cast<int>(level));
}

}  // namespace toxtunnel::util
