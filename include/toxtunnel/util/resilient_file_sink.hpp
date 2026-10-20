#pragma once

#include <spdlog/details/log_msg.h>
#include <spdlog/formatter.h>
#include <spdlog/sinks/base_sink.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace toxtunnel::util {

/// Health of the daemon's log file, as reported by `inspect status`.
enum class LogSinkState : int {
    /// The file is open and its last write / flush succeeded.
    Ok = 0,
    /// The file is unwritable; records are routed to the platform fallback
    /// (syslog on POSIX). "Routed", not "delivered": syslog(3) reports nothing.
    Fallback = 1,
    /// The file is unwritable and there is no fallback; records are dropped
    /// (counted in `toxtunnel_log_records_dropped_total`).
    Failed = 2,
};

[[nodiscard]] const char* to_string(LogSinkState state) noexcept;

/// A file sink that survives its file going bad (issue #47).
///
/// spdlog's file sinks throw `spdlog_ex` when fwrite / fflush fails, and the
/// logger answers with a stderr line from its error handler — which goes
/// nowhere for a daemon whose stderr is the same revoked fd. From then on the
/// process logs nothing at all and nothing says so.
///
/// This wrapper owns the real file sink (built by `primary`), catches every
/// failure at the sink boundary, counts it, and recovers best-effort:
///
///  * on a write or flush failure the file sink is discarded and re-created
///    through `primary` — at most once per `retry_interval`, so a dead disk
///    cannot turn every log call into an open() storm;
///  * a re-created sink only counts as recovered once a notice line has been
///    written AND flushed through it; a candidate that opens but cannot write
///    is discarded like the original;
///  * while the file is down, records go to the sink built by `fallback`
///    (if any), and the periodic flush keeps retrying the file so a quiet
///    daemon recovers too.
///
/// Recovery is best effort by construction: the record whose write failed is
/// retried once on the re-created file, but whatever the stdio buffer held
/// when a FLUSH failed is unknown — it may be lost, or partly duplicated.
///
/// Nothing ever propagates out of the sink hooks: an unknown exception type
/// would otherwise be rethrown by spdlog itself (`SPDLOG_LOGGER_CATCH`).
/// Diagnostics never go through `Logger` (that would recurse into this sink).
///
/// The construction-time open is NOT wrapped: a log file that cannot be opened
/// at startup still fails startup, exactly as before.
class ResilientFileSink final : public spdlog::sinks::base_sink<std::mutex> {
   public:
    using SinkFactory = std::function<spdlog::sink_ptr()>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    /// @param primary         Builds the real file sink. Called once here
    ///                        (exceptions propagate) and again on recovery.
    /// @param fallback        Builds the fallback sink lazily, the first time
    ///                        the file is down. May be empty (no fallback).
    /// @param retry_interval  Minimum spacing between reopen attempts.
    /// @param clock           Injectable for tests.
    ResilientFileSink(
        SinkFactory primary, SinkFactory fallback,
        std::chrono::milliseconds retry_interval = std::chrono::seconds(5),
        Clock clock = [] { return std::chrono::steady_clock::now(); });

    [[nodiscard]] LogSinkState state() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override;
    void flush_() override;
    void set_pattern_(const std::string& pattern) override;
    void set_formatter_(std::unique_ptr<spdlog::formatter> sink_formatter) override;

   private:
    // All of these run under base_sink's mutex.
    void deliver(const spdlog::details::log_msg& msg);
    void flush_impl();
    /// Count the failure in flight and drop the file sink. Call inside catch.
    void note_failure() noexcept;
    /// Store the text of the exception in flight. Call inside catch.
    void remember_error() noexcept;
    /// Try to re-create the file sink if the retry deadline has passed.
    void maybe_reopen(spdlog::string_view_t logger_name);
    /// Deliver `msg` to the fallback (null: only announce the outage), building
    /// it on first use; false = nothing could take it.
    bool deliver_fallback(const spdlog::details::log_msg* msg);
    void publish_state() noexcept;

    SinkFactory primary_factory_;
    SinkFactory fallback_factory_;
    std::chrono::milliseconds retry_interval_;
    Clock clock_;

    spdlog::sink_ptr primary_;
    spdlog::sink_ptr fallback_;
    bool fallback_announced_ = false;
    std::chrono::steady_clock::time_point next_retry_{};
    std::string last_error_;

    std::atomic<LogSinkState> state_{LogSinkState::Ok};
};

}  // namespace toxtunnel::util
