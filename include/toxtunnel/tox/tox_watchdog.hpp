#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>

namespace toxtunnel::tox {

// ---------------------------------------------------------------------------
// ToxWatchdog
// ---------------------------------------------------------------------------

/// Deadline-based watchdog for the dedicated Tox thread.
///
/// The Tox thread increments `heartbeat()` on every return from
/// `tox_iterate(...)`. A 1 Hz timer on the main `IoContext` reads the
/// timestamp; if the gap exceeds `deadline_seconds` the abort hook fires.
/// In production the abort hook flushes the spdlog sink, increments the
/// persistent abort counter, and calls `std::abort()`. Tests inject a
/// custom hook so the failure case can be observed without killing the
/// process.
///
/// Thread safety: `heartbeat()` is lock-free (single atomic store).
/// `start()` and `stop()` may be called from any thread but a single
/// owner is expected to drive them.
class ToxWatchdog {
   public:
    /// Hook invoked when a stall past the deadline is detected. Default
    /// implementation flushes spdlog and calls `std::abort()`.
    using AbortHook = std::function<void()>;

    ToxWatchdog() = default;
    ~ToxWatchdog();

    ToxWatchdog(const ToxWatchdog&) = delete;
    ToxWatchdog& operator=(const ToxWatchdog&) = delete;
    ToxWatchdog(ToxWatchdog&&) = delete;
    ToxWatchdog& operator=(ToxWatchdog&&) = delete;

    /// Configure the deadline + behaviour. Safe to call before `start()`.
    void configure(std::chrono::seconds deadline, bool enabled);

    /// Override the path of the abort counter file. Defaults to "<data_dir>/
    /// abort_count" once `set_data_dir()` is called. Empty path disables
    /// persistence.
    void set_data_dir(const std::filesystem::path& data_dir);

    /// Override the abort hook (tests, custom shutdown). Defaults to flush +
    /// `std::abort()`.
    void set_abort_hook(AbortHook hook);

    /// Override the systemd notifier hook (default: send `WATCHDOG=1`).
    using NotifyHook = std::function<void()>;
    void set_systemd_notify_hook(NotifyHook hook) { systemd_notify_hook_ = std::move(hook); }

    /// Start the 1 Hz observer timer on the supplied io_context. The watchdog
    /// becomes effective from this point.
    void start(asio::io_context& io_ctx);

    /// Stop the observer timer. Idempotent.
    void stop();

    /// Called by the Tox thread on every successful return from `tox_iterate`.
    /// Lock-free.
    void heartbeat() noexcept;

    /// Force a check now (test hook + main-thread shutdown path).
    /// Returns the observed lag in milliseconds.
    std::int64_t check_once() noexcept;

    /// Atomic counters surfaced to inspect / metrics.
    [[nodiscard]] std::uint64_t heartbeat_count() const noexcept {
        return heartbeat_counter_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::int64_t last_heartbeat_ns() const noexcept {
        return last_heartbeat_ns_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::int64_t lag_ms() const noexcept {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto last = last_heartbeat_ns_.load(std::memory_order_acquire);
        if (last == 0) {
            return 0;
        }
        return (now - last) / 1'000'000;
    }

    [[nodiscard]] bool enabled() const noexcept { return enabled_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::chrono::seconds deadline() const noexcept {
        return std::chrono::seconds(deadline_seconds_.load(std::memory_order_relaxed));
    }

   private:
    void arm_timer();
    void persist_abort_count();
    static void default_abort_hook();

    std::atomic<std::uint64_t> heartbeat_counter_{0};
    std::atomic<std::int64_t> last_heartbeat_ns_{0};
    std::atomic<int> deadline_seconds_{30};
    std::atomic<bool> enabled_{true};
    std::atomic<bool> aborted_{false};

    asio::io_context* io_ctx_{nullptr};
    std::unique_ptr<asio::steady_timer> timer_;
    std::atomic<bool> running_{false};

    std::filesystem::path data_dir_;
    AbortHook abort_hook_;
    NotifyHook systemd_notify_hook_;
};

}  // namespace toxtunnel::tox
