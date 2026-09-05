#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>

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

    ToxWatchdog();
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
    /// `std::abort()`. Observer hooks run on the supplied io_context and may
    /// call or wait for `stop()`, but must not synchronously destroy this
    /// object: destruction waits for an in-flight observer hook to return.
    void set_abort_hook(AbortHook hook);

    /// Override the systemd notifier hook (default: send `WATCHDOG=1`). The
    /// observer-hook lifetime constraint documented above also applies here.
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
    ///
    /// Suspend immunity (issue #38): a stale heartbeat alone does not abort.
    /// A host that sleeps, or a hypervisor that pauses the guest, leaves the
    /// heartbeat hours old on resume while the Tox thread is perfectly fine —
    /// that was every watchdog abort on the Windows QA rig. So the observer
    /// (a) ignores a tick after which it can see it was itself stalled for
    /// longer than the deadline (the whole process was suspended), and
    /// (b) requires the heartbeat COUNTER to stay unchanged for
    /// `kConfirmationTicks` consecutive over-deadline ticks before it aborts.
    /// A real wedge still trips after deadline + a few seconds.
    std::int64_t check_once() noexcept;

    /// Consecutive over-deadline observer ticks, with no heartbeat progress,
    /// required before the abort hook runs. Each tick is ~1 s of the observer
    /// actually running, so a suspend/resume — which yields one tick with a
    /// huge lag and then a moving heartbeat — never reaches it.
    static constexpr unsigned kConfirmationTicks = 5;

    /// What the Tox thread is doing right now, reported by its owner so a
    /// stall names the phase it is stuck in (tox_iterate itself, a posted
    /// task, an application callback, ...). Lock-free.
    enum class Phase : std::uint8_t { Idle, Iterate, Tasks, Dispatch, Maintenance };
    void note_phase(Phase phase) noexcept {
        phase_.store(static_cast<std::uint8_t>(phase), std::memory_order_relaxed);
    }
    [[nodiscard]] Phase phase() const noexcept {
        return static_cast<Phase>(phase_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] static const char* phase_name(Phase phase) noexcept;

    /// Over-deadline ticks observed so far without heartbeat progress (test
    /// observability; resets whenever the heartbeat moves).
    [[nodiscard]] unsigned over_deadline_ticks() const noexcept {
        return over_deadline_ticks_.load(std::memory_order_relaxed);
    }

    /// Test seams: make the last heartbeat / the observer's own last check
    /// look @p age old, so the deadline logic can be driven without sleeping.
    void backdate_heartbeat_for_test(std::chrono::milliseconds age) noexcept;
    void backdate_last_check_for_test(std::chrono::milliseconds age) noexcept;

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
    struct ObserverState;

    void arm_timer();
    void arm_timer_locked();
    void persist_abort_count();
    static void default_abort_hook();

    std::atomic<std::uint64_t> heartbeat_counter_{0};
    std::atomic<std::int64_t> last_heartbeat_ns_{0};
    std::atomic<int> deadline_seconds_{30};
    std::atomic<bool> enabled_{true};
    std::atomic<bool> aborted_{false};

    /// Observer bookkeeping for the confirmation logic (see check_once()).
    /// Written only by check_once(); atomics because the shutdown path may
    /// call it from another thread than the timer.
    std::atomic<std::uint64_t> last_seen_heartbeat_{0};
    std::atomic<unsigned> over_deadline_ticks_{0};
    std::atomic<std::int64_t> last_check_ns_{0};
    /// One-shot per stall: the half-deadline early warning fires once and
    /// re-arms only after the heartbeat moves again.
    std::atomic<bool> stall_warned_{false};
    std::atomic<std::uint8_t> phase_{0};
    /// A stalled observer is forgiven ONCE per unchanged heartbeat: if the
    /// observer keeps arriving late while the heartbeat still does not move,
    /// that is a starved process with a wedged Tox thread, and the late ticks
    /// count towards confirmation instead of resetting it every time.
    std::atomic<bool> suspend_forgiven_{false};
    /// Serialises check_once(): the 1 Hz timer and the shutdown path may both
    /// call it, and two overlapping checks must not count one observer
    /// interval twice. A check that finds another in progress skips itself.
    std::mutex check_mutex_;

    asio::io_context* io_ctx_{nullptr};
    std::unique_ptr<asio::steady_timer> timer_;
    std::atomic<bool> running_{false};
    std::shared_ptr<ObserverState> observer_state_;

    std::filesystem::path data_dir_;
    AbortHook abort_hook_;
    NotifyHook systemd_notify_hook_;
};

}  // namespace toxtunnel::tox
