#include "toxtunnel/tox/tox_watchdog.hpp"

#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <string>

#include "toxtunnel/util/atomic_file.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/systemd_notify.hpp"

namespace toxtunnel::tox {

struct ToxWatchdog::ObserverState {
    std::mutex mutex;
    std::condition_variable callbacks_drained;
    ToxWatchdog* owner{nullptr};
    std::size_t callbacks_in_flight{0};
    std::uint64_t generation{0};
};

ToxWatchdog::ToxWatchdog() : observer_state_(std::make_shared<ObserverState>()) {
    observer_state_->owner = this;
}

ToxWatchdog::~ToxWatchdog() {
    stop();
    std::unique_lock lock(observer_state_->mutex);
    observer_state_->callbacks_drained.wait(
        lock, [state = observer_state_] { return state->callbacks_in_flight == 0; });
    observer_state_->owner = nullptr;
}

void ToxWatchdog::configure(std::chrono::seconds deadline, bool enabled) {
    // Enforce the design-doc minimum of 5 seconds — below that, legitimate
    // toxcore behaviour can trip false positives.
    auto secs = static_cast<int>(deadline.count());
    if (secs < 5) {
        secs = 5;
    }
    deadline_seconds_.store(secs, std::memory_order_relaxed);
    enabled_.store(enabled, std::memory_order_relaxed);
}

void ToxWatchdog::set_data_dir(const std::filesystem::path& data_dir) {
    data_dir_ = data_dir;
}

void ToxWatchdog::set_abort_hook(AbortHook hook) {
    abort_hook_ = std::move(hook);
}

void ToxWatchdog::start(asio::io_context& io_ctx) {
    if (running_.exchange(true)) {
        return;
    }

    std::lock_guard lock(observer_state_->mutex);
    // A concurrent stop() may have won after the exchange above but before
    // this thread acquired the observer lock.
    if (!running_.load()) {
        return;
    }
    ++observer_state_->generation;
    io_ctx_ = &io_ctx;
    timer_ = std::make_unique<asio::steady_timer>(io_ctx);
    // Seed the heartbeat so the very first observer tick doesn't fire on a
    // pristine state (last_heartbeat_ns == 0).
    last_heartbeat_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                             std::memory_order_release);
    arm_timer_locked();
}

void ToxWatchdog::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    std::lock_guard lock(observer_state_->mutex);
    ++observer_state_->generation;
    if (timer_) {
        try {
            timer_->cancel();
        } catch (...) {
            // Cancelling an already-expired timer can throw; we don't care.
        }
        timer_.reset();
    }
    io_ctx_ = nullptr;
}

void ToxWatchdog::heartbeat() noexcept {
    heartbeat_counter_.fetch_add(1, std::memory_order_relaxed);
    last_heartbeat_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                             std::memory_order_release);
}

const char* ToxWatchdog::phase_name(Phase phase) noexcept {
    switch (phase) {
        case Phase::Idle:
            return "idle";
        case Phase::Iterate:
            return "tox_iterate";
        case Phase::Tasks:
            return "posted tasks";
        case Phase::Dispatch:
            return "application callbacks";
        case Phase::Maintenance:
            return "maintenance";
    }
    return "unknown";
}

void ToxWatchdog::backdate_heartbeat_for_test(std::chrono::milliseconds age) noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    last_heartbeat_ns_.store(now - std::chrono::nanoseconds(age).count(),
                             std::memory_order_release);
}

void ToxWatchdog::backdate_last_check_for_test(std::chrono::milliseconds age) noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    last_check_ns_.store(now - std::chrono::nanoseconds(age).count(), std::memory_order_relaxed);
}

std::int64_t ToxWatchdog::check_once() noexcept {
    const auto lag = lag_ms();
    util::MetricsRegistry::instance().set_tox_iterate_lag_ms(lag);
    if (!enabled_.load(std::memory_order_relaxed)) {
        return lag;
    }
    const auto deadline_ms =
        static_cast<std::int64_t>(deadline_seconds_.load(std::memory_order_relaxed)) * 1000;

    // One check at a time; an overlapping caller (shutdown path vs. timer)
    // must not count the same unchanged heartbeat twice.
    std::unique_lock<std::mutex> serial(check_mutex_, std::try_to_lock);
    if (!serial.owns_lock()) {
        return lag;
    }

    // How long since this observer itself last ran. The observer is a 1 Hz
    // timer; a gap far beyond that means the observer was not running either —
    // the process (or the whole machine) was suspended.
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto prev_check_ns = last_check_ns_.exchange(now_ns, std::memory_order_relaxed);
    const std::int64_t observer_gap_ms =
        prev_check_ns == 0 ? 0 : (now_ns - prev_check_ns) / 1'000'000;

    const std::uint64_t hb = heartbeat_count();
    const std::uint64_t seen = last_seen_heartbeat_.exchange(hb, std::memory_order_relaxed);
    if (hb != seen) {
        // The Tox thread made progress since the last tick, whatever the
        // timestamp says. Everything below is about a heartbeat that has NOT
        // moved.
        over_deadline_ticks_.store(0, std::memory_order_relaxed);
        suspend_forgiven_.store(false, std::memory_order_relaxed);
        if (stall_warned_.exchange(false, std::memory_order_relaxed)) {
            util::Logger::info("tox_thread heartbeat resumed (lag_ms={} at the last check)", lag);
        }
        if (systemd_notify_hook_) {
            systemd_notify_hook_();
        }
        return lag;
    }

    if (observer_gap_ms > deadline_ms &&
        !suspend_forgiven_.exchange(true, std::memory_order_relaxed)) {
        // The observer did not run for longer than the deadline, so neither
        // did anything else in this process: a suspend/resume, not a wedge.
        // The heartbeat's age proves nothing yet; give the Tox thread a tick
        // to show life before counting anything against it (issue #38).
        // Forgiven ONCE per unchanged heartbeat: a process so starved that
        // the observer keeps arriving late while the heartbeat never moves
        // has a wedged Tox thread after all, and its late ticks count.
        util::Logger::warn(
            "watchdog observer itself stalled for {} ms (process suspended?); ignoring the {} ms "
            "heartbeat lag until the Tox thread has had a chance to run",
            observer_gap_ms, lag);
        over_deadline_ticks_.store(0, std::memory_order_relaxed);
        return lag;
    }

    if (lag > deadline_ms) {
        const unsigned ticks = over_deadline_ticks_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ticks < kConfirmationTicks) {
            util::Logger::warn(
                "tox_thread heartbeat stale for {} ms (deadline {} ms, phase={}); confirming "
                "wedge ({}/{})",
                lag, deadline_ms, phase_name(phase()), ticks, kConfirmationTicks);
            return lag;
        }
        if (!aborted_.exchange(true)) {
            util::Logger::critical(
                "tox_thread wedge detected: lag_ms={} deadline_ms={} heartbeat_count={} phase={} "
                "(confirmed over {} consecutive checks); aborting so the service manager restarts "
                "the daemon",
                lag, deadline_ms, hb, phase_name(phase()), ticks);
            persist_abort_count();
            if (abort_hook_) {
                abort_hook_();
            } else {
                default_abort_hook();
            }
        }
        return lag;
    }

    if (lag > deadline_ms / 2) {
        // Early warning, once per stall: survives in the log even if the
        // final line is lost with the process.
        if (!stall_warned_.exchange(true, std::memory_order_relaxed)) {
            util::Logger::warn(
                "tox_thread has not returned for {} ms (deadline {} ms, phase={}); will abort if "
                "it stays stalled",
                lag, deadline_ms, phase_name(phase()));
        }
        return lag;
    }

    if (systemd_notify_hook_) {
        systemd_notify_hook_();
    }
    return lag;
}

void ToxWatchdog::arm_timer() {
    std::lock_guard lock(observer_state_->mutex);
    arm_timer_locked();
}

void ToxWatchdog::arm_timer_locked() {
    if (!timer_ || !running_.load()) {
        return;
    }
    timer_->expires_after(std::chrono::seconds(1));
    const auto generation = observer_state_->generation;
    timer_->async_wait([state = observer_state_, generation](const asio::error_code& ec) {
        std::unique_lock lock(state->mutex);
        auto* owner = state->owner;
        if (ec || owner == nullptr || state->generation != generation || !owner->running_.load()) {
            return;
        }

        ++state->callbacks_in_flight;
        lock.unlock();
        owner->check_once();

        lock.lock();
        --state->callbacks_in_flight;
        state->callbacks_drained.notify_all();
        if (state->owner == owner && state->generation == generation && owner->running_.load()) {
            owner->arm_timer_locked();
        }
    });
}

void ToxWatchdog::persist_abort_count() {
    util::MetricsRegistry::instance().inc_watchdog_aborts();
    if (data_dir_.empty()) {
        return;
    }
    try {
        const auto path = data_dir_ / "abort_count";
        std::uint64_t current = 0;
        {
            std::ifstream in(path);
            if (in) {
                in >> current;
            }
        }
        ++current;
        // Use atomic_write_file so an abort triggered between truncate and
        // write does not zero the persisted counter (the previous
        // ios::trunc + write was vulnerable to exactly that race).
        const std::string serialised = std::to_string(current) + '\n';
        (void)util::atomic_write_file(path, serialised);
    } catch (...) {
        // Best-effort; never let the abort path itself throw.
    }
}

void ToxWatchdog::default_abort_hook() {
    util::Logger::flush();
    std::abort();
}

}  // namespace toxtunnel::tox
