#include "toxtunnel/tox/tox_watchdog.hpp"

#include <cstdlib>
#include <fstream>
#include <string>

#include "toxtunnel/util/atomic_file.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/systemd_notify.hpp"

namespace toxtunnel::tox {

ToxWatchdog::~ToxWatchdog() {
    stop();
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
    io_ctx_ = &io_ctx;
    timer_ = std::make_unique<asio::steady_timer>(io_ctx);
    // Seed the heartbeat so the very first observer tick doesn't fire on a
    // pristine state (last_heartbeat_ns == 0).
    last_heartbeat_ns_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                             std::memory_order_release);
    arm_timer();
}

void ToxWatchdog::stop() {
    if (!running_.exchange(false)) {
        return;
    }
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

std::int64_t ToxWatchdog::check_once() noexcept {
    const auto lag = lag_ms();
    util::MetricsRegistry::instance().set_tox_iterate_lag_ms(lag);
    if (!enabled_.load(std::memory_order_relaxed)) {
        return lag;
    }
    const auto deadline_ms =
        static_cast<std::int64_t>(deadline_seconds_.load(std::memory_order_relaxed)) * 1000;
    if (lag > deadline_ms && !aborted_.exchange(true)) {
        util::Logger::critical(
            "tox_thread wedge detected: lag_ms={} deadline_ms={} heartbeat_count={}", lag,
            deadline_ms, heartbeat_count());
        persist_abort_count();
        if (abort_hook_) {
            abort_hook_();
        } else {
            default_abort_hook();
        }
    } else if (systemd_notify_hook_) {
        systemd_notify_hook_();
    }
    return lag;
}

void ToxWatchdog::arm_timer() {
    if (!timer_ || !running_.load()) {
        return;
    }
    timer_->expires_after(std::chrono::seconds(1));
    timer_->async_wait([this](const asio::error_code& ec) {
        if (ec || !running_.load()) {
            return;
        }
        check_once();
        arm_timer();
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
