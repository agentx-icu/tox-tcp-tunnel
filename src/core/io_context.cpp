#include "toxtunnel/core/io_context.hpp"

#include <algorithm>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::core {

IoContext::IoContext(std::size_t num_threads)
    : num_threads_(num_threads == 0 ? std::max<std::size_t>(std::thread::hardware_concurrency(), 2)
                                    : num_threads) {}

IoContext::~IoContext() {
    stop();
}

// =========================================================================
// Lifecycle
// =========================================================================

void IoContext::run() {
    if (running_.load(std::memory_order_acquire)) {
        util::Logger::debug("IoContext::run() called but already running; ignoring");
        return;
    }

    running_.store(true, std::memory_order_release);

    // Install a work guard so that io_context::run() does not return
    // while we want the thread pool to stay alive.
    work_guard_ = std::make_unique<work_guard_type>(io_context_.get_executor());

    threads_.reserve(num_threads_);
    for (std::size_t i = 0; i < num_threads_; ++i) {
        threads_.emplace_back([this, i]() {
            util::Logger::debug("IoContext worker thread {} started", i);
            io_context_.run();
            util::Logger::debug("IoContext worker thread {} exiting", i);
        });
    }

    util::Logger::info("IoContext started with {} worker thread(s)", num_threads_);
}

void IoContext::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    util::Logger::info("IoContext stopping...");

    // Release the work guard so that run() can return once all pending
    // handlers have completed or been cancelled.
    work_guard_.reset();

    // Request the io_context to stop processing.  Outstanding async
    // operations will be cancelled.
    io_context_.stop();

    join_threads();

    running_.store(false, std::memory_order_release);
    util::Logger::info("IoContext stopped");
}

void IoContext::restart() {
    if (running_.load(std::memory_order_acquire)) {
        util::Logger::warn("IoContext::restart() called while still running; stopping first");
        stop();
    }

    io_context_.restart();
    util::Logger::debug("IoContext restarted; ready for run()");
}

// =========================================================================
// Internal helpers
// =========================================================================

void IoContext::join_threads() {
    const auto this_id = std::this_thread::get_id();
    for (auto& thread : threads_) {
        if (!thread.joinable()) {
            continue;
        }
        if (thread.get_id() == this_id) {
            // Defense-in-depth: stop()/join must never run on one of our own
            // worker threads (that would self-join → std::system_error or a
            // hang). Callers route shutdown to a non-worker thread (see
            // TunnelClient::request_stop). If we somehow land here anyway,
            // detaching is the least-bad option — io_context_.stop() has
            // already been requested, so this thread's run() returns promptly.
            util::Logger::error(
                "IoContext::join_threads called from a worker thread; detaching to avoid "
                "self-join deadlock (shutdown should be driven from a non-worker thread)");
            thread.detach();
            continue;
        }
        thread.join();
    }
    threads_.clear();
}

}  // namespace toxtunnel::core
