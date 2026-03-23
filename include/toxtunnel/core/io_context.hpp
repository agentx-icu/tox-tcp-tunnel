#pragma once

#include <asio.hpp>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace toxtunnel::core {

/// Wrapper around asio::io_context that manages a thread pool of worker
/// threads, provides timer creation helpers, and supports strand creation
/// for serialised handler execution.
///
/// Typical usage:
/// @code
///   IoContext ctx(4);          // 4 worker threads
///   ctx.run();                 // start the thread pool
///
///   ctx.schedule_after(std::chrono::seconds(5), []{ ... });
///   auto strand = ctx.make_strand();
///
///   ctx.stop();                // graceful shutdown
/// @endcode
///
/// The object is non-copyable and non-movable.  Destruction automatically
/// stops the io_context and joins all worker threads.
class IoContext {
   public:
    /// Construct an IoContext.
    /// @param num_threads  Number of worker threads to create when run() is
    ///                     called.  Defaults to the hardware concurrency
    ///                     (or 2 if that cannot be determined).
    explicit IoContext(std::size_t num_threads = 0);

    /// Destructor.  Stops the io_context and joins all threads.
    ~IoContext();

    // Non-copyable, non-movable.
    IoContext(const IoContext&) = delete;
    IoContext& operator=(const IoContext&) = delete;
    IoContext(IoContext&&) = delete;
    IoContext& operator=(IoContext&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Start the worker thread pool.
    ///
    /// Each thread calls io_context::run().  A work guard is held so that
    /// the threads do not exit until stop() is called (or the IoContext is
    /// destroyed) even when there are no pending handlers.
    ///
    /// Calling run() on an already-running IoContext is a no-op.
    void run();

    /// Stop the io_context and join all worker threads.
    ///
    /// Outstanding asynchronous operations are cancelled.  After stop()
    /// returns, run() may be called again (after restart()).
    void stop();

    /// Reset the io_context so that it can be run() again after a stop().
    ///
    /// Must only be called after stop() has returned and before the next
    /// call to run().
    void restart();

    /// Return true if the thread pool is currently running.
    [[nodiscard]] bool is_running() const noexcept { return running_; }

    /// Return the number of worker threads configured.
    [[nodiscard]] std::size_t num_threads() const noexcept { return num_threads_; }

    // -----------------------------------------------------------------
    // Access to the underlying io_context
    // -----------------------------------------------------------------

    /// Return a reference to the underlying asio::io_context.
    [[nodiscard]] asio::io_context& get_io_context() noexcept { return io_context_; }

    /// @overload const access.
    [[nodiscard]] const asio::io_context& get_io_context() const noexcept { return io_context_; }

    /// Return the executor associated with the io_context.
    [[nodiscard]] asio::io_context::executor_type get_executor() noexcept {
        return io_context_.get_executor();
    }

    // -----------------------------------------------------------------
    // Strand creation
    // -----------------------------------------------------------------

    /// Create a strand for serialised (non-concurrent) handler dispatch
    /// on this io_context.
    [[nodiscard]] asio::strand<asio::io_context::executor_type> make_strand() {
        return asio::make_strand(io_context_);
    }

    // -----------------------------------------------------------------
    // Timer helpers
    // -----------------------------------------------------------------

    /// Schedule a handler to be invoked after @p delay has elapsed.
    ///
    /// The handler signature is `void()`.  The timer object is kept alive
    /// internally until the handler fires or is cancelled.
    ///
    /// @param delay   Duration to wait before invoking the handler.
    /// @param handler Callable to invoke when the timer expires.
    template <typename Rep, typename Period, typename Handler>
    void schedule_after(std::chrono::duration<Rep, Period> delay, Handler handler) {
        auto timer = std::make_shared<asio::steady_timer>(io_context_, delay);
        timer->async_wait([handler = std::move(handler), timer](const asio::error_code& ec) {
            if (!ec) {
                handler();
            }
        });
    }

    /// Schedule a handler to be invoked at the given absolute time point.
    ///
    /// @param time_point  The point in time at which the handler should fire.
    /// @param handler     Callable to invoke when the timer expires.
    template <typename Clock, typename Duration, typename Handler>
    void schedule_at(std::chrono::time_point<Clock, Duration> time_point, Handler handler) {
        auto delay = time_point - Clock::now();
        if (delay.count() <= 0) {
            // Already past; post immediately.
            asio::post(io_context_, std::move(handler));
            return;
        }
        schedule_after(std::chrono::duration_cast<std::chrono::steady_clock::duration>(delay),
                       std::move(handler));
    }

    /// Create a steady_timer bound to this io_context.
    ///
    /// The caller owns the returned timer and is responsible for managing
    /// its lifetime.
    [[nodiscard]] asio::steady_timer make_steady_timer() { return asio::steady_timer(io_context_); }

    /// @overload Create a timer that expires after @p delay.
    template <typename Rep, typename Period>
    [[nodiscard]] asio::steady_timer make_steady_timer(std::chrono::duration<Rep, Period> delay) {
        return asio::steady_timer(io_context_, delay);
    }

    // -----------------------------------------------------------------
    // Post / dispatch helpers
    // -----------------------------------------------------------------

    /// Post a handler for deferred execution on one of the worker threads.
    template <typename Handler>
    void post(Handler handler) {
        asio::post(io_context_, std::move(handler));
    }

    /// Dispatch a handler: if the caller is already running inside one of
    /// the worker threads, the handler may be invoked immediately;
    /// otherwise it is posted.
    template <typename Handler>
    void dispatch(Handler handler) {
        asio::dispatch(io_context_, std::move(handler));
    }

   private:
    /// Join all worker threads.  Called internally by stop() and the
    /// destructor.
    void join_threads();

    asio::io_context io_context_;

    /// Work guard that prevents io_context::run() from returning when
    /// there are no pending handlers.  Uses the modern executor_work_guard
    /// API (the old io_context::work is removed under ASIO_NO_DEPRECATED).
    using work_guard_type = asio::executor_work_guard<asio::io_context::executor_type>;
    std::unique_ptr<work_guard_type> work_guard_;

    std::vector<std::thread> threads_;
    std::size_t num_threads_;
    bool running_{false};
};

}  // namespace toxtunnel::core
