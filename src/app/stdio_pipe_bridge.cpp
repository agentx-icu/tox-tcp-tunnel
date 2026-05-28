#include "toxtunnel/app/stdio_pipe_bridge.hpp"

#include <array>
#include <cerrno>

#include "toxtunnel/util/logger.hpp"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace toxtunnel::app {

StdioPipeBridge::StdioPipeBridge(int input_fd, int output_fd) {
#ifndef _WIN32
    input_fd_ = ::dup(input_fd);
    output_fd_ = ::dup(output_fd);
#else
    (void)input_fd;
    (void)output_fd;
#endif
}

StdioPipeBridge::~StdioPipeBridge() {
    stop();
}

util::Expected<void, std::string> StdioPipeBridge::start(InputCallback on_input,
                                                         ClosedCallback on_closed) {
#ifdef _WIN32
    (void)on_input;
    (void)on_closed;
    return util::make_unexpected(std::string("StdioPipeBridge is not implemented on Windows"));
#else
    if (running_.exchange(true)) {
        return util::make_unexpected(std::string("StdioPipeBridge is already running"));
    }

    if (input_fd_ < 0 || output_fd_ < 0) {
        running_.store(false);
        return util::make_unexpected(std::string("Failed to duplicate stdio file descriptors"));
    }

    on_input_ = std::move(on_input);
    on_closed_ = std::move(on_closed);
    input_thread_ = std::thread([this] { read_loop(); });
    return {};
#endif
}

void StdioPipeBridge::write_output(std::span<const uint8_t> data) {
#ifndef _WIN32
    if (data.empty()) {
        return;
    }

    // output_mutex_ serializes concurrent writers so their byte streams never
    // interleave. The fd is snapshotted under fd_mutex_ and the ::write runs
    // WITHOUT fd_mutex_ held, so close_descriptors() (which takes only fd_mutex_,
    // never output_mutex_) can close the fd to interrupt a stalled write instead
    // of wedging behind it. running_ is always cleared before close_descriptors()
    // runs and is re-checked each iteration, so once teardown starts the loop
    // stops issuing writes; an in-flight ::write is interrupted by the close.
    //
    // Residual (accepted): a teardown that closes the fd in the brief window
    // between this snapshot and the ::write, AND a concurrent open() in another
    // thread reusing that exact fd number, would write to the wrong descriptor.
    // Closing fully needs non-blocking I/O — unsafe here: O_NONBLOCK on a dup()'d
    // stdio fd flips the shared open-file-description flag and would make the
    // parent's real stdout non-blocking — or a self-pipe redesign, both
    // disproportionate for this one-shot, process-lifetime bridge.
    std::lock_guard<std::mutex> write_lock(output_mutex_);
    int fd;
    {
        std::lock_guard<std::mutex> fd_lock(fd_mutex_);
        fd = output_fd_;
    }
    if (fd < 0) {
        return;
    }
    std::size_t written = 0;
    while (written < data.size() && running_.load()) {
        const auto* buffer = reinterpret_cast<const char*>(data.data() + written);
        const auto remaining = data.size() - written;
        const ssize_t rc = ::write(fd, buffer, remaining);
        if (rc > 0) {
            written += static_cast<std::size_t>(rc);
            continue;
        }
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
#else
    (void)data;
#endif
}

void StdioPipeBridge::stop() {
    running_.store(false);
    close_descriptors();

    std::thread thread_to_join;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (!input_thread_.joinable()) {
            return;
        }
        if (input_thread_.get_id() == std::this_thread::get_id()) {
            input_thread_.detach();
            return;
        }
        thread_to_join = std::move(input_thread_);
    }

    if (thread_to_join.joinable()) {
        thread_to_join.join();
    }
}

void StdioPipeBridge::read_loop() {
#ifndef _WIN32
    // Snapshot input_fd_ once under fd_mutex_ and read the local thereafter, so
    // this thread never races close_descriptors()'s write of the member. A
    // close() of the same descriptor still interrupts the blocked ::read below.
    int fd;
    {
        std::lock_guard<std::mutex> fd_lock(fd_mutex_);
        fd = input_fd_;
    }
    std::array<uint8_t, 4096> buffer{};

    while (running_.load()) {
        const ssize_t rc = ::read(fd, buffer.data(), buffer.size());
        if (rc > 0) {
            if (on_input_) {
                on_input_(std::span<const uint8_t>(buffer.data(), static_cast<std::size_t>(rc)));
            }
            continue;
        }

        if (rc == 0) {
            break;
        }

        if (errno == EINTR) {
            continue;
        }

        if (!running_.load()) {
            return;
        }

        util::Logger::debug("StdioPipeBridge read error: {}", std::strerror(errno));
        break;
    }

    if (running_.exchange(false) && on_closed_) {
        on_closed_();
    }

    close_descriptors();
#endif
}

void StdioPipeBridge::close_descriptors() {
#ifndef _WIN32
    // Called from both stop() and read_loop() on different threads. Swap the
    // fds to -1 under fd_mutex_ (held only briefly, never across I/O) so exactly
    // one caller observes each positive descriptor: no double-close, and no
    // closing of a number the OS has already reissued. Closing the old fd here
    // interrupts read_loop's blocked ::read and any in-flight write_output
    // ::write; taking fd_mutex_ rather than output_mutex_ means we never wait
    // behind a stalled write, so shutdown can't wedge.
    int in_fd;
    int out_fd;
    {
        std::lock_guard<std::mutex> fd_lock(fd_mutex_);
        in_fd = input_fd_;
        input_fd_ = -1;
        out_fd = output_fd_;
        output_fd_ = -1;
    }
    if (in_fd >= 0) {
        ::close(in_fd);
    }
    if (out_fd >= 0) {
        ::close(out_fd);
    }
#endif
}

}  // namespace toxtunnel::app
