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
    if (output_fd_ < 0 || data.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(output_mutex_);
    std::size_t written = 0;
    while (written < data.size() && running_.load()) {
        const auto* buffer = reinterpret_cast<const char*>(data.data() + written);
        const auto remaining = data.size() - written;
        const ssize_t rc = ::write(output_fd_, buffer, remaining);
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

    if (input_thread_.joinable() && input_thread_.get_id() != std::this_thread::get_id()) {
        input_thread_.join();
    }
}

void StdioPipeBridge::read_loop() {
#ifndef _WIN32
    std::array<uint8_t, 4096> buffer{};

    while (running_.load()) {
        const ssize_t rc = ::read(input_fd_, buffer.data(), buffer.size());
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
    if (input_fd_ >= 0) {
        ::close(input_fd_);
        input_fd_ = -1;
    }
    if (output_fd_ >= 0) {
        ::close(output_fd_);
        output_fd_ = -1;
    }
#endif
}

}  // namespace toxtunnel::app
