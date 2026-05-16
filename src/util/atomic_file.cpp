#include "toxtunnel/util/atomic_file.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/fcntl.h>
#endif
#endif

namespace toxtunnel::util {

namespace {

#if !defined(_WIN32)
[[nodiscard]] bool write_all(int fd, const std::uint8_t* data, std::size_t size) noexcept {
    while (size > 0) {
        const auto n = ::write(fd, data, size);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        data += n;
        size -= static_cast<std::size_t>(n);
    }
    return true;
}
#endif

#if !defined(_WIN32)
Expected<void, std::string> posix_write(const std::filesystem::path& path,
                                        std::span<const std::uint8_t> contents,
                                        const AtomicFileOptions& opts) {
    auto tmp = path;
    tmp += ".tmp." + std::to_string(::getpid());

    const auto mode_bits = static_cast<mode_t>(opts.mode);
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode_bits);
    if (fd < 0) {
        return make_unexpected(std::string("open tmp '") + tmp.string() +
                               "': " + std::strerror(errno));
    }
    if (!write_all(fd, contents.data(), contents.size())) {
        const auto err = std::strerror(errno);
        ::close(fd);
        ::unlink(tmp.c_str());
        return make_unexpected(std::string("write tmp '") + tmp.string() + "': " + err);
    }

#if defined(__APPLE__)
    if (opts.use_full_fsync_macos) {
        if (::fcntl(fd, F_FULLFSYNC) != 0) {
            // F_FULLFSYNC can fail on some filesystems (network FS); fall
            // through to plain fsync as a best-effort.
            if (::fsync(fd) != 0) {
                const auto err = std::strerror(errno);
                ::close(fd);
                ::unlink(tmp.c_str());
                return make_unexpected(std::string("fsync tmp: ") + err);
            }
        }
    } else {
        if (::fsync(fd) != 0) {
            const auto err = std::strerror(errno);
            ::close(fd);
            ::unlink(tmp.c_str());
            return make_unexpected(std::string("fsync tmp: ") + err);
        }
    }
#else
    if (::fsync(fd) != 0) {
        const auto err = std::strerror(errno);
        ::close(fd);
        ::unlink(tmp.c_str());
        return make_unexpected(std::string("fsync tmp: ") + err);
    }
#endif

    if (::close(fd) != 0) {
        const auto err = std::strerror(errno);
        ::unlink(tmp.c_str());
        return make_unexpected(std::string("close tmp: ") + err);
    }

    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        const auto err = std::strerror(errno);
        ::unlink(tmp.c_str());
        return make_unexpected(std::string("rename to '") + path.string() + "': " + err);
    }

    if (opts.fsync_parent_dir) {
        const auto parent = path.parent_path();
        if (!parent.empty()) {
            const int dfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd >= 0) {
                (void)::fsync(dfd);
                ::close(dfd);
            }
            // Best-effort: a missing parent fsync is rarely fatal.
        }
    }
    return {};
}
#endif

#if defined(_WIN32)
Expected<void, std::string> windows_write(const std::filesystem::path& path,
                                          std::span<const std::uint8_t> contents,
                                          const AtomicFileOptions& /*opts*/) {
    auto tmp = path;
    tmp += ".tmp";

    HANDLE h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return make_unexpected(std::string("CreateFileW tmp failed: ") +
                               std::to_string(::GetLastError()));
    }
    DWORD written = 0;
    if (!::WriteFile(h, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) ||
        written != contents.size()) {
        ::CloseHandle(h);
        ::DeleteFileW(tmp.c_str());
        return make_unexpected(std::string("WriteFile tmp failed: ") +
                               std::to_string(::GetLastError()));
    }
    ::FlushFileBuffers(h);
    ::CloseHandle(h);

    if (!::MoveFileExW(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto err = ::GetLastError();
        ::DeleteFileW(tmp.c_str());
        return make_unexpected(std::string("MoveFileExW failed: ") + std::to_string(err));
    }
    return {};
}
#endif

}  // namespace

Expected<void, std::string> atomic_write_file(const std::filesystem::path& path,
                                              std::span<const std::uint8_t> contents,
                                              const AtomicFileOptions& options) {
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return make_unexpected(std::string("create_directories: ") + ec.message());
        }
    }
#if defined(_WIN32)
    return windows_write(path, contents, options);
#else
    return posix_write(path, contents, options);
#endif
}

Expected<void, std::string> atomic_write_file(const std::filesystem::path& path,
                                              std::string_view contents,
                                              const AtomicFileOptions& options) {
    return atomic_write_file(
        path,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(contents.data()),
                                      contents.size()),
        options);
}

}  // namespace toxtunnel::util
