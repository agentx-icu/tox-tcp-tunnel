#include "toxtunnel/util/atomic_file.hpp"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>

#include <vector>
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

// Process-monotonic counter so two calls in the same process (and even the
// same thread) never collide on a temp name. Combined with the thread id and
// PID below, the staging file is unique per call — the M-04 fix. Without it,
// two threads writing the same target path shared `<path>.tmp.<pid>` and
// truncated / renamed over each other.
std::atomic<std::uint64_t> g_tmp_counter{0};

// Build the per-call unique suffix appended after ".tmp.". Form is
// "<pid>.<thread-id>.<counter>" so it is stable to read in a directory listing
// yet collision-free across threads and repeated calls.
std::string unique_tmp_suffix() {
    std::ostringstream oss;
#if defined(_WIN32)
    oss << ::GetCurrentProcessId();
#else
    oss << static_cast<long long>(::getpid());
#endif
    oss << '.' << std::this_thread::get_id() << '.'
        << g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

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
    const auto mode_bits = static_cast<mode_t>(opts.mode);

    // M-04: open the staging file with O_EXCL so two concurrent writers can
    // never share one temp file. The suffix is unique per call, but O_EXCL is
    // the hard guarantee — on the astronomically unlikely collision we retry
    // with a fresh suffix rather than clobber an in-flight writer.
    std::filesystem::path tmp;
    int fd = -1;
    for (int attempt = 0; attempt < 8; ++attempt) {
        tmp = path;
        tmp += ".tmp." + unique_tmp_suffix();
        fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode_bits);
        if (fd >= 0) {
            break;
        }
        if (errno == EEXIST) {
            continue;
        }
        return make_unexpected(std::string("open tmp '") + tmp.string() +
                               "': " + std::strerror(errno));
    }
    if (fd < 0) {
        return make_unexpected(std::string("open tmp '") + tmp.string() +
                               "': could not create a unique staging file");
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
#if defined(__APPLE__)
                // macOS fsync() does not flush platter caches; F_FULLFSYNC
                // does. The header doc promises "F_FULLFSYNC on macOS for
                // the identity file" — for that promise to hold end to
                // end, the *directory entry* commit also needs the full
                // barrier. F_FULLFSYNC may fail on some FS (network FS,
                // older HFS); plain fsync is the documented fallback
                // (H-35 in the 2026-05-20 review).
                if (opts.use_full_fsync_macos) {
                    if (::fcntl(dfd, F_FULLFSYNC) != 0) {
                        (void)::fsync(dfd);
                    }
                } else {
                    (void)::fsync(dfd);
                }
#else
                (void)::fsync(dfd);
#endif
                ::close(dfd);
            }
            // Best-effort: a missing parent fsync is rarely fatal.
        }
    }
    return {};
}
#endif

#if defined(_WIN32)

// M-S-1 (2026-05-20 fix-storm review): on POSIX the `opts.mode` field
// is applied via open(2)'s mode argument so callers like tox_save.dat
// land at 0600. The Windows path used to ignore opts entirely, so the
// Tox private-key file inherited the parent directory's DACL — on a
// multi-user box that meant other users could read the identity.
// Build an owner-only SECURITY_ATTRIBUTES when the caller asks for
// restricted perms (any POSIX-style mode that excludes group/world);
// otherwise fall back to inherited ACLs (matches the 0644 default).
namespace {

// A POSIX mode of 0600/0400 has the group + world bits all zero.
// Accept the strongly-typed std::filesystem::perms so callers can pass
// opts.mode without an explicit cast; on MSVC the conversion to
// unsigned is not implicit (CI-pedantic-fix follow-up 2026-05-21).
bool is_owner_only_mode(std::filesystem::perms mode) {
    using P = std::filesystem::perms;
    constexpr auto kGroupOrWorld = P::group_all | P::others_all;
    return (mode & kGroupOrWorld) == P::none;
}

struct OwnerOnlySa {
    PSECURITY_DESCRIPTOR sd = nullptr;
    SECURITY_ATTRIBUTES sa{};
    ~OwnerOnlySa() {
        if (sd) {
            ::LocalFree(sd);
        }
    }
};

// Build an SD that grants the current user GENERIC_ALL and excludes
// everyone else via a protected DACL. Returns false on any Win32
// failure (caller falls back to the inherited ACL — same as before).
bool build_owner_only_sa(OwnerOnlySa& out) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    DWORD needed = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        ::CloseHandle(token);
        return false;
    }
    std::vector<std::uint8_t> buf(needed);
    if (!::GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
        ::CloseHandle(token);
        return false;
    }
    ::CloseHandle(token);

    PSID user_sid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
    LPSTR sid_str = nullptr;
    if (!::ConvertSidToStringSidA(user_sid, &sid_str)) {
        return false;
    }
    // SDDL: owner = user, group = user, protected DACL with one ACE
    // granting GENERIC_ALL ("GA") to the user SID. "P" prevents
    // inheritance of less-restrictive parent ACEs.
    std::string sddl = "O:";
    sddl += sid_str;
    sddl += "G:";
    sddl += sid_str;
    sddl += "D:P(A;;GA;;;";
    sddl += sid_str;
    sddl += ")";
    ::LocalFree(sid_str);

    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1,
                                                                &out.sd, nullptr)) {
        return false;
    }
    out.sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    out.sa.lpSecurityDescriptor = out.sd;
    out.sa.bInheritHandle = FALSE;
    return true;
}

}  // namespace

Expected<void, std::string> windows_write(const std::filesystem::path& path,
                                          std::span<const std::uint8_t> contents,
                                          const AtomicFileOptions& opts) {
    // M-04: the staging file name is unique per call (PID + thread id +
    // process-monotonic counter), and CREATE_NEW makes that a hard guarantee —
    // two concurrent writers of the same target can never share one temp file
    // and clobber each other. The old code used the PID alone with
    // CREATE_ALWAYS, so two threads in one process raced the same temp.
    OwnerOnlySa owner_only;
    SECURITY_ATTRIBUTES* sa_ptr = nullptr;
    if (is_owner_only_mode(opts.mode) && build_owner_only_sa(owner_only)) {
        sa_ptr = &owner_only.sa;
    }

    // unique_tmp_suffix() returns narrow chars (digits, dots, hex thread id);
    // widen them trivially since they are all 7-bit ASCII.
    const std::string suffix_narrow = unique_tmp_suffix();
    std::wstring suffix_wide(suffix_narrow.begin(), suffix_narrow.end());

    std::filesystem::path tmp;
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 8; ++attempt) {
        tmp = path;
        if (attempt == 0) {
            tmp += L".tmp." + suffix_wide;
        } else {
            // Fresh suffix on the (near-impossible) CREATE_NEW collision.
            const std::string retry = unique_tmp_suffix();
            tmp += L".tmp." + std::wstring(retry.begin(), retry.end());
        }
        h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, sa_ptr, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            break;
        }
        if (::GetLastError() == ERROR_FILE_EXISTS) {
            continue;
        }
        return make_unexpected(std::string("CreateFileW tmp failed: ") +
                               std::to_string(::GetLastError()));
    }
    if (h == INVALID_HANDLE_VALUE) {
        return make_unexpected(
            std::string("CreateFileW tmp failed: could not create a unique staging file"));
    }
    // WriteFile is limited to DWORD bytes per call; loop for larger inputs
    // so a >4 GiB payload (theoretical, but a real bug waiting to happen
    // if a caller ever passes one) is written in full instead of silently
    // truncated.
    const std::uint8_t* p = contents.data();
    std::size_t remaining = contents.size();
    while (remaining > 0) {
        // The extra parens around `(std::numeric_limits<DWORD>::max)`
        // suppress Windows.h's `max(a,b)` macro — without them, MSVC
        // expands the macro and fails to parse the call (CI-pedantic-fix
        // 2026-05-21).
        const DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(remaining, (std::numeric_limits<DWORD>::max)()));
        DWORD written = 0;
        if (!::WriteFile(h, p, chunk, &written, nullptr) || written != chunk) {
            const auto err = ::GetLastError();
            ::CloseHandle(h);
            ::DeleteFileW(tmp.c_str());
            return make_unexpected(std::string("WriteFile tmp failed: ") + std::to_string(err));
        }
        p += written;
        remaining -= written;
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
