#include "toxtunnel/util/pid_file.hpp"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <set>
#include <string>
#include <system_error>

#include "toxtunnel/util/atomic_file.hpp"

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <libproc.h>
#include <unistd.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace toxtunnel::util {

namespace {

/// Data dirs claimed by *this* process.
///
/// The kernel lock below is per-process, not per-file-description: POSIX
/// fcntl(F_SETLK) succeeds when the same process locks the same file twice, so
/// it cannot catch a second daemon inside one process (an embedding host, or a
/// test). Tracking claims in-process makes the guard mean the same thing
/// everywhere: one holder per data_dir, full stop.
std::mutex& claimed_dirs_mutex() {
    static std::mutex m;
    return m;
}

std::set<std::string>& claimed_dirs() {
    static std::set<std::string> dirs;
    return dirs;
}

/// Best-effort canonical form so "./d" and "/abs/d" are recognised as one dir.
std::string claim_key(const std::filesystem::path& data_dir) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(data_dir, ec);
    return ec ? data_dir.string() : canonical.string();
}

long current_pid() {
#if defined(_WIN32)
    return static_cast<long>(GetCurrentProcessId());
#else
    return static_cast<long>(::getpid());
#endif
}

}  // namespace

Expected<void, std::string> write_pid_file(const std::filesystem::path& data_dir) {
    if (data_dir.empty()) {
        return unexpected(std::string("data_dir is empty"));
    }
    std::error_code ec;
    std::filesystem::create_directories(data_dir, ec);
    if (ec) {
        return unexpected("cannot create " + data_dir.string() + ": " + ec.message());
    }
    const auto path = data_dir / kPidFileName;
    // Staged temp + rename rather than truncate-in-place: a concurrent
    // `toxtunnel inspect` / `toxtunnel reload` must never observe a truncated
    // (empty / half-written) pid file while a daemon is starting.
    AtomicFileOptions options;
    options.fsync_parent_dir = false;  // a pid file lost to a crash is harmless
    options.use_full_fsync_macos = false;
    auto written = atomic_write_file(path, std::to_string(current_pid()) + "\n", options);
    if (!written) {
        return unexpected(written.error());
    }
    return {};
}

std::optional<long> read_pid_file(const std::filesystem::path& data_dir) {
    if (data_dir.empty()) {
        return std::nullopt;
    }
    std::ifstream in(data_dir / kPidFileName);
    if (!in) {
        return std::nullopt;
    }
    // Strict: the file holds one positive integer and nothing else. `123abc`
    // and `123 456` are corruption, not a pid — accepting the leading digits
    // would hand a signal to whatever process happens to own that number.
    std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto first = contents.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return std::nullopt;
    }
    const auto last = contents.find_last_not_of(" \t\r\n");
    const std::string trimmed = contents.substr(first, last - first + 1);
    if (trimmed.empty() || trimmed.find_first_not_of("0123456789") != std::string::npos) {
        return std::nullopt;
    }
    long pid = 0;
    try {
        pid = std::stol(trimmed);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (pid <= 0) {
        return std::nullopt;
    }
    return pid;
}

void remove_pid_file(const std::filesystem::path& data_dir) {
    // Best-effort: read-then-unlink is not atomic, so a second daemon that took
    // over the same data_dir between these two calls could lose its freshly
    // written pid file. Two daemons sharing a data_dir is already a
    // misconfiguration (one Tox identity, one inspect socket); this check
    // exists for the ordinary case — a restart whose old process exits after
    // the new one has written its pid.
    const auto recorded = read_pid_file(data_dir);
    if (!recorded.has_value() || *recorded != current_pid()) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove(data_dir / kPidFileName, ec);
}

std::optional<bool> pid_is_toxtunnel(long pid) {
    if (pid <= 0) {
        return false;
    }
#if defined(__linux__)
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    if (!comm) {
        return false;  // no such process (or /proc unavailable — treat as gone)
    }
    std::string name;
    std::getline(comm, name);
    return name.rfind("toxtunnel", 0) == 0;
#elif defined(__APPLE__)
    char buf[PROC_PIDPATHINFO_MAXSIZE] = {};
    const int n = proc_pidpath(static_cast<int>(pid), buf, sizeof(buf));
    if (n <= 0) {
        return false;
    }
    const std::string exe(buf, static_cast<std::size_t>(n));
    return exe.find("toxtunnel") != std::string::npos;
#else
    return std::nullopt;
#endif
}

PidFileGuard::PidFileGuard(std::filesystem::path data_dir) : data_dir_(std::move(data_dir)) {
    if (data_dir_.empty()) {
        error_ = "data_dir is empty";
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        error_ = "cannot create " + data_dir_.string() + ": " + ec.message();
        return;
    }

    // In-process claim first (see claimed_dirs()).
    claim_key_ = claim_key(data_dir_);
    {
        std::lock_guard<std::mutex> lock(claimed_dirs_mutex());
        if (!claimed_dirs().insert(claim_key_).second) {
            status_ = Status::AlreadyLocked;
            holder_pid_ = current_pid();
            error_ = "this process already owns " + data_dir_.string();
            claim_key_.clear();  // we did not insert it; must not erase it later
            return;
        }
    }

    const auto lock_path_str = (data_dir_ / kLockFileName).string();

#if defined(_WIN32)
    // Exclusive open with no sharing: a second daemon gets ERROR_SHARING_VIOLATION.
    // FILE_FLAG_DELETE_ON_CLOSE keeps the directory tidy without a separate unlink.
    HANDLE handle = CreateFileA(lock_path_str.c_str(), GENERIC_READ | GENERIC_WRITE,
                                /*dwShareMode=*/0, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        // Only a sharing/lock violation means "someone else holds it".
        // ERROR_ACCESS_DENIED is usually an ACL or delete-pending problem, and
        // reporting it as a live conflict would both mislead and bypass the
        // TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR escape hatch (which only applies to
        // non-conflict failures).
        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
            status_ = Status::AlreadyLocked;
            holder_pid_ = read_pid_file(data_dir_).value_or(0);
            error_ = "another toxtunnel already owns " + data_dir_.string();
        } else if (err == ERROR_ACCESS_DENIED) {
            error_ = "cannot open " + lock_path_str +
                     " (access denied — check the ACL on the data directory, or whether a "
                     "previous lock file is pending deletion)";
        } else {
            error_ = "cannot open " + lock_path_str + " (error " + std::to_string(err) + ")";
        }
        release_claim();
        return;
    }
    lock_handle_ = handle;
#else
    const int fd = ::open(lock_path_str.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        error_ = "cannot open " + lock_path_str + ": " + std::strerror(errno);
        release_claim();
        return;
    }
    // Whole-file write lock. fcntl (not flock) because it is the variant with
    // defined semantics on the network filesystems people occasionally point a
    // data_dir at, and because it is released automatically when the process
    // dies however it dies.
    struct flock fl{};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (::fcntl(fd, F_SETLK, &fl) != 0) {
        const int err = errno;
        ::close(fd);
        if (err == EACCES || err == EAGAIN) {
            status_ = Status::AlreadyLocked;
            holder_pid_ = read_pid_file(data_dir_).value_or(0);
            error_ = "another toxtunnel already owns " + data_dir_.string();
        } else {
            error_ = "cannot lock " + lock_path_str + ": " + std::strerror(err);
        }
        release_claim();
        return;
    }
    lock_fd_ = fd;
#endif

    // Lock held: publish the pid. A stale pid file from a killed predecessor is
    // simply overwritten — we know it is stale because we just took the lock.
    auto result = write_pid_file(data_dir_);
    if (!result.has_value()) {
        error_ = result.error();
        release_lock();
        release_claim();
        return;
    }
    status_ = Status::Acquired;
}

void PidFileGuard::release_claim() noexcept {
    if (claim_key_.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(claimed_dirs_mutex());
    claimed_dirs().erase(claim_key_);
    claim_key_.clear();
}

void PidFileGuard::release_lock() noexcept {
#if defined(_WIN32)
    if (lock_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(lock_handle_));
        lock_handle_ = nullptr;
    }
#else
    if (lock_fd_ >= 0) {
        // Closing the fd drops the fcntl lock. Deliberately do NOT unlink the
        // lock file: another daemon may already have it open, and removing the
        // name while it holds that inode would let a third process create a
        // fresh file and lock it — two daemons, both "holding the lock". An
        // empty toxtunnel.lock left in the data dir costs nothing.
        ::close(lock_fd_);
        lock_fd_ = -1;
    }
#endif
}

PidFileGuard::~PidFileGuard() {
    if (status_ == Status::Acquired) {
        remove_pid_file(data_dir_);
    }
    release_lock();
    release_claim();
}

}  // namespace toxtunnel::util
