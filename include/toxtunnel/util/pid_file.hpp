#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

/// File name the daemon publishes under `data_dir` so the `inspect` / `reload`
/// subcommands can find the running process. POSIX `inspect` talks to the
/// Unix socket directly and only `reload` needs the pid; on Windows both the
/// inspect and reload named pipes are per-pid, so the file is the only
/// discovery mechanism that does not require the operator to look it up.
inline constexpr const char* kPidFileName = "toxtunnel.pid";

/// Write the current process id to `<data_dir>/toxtunnel.pid`, overwriting a
/// stale file left behind by a previous (crashed) instance.
Expected<void, std::string> write_pid_file(const std::filesystem::path& data_dir);

/// Remove `<data_dir>/toxtunnel.pid` when it still records *our* pid, so a
/// restart that has already written a newer pid keeps it. Best-effort only:
/// the read and the unlink are not atomic (see the note in the .cpp).
void remove_pid_file(const std::filesystem::path& data_dir);

/// Read the pid recorded in `<data_dir>/toxtunnel.pid`. nullopt when the file is
/// missing, empty, or does not parse as a positive integer.
std::optional<long> read_pid_file(const std::filesystem::path& data_dir);

/// Best-effort check that `pid` currently names a live toxtunnel process, used
/// to keep `toxtunnel reload` from signalling an unrelated process after a pid
/// file went stale. It narrows, but cannot close, the window — the pid could be
/// recycled between this check and the signal. Returns nullopt on platforms
/// with no cheap way to inspect a process name; the caller should then rely on
/// the signal's own error handling.
std::optional<bool> pid_is_toxtunnel(long pid);

/// File name of the exclusive data-dir lock, held for the daemon's lifetime.
inline constexpr const char* kLockFileName = "toxtunnel.lock";

/// Why a lock and not just a pid file: two daemons sharing one `data_dir` share
/// one Tox identity (`tox_save.dat`), one inspect socket and one
/// `known_servers.yaml`. Nothing used to stop that, and
/// the symptoms — an identity that "randomly" loses friends, an inspect socket
/// that answers for the wrong process — are miserable to diagnose. A kernel
/// lock also releases automatically when a process dies, which is what makes a
/// pid file left behind by `kill -9` self-healing instead of permanently
/// confusing.
///
/// Not a general-purpose mutex: `data_dir` on a network filesystem (NFS/CIFS)
/// has unreliable lock semantics, which is one more reason the docs call a
/// local data_dir a requirement.
///
/// RAII holder: takes the data-dir lock and writes the pid file on
/// construction; on destruction it removes the pid file and releases the lock.
///
/// On POSIX the lock file is deliberately left in place — unlinking it would
/// let a third process create a fresh inode and "acquire" a lock nobody else
/// can see. Windows has no such hazard (the handle itself is the exclusion), so
/// there the file is opened FILE_FLAG_DELETE_ON_CLOSE and disappears with the
/// process.
class PidFileGuard {
   public:
    /// Outcome of trying to take the data dir.
    enum class Status {
        Acquired,       ///< lock held, pid file written
        AlreadyLocked,  ///< another live daemon owns this data_dir
        Failed,         ///< could not lock or write for some other reason
    };

    explicit PidFileGuard(std::filesystem::path data_dir);
    ~PidFileGuard();

    PidFileGuard(const PidFileGuard&) = delete;
    PidFileGuard& operator=(const PidFileGuard&) = delete;

    [[nodiscard]] bool active() const noexcept { return status_ == Status::Acquired; }
    [[nodiscard]] Status status() const noexcept { return status_; }

    /// True when the data_dir is already owned by another running daemon. The
    /// caller must NOT start: it would corrupt shared state.
    [[nodiscard]] bool conflicted() const noexcept { return status_ == Status::AlreadyLocked; }

    /// The pid recorded by the daemon that holds the lock (0 when unknown).
    [[nodiscard]] long holder_pid() const noexcept { return holder_pid_; }

    [[nodiscard]] const std::string& error() const noexcept { return error_; }
    [[nodiscard]] std::filesystem::path path() const { return data_dir_ / kPidFileName; }
    [[nodiscard]] std::filesystem::path lock_path() const { return data_dir_ / kLockFileName; }

   private:
    void release_lock() noexcept;
    void release_claim() noexcept;

    std::filesystem::path data_dir_;
    /// Key under which this guard registered the data dir in-process; empty
    /// when we hold no claim.
    std::string claim_key_;
    Status status_ = Status::Failed;
    long holder_pid_ = 0;
    std::string error_;
#if defined(_WIN32)
    void* lock_handle_ = nullptr;  // HANDLE, kept void* to keep windows.h out of this header
#else
    int lock_fd_ = -1;
#endif
};

}  // namespace toxtunnel::util
