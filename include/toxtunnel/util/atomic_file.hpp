#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

// ---------------------------------------------------------------------------
// AtomicFileOptions
// ---------------------------------------------------------------------------

/// Options for `atomic_write_file`. The defaults match the v0.4.0 design
/// doc: write to a per-call-unique `<path>.tmp.<pid>.<tid>.<counter>` staging
/// file, fsync the temp file, rename, and on POSIX optionally fsync the parent
/// directory for full durability. The unique suffix lets two threads in the
/// same process write the same target concurrently without clobbering each
/// other's staging file.
struct AtomicFileOptions {
    /// File permissions (POSIX); ignored on Windows.
    std::filesystem::perms mode =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
        std::filesystem::perms::group_read | std::filesystem::perms::others_read;

    /// Fsync the directory after rename. Slower but durable across power-cut
    /// on ext4/xfs/btrfs. The design doc recommends `true` for
    /// `tox_save.dat`, `false` for the bootstrap_nodes.json cache.
    bool fsync_parent_dir = true;

    /// On macOS, prefer F_FULLFSYNC over plain fsync. macOS fsync does not
    /// flush platter caches; F_FULLFSYNC does, at higher latency. Critical
    /// files (the Tox identity) should use this; convenience caches need not.
    bool use_full_fsync_macos = true;
};

// ---------------------------------------------------------------------------
// atomic_write_file
// ---------------------------------------------------------------------------

/// Write `contents` to `path` atomically: stage in a per-call-unique
/// `<path>.tmp.<pid>.<tid>.<counter>`, fsync the temp, rename over `path`,
/// optionally fsync the parent dir.
///
/// On POSIX the rename is atomic with respect to crash recovery; on Windows
/// the equivalent is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING |
/// MOVEFILE_WRITE_THROUGH`.
///
/// Returns an empty Expected on success, or an error string on failure.
/// On failure the temp file is best-effort removed; the canonical path is
/// left untouched.
[[nodiscard]] Expected<void, std::string> atomic_write_file(const std::filesystem::path& path,
                                                            std::span<const std::uint8_t> contents,
                                                            const AtomicFileOptions& options = {});

/// Convenience overload accepting a string_view.
[[nodiscard]] Expected<void, std::string> atomic_write_file(const std::filesystem::path& path,
                                                            std::string_view contents,
                                                            const AtomicFileOptions& options = {});

}  // namespace toxtunnel::util
