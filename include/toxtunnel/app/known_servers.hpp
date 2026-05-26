#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::app {

/// Connection transport last reported by toxcore for a given peer.
enum class KnownConnectionType : uint8_t {
    None,  ///< Never observed online (or last seen offline).
    Tcp,   ///< Connected via Tox TCP relay.
    Udp,   ///< Direct UDP (NAT-traversed P2P).
};

[[nodiscard]] std::string to_string(KnownConnectionType type);
[[nodiscard]] std::optional<KnownConnectionType> known_connection_type_from_string(
    std::string_view str);

/// Server-disclosed system info, populated from INFO_REPLY frames.
/// Every field is optional because the server discloses each one only when
/// its `server.disclose.*` flag is true.
struct KnownServerInfo {
    std::optional<std::string> hostname;
    std::optional<std::string> os;
    std::optional<std::string> os_version;
    std::optional<std::string> arch;
    std::optional<uint64_t> uptime_seconds;
    std::optional<std::string> toxtunnel_version;
    /// When the disclosed snapshot was received (UTC ISO-8601).
    std::optional<std::string> reported_at;

    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] bool operator==(const KnownServerInfo& other) const = default;
};

/// One entry in the client-side known-servers registry.
///
/// Persisted to `<data_dir>/known_servers.yaml`. Identity is the 76-char
/// uppercase Tox ID. `alias` is a user-friendly handle that the CLI
/// `--server-id` flag also accepts.
struct KnownServer {
    /// 76-char uppercase hex Tox ID. Required.
    std::string tox_id;
    /// Optional short handle. Unique within the registry.
    std::optional<std::string> alias;
    /// First time this client successfully connected (UTC ISO-8601).
    std::optional<std::string> first_connected_at;
    /// Most recent time this client successfully connected (UTC ISO-8601).
    std::optional<std::string> last_connected_at;
    /// Most recent transport reported by toxcore.
    KnownConnectionType last_connection_type = KnownConnectionType::None;
    /// Server-disclosed system info (populated from INFO_REPLY).
    KnownServerInfo info;
    /// User-supplied free-form notes.
    std::string notes;

    [[nodiscard]] bool operator==(const KnownServer& other) const = default;
};

/// File-backed registry of servers this client has connected to.
///
/// All operations are in-memory; call `save()` to persist. The file is loaded
/// once at construction (or by `reload()`).
///
/// **In-process thread safety**: every public method takes an internal mutex,
/// so the store is safe to call concurrently from multiple threads in the same
/// process (H-03). In the daemon, `record_connection` runs on the Tox thread
/// while `record_info` / `save` run on the INFO_REPLY inbound strand — both
/// the in-memory vector and the persist path are now serialised. The
/// mutex covers the whole `save()` (serialise + atomic write) so a concurrent
/// mutation can't tear the snapshot being written.
///
/// **Cross-process**: this store still does NOT take a file lock. The on-disk
/// file is treated as single-writer across processes. In practice that means:
/// while the toxtunnel client daemon is running, do NOT mutate the registry
/// from the CLI (`toxtunnel servers add|remove`) — the daemon's next
/// `record_connection` will overwrite your change (and vice versa). Stop the
/// daemon first (`systemctl stop toxtunnel` / `sc stop ToxTunnel` /
/// `launchctl kickstart …`) before editing.
///
/// Format on disk (YAML):
/// @code
///   servers:
///     - tox_id: "ABCDEF...76hex"
///       alias: "homelab"
///       first_connected_at: "2026-05-13T03:00:00Z"
///       last_connected_at: "2026-05-13T03:14:22Z"
///       last_connection_type: "udp"
///       info:
///         hostname: "nas-01"
///         os: "Linux"
///         arch: "aarch64"
///         reported_at: "2026-05-13T03:14:22Z"
///       notes: ""
/// @endcode
class KnownServersStore {
   public:
    /// Construct a store backed by `<data_dir>/known_servers.yaml`.
    /// If the file is absent, the in-memory store starts empty (no error).
    /// If the file exists but cannot be parsed, the constructor leaves the
    /// store empty and the parse error is reported via `last_load_error()`.
    explicit KnownServersStore(std::filesystem::path data_dir);

    /// Reload from disk, discarding any unsaved in-memory changes.
    /// Returns success/failure of the load. Missing file is treated as success
    /// with an empty registry.
    [[nodiscard]] util::Expected<void, std::string> reload();

    /// Persist the in-memory state to disk atomically (write-to-temp + rename).
    [[nodiscard]] util::Expected<void, std::string> save() const;

    // ---------------------------------------------------------------------
    // Lookup
    // ---------------------------------------------------------------------

    /// Look up by exact 76-char uppercase Tox ID. Returns nullptr if absent.
    [[nodiscard]] const KnownServer* find_by_tox_id(std::string_view tox_id) const;

    /// Look up by alias. Returns nullptr if absent.
    [[nodiscard]] const KnownServer* find_by_alias(std::string_view alias) const;

    /// Resolve a user-supplied identifier into a Tox ID:
    /// - If `id_or_alias` is exactly 76 hex chars, returns it uppercased.
    /// - Otherwise treats it as an alias and looks it up.
    /// - On no match, returns the original string back (caller will fail
    ///   validation and surface a clear error).
    [[nodiscard]] std::string resolve_tox_id(std::string_view id_or_alias) const;

    // ---------------------------------------------------------------------
    // Mutation
    // ---------------------------------------------------------------------

    /// Insert or update an entry by Tox ID. Replaces the whole record.
    /// Returns false if `entry.tox_id` is not a valid 76-char hex string,
    /// or if `entry.alias` collides with an existing entry's alias.
    bool upsert(const KnownServer& entry);

    /// Convenience: record/refresh the connection metadata only. Inserts a
    /// minimal entry if the Tox ID is not yet known. Updates `first_connected_at`
    /// only when missing.
    /// Returns true on success, false if `tox_id` is invalid.
    bool record_connection(std::string_view tox_id, KnownConnectionType type);

    /// Update the disclosed system info for a server. Inserts a minimal entry
    /// if the Tox ID is not yet known.
    /// Returns true on success, false if `tox_id` is invalid.
    bool record_info(std::string_view tox_id, const KnownServerInfo& info);

    /// Remove by alias OR Tox ID (resolved via `resolve_tox_id`).
    /// Returns true if a record was removed.
    bool remove(std::string_view alias_or_tox_id);

    // ---------------------------------------------------------------------
    // Inspection
    // ---------------------------------------------------------------------

    /// All known servers, sorted by alias (entries without alias sort last,
    /// then by tox_id).
    [[nodiscard]] std::vector<KnownServer> entries() const;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    /// Path of the backing file.
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

    /// If `reload()` (or the constructor's initial load) failed, returns the
    /// error string; otherwise std::nullopt.
    [[nodiscard]] const std::optional<std::string>& last_load_error() const noexcept {
        return last_load_error_;
    }

   private:
    /// Guards `servers_`, `last_load_error_`, and `save()`. Acquired at the
    /// public-method boundary; the `*_locked` helpers below assume it is held
    /// to avoid recursive locking (H-03).
    mutable std::mutex mu_;
    std::filesystem::path data_dir_;
    std::filesystem::path path_;
    std::vector<KnownServer> servers_;
    std::optional<std::string> last_load_error_;

    // Unlocked helpers — caller must hold `mu_`.
    [[nodiscard]] util::Expected<void, std::string> load_from_disk_locked();
    [[nodiscard]] util::Expected<void, std::string> save_locked() const;
    [[nodiscard]] const KnownServer* find_by_alias_locked(std::string_view alias) const;
    [[nodiscard]] std::string resolve_tox_id_locked(std::string_view id_or_alias) const;

    [[nodiscard]] static bool is_valid_tox_id(std::string_view candidate);
    [[nodiscard]] static std::string to_upper_hex(std::string_view input);
};

/// Return the current UTC time as an ISO-8601 string ("2026-05-13T03:14:22Z").
/// Uses second resolution.
[[nodiscard]] std::string iso8601_utc_now();

}  // namespace toxtunnel::app
