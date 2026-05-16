#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::app {

// ---------------------------------------------------------------------------
// TunnelResumeEntry / TunnelResumeStore
// ---------------------------------------------------------------------------

/// One persisted resume entry. Mirrors the design-doc YAML schema.
struct TunnelResumeEntry {
    std::uint16_t tunnel_id = 0;
    std::string target_host;
    std::uint16_t target_port = 0;
    std::uint64_t last_local_recv_offset = 0;
    std::uint64_t last_local_send_offset = 0;
    std::uint16_t local_listener_port = 0;
    std::int64_t saved_at_ns = 0;

    bool operator==(const TunnelResumeEntry& other) const = default;
};

/// Persistence wrapper around `<data_dir>/tunnel_resume_state.yaml`. Uses
/// the v0.4 atomic-write helper. Schema-versioned; entries older than the
/// configured `max_age_seconds` are dropped on load.
///
/// Thread safety: all public methods are safe to call from any thread.
class TunnelResumeStore {
   public:
    /// Construct with a path (defaults to `<data_dir>/tunnel_resume_state.yaml`).
    /// Use `set_max_age_seconds()` to override the staleness ceiling.
    TunnelResumeStore() = default;

    /// Set the on-disk path. Empty disables persistence (in-memory only).
    void set_path(const std::filesystem::path& path);

    /// Set the on-load freshness ceiling. Entries with `saved_at_ns` older
    /// than now() - max_age are discarded during `load()`.
    void set_max_age_seconds(std::uint32_t seconds) { max_age_seconds_ = seconds; }

    /// Server tox_id this store is bound to. Used to validate against
    /// reconnects: if the active server changes, the saved entries are
    /// discarded.
    void set_server_tox_id(std::string id);

    /// Load from disk. Missing file is fine (returns empty Expected with
    /// no entries). Parse failures surface as Expected error.
    [[nodiscard]] util::Expected<void, std::string> load();

    /// Persist the current entries via `util::atomic_write_file`. Idempotent.
    [[nodiscard]] util::Expected<void, std::string> save() const;

    /// Replace the entry for the given tunnel_id, or insert a new one.
    void upsert(const TunnelResumeEntry& entry);

    /// Remove the entry for the given tunnel_id.
    void erase(std::uint16_t tunnel_id);

    /// Snapshot the current entries.
    [[nodiscard]] std::vector<TunnelResumeEntry> entries() const;

    /// Look up a single entry. Returns nullopt if not found.
    [[nodiscard]] std::optional<TunnelResumeEntry> find(std::uint16_t tunnel_id) const;

    /// Drop every entry whose `saved_at_ns` is older than `max_age_seconds`.
    /// Returns the number of dropped entries. Called automatically by load().
    std::size_t prune_stale();

   private:
    mutable std::mutex mu_;
    std::filesystem::path path_;
    std::string server_tox_id_;
    std::uint32_t max_age_seconds_ = 300;
    std::vector<TunnelResumeEntry> entries_;
};

}  // namespace toxtunnel::app
