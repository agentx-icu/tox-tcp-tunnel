#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace toxtunnel {

struct ServerInfoDisclose;  // forward-declared from util/config.hpp

namespace util {

/// Snapshot of server-side system info. Each field is optional because the
/// caller (server) gates each one independently via ServerInfoDisclose.
struct SystemInfoSnapshot {
    std::optional<std::string> hostname;
    std::optional<std::string> os;
    std::optional<std::string> os_version;
    std::optional<std::string> arch;
    std::optional<uint64_t> uptime_seconds;
    std::optional<std::string> toxtunnel_version;
};

/// Gather only the fields that `policy` explicitly opts into.
///
/// Each field defaults to "do not collect" — the caller (TunnelServer) is
/// responsible for setting `policy.<field>` to true based on
/// `server.disclose.*` in the YAML config. This keeps the gather function
/// itself unaware of any opt-out / opt-in defaults.
[[nodiscard]] SystemInfoSnapshot gather_system_info(const ServerInfoDisclose& policy);

/// Serialize a snapshot to YAML bytes for an INFO_REPLY payload.
[[nodiscard]] std::string snapshot_to_yaml(const SystemInfoSnapshot& snapshot);

/// Parse YAML bytes from an INFO_REPLY payload back into a snapshot.
/// Returns an empty snapshot on parse failure (caller can detect via all
/// fields being nullopt).
[[nodiscard]] SystemInfoSnapshot snapshot_from_yaml(std::string_view yaml);

}  // namespace util
}  // namespace toxtunnel
