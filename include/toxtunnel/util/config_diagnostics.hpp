#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace toxtunnel::util {

/// A key present in the YAML that no version of the parser reads.
struct UnknownConfigKey {
    /// Dotted path as written, e.g. "tox.local_discovery_enabled" or
    /// "client.forwards[0].localport".
    std::string path;
};

/// Walk a parsed config file and report keys the daemon will silently ignore.
///
/// Why this exists: the parser is a series of `if (node["x"])` lookups, so a
/// key it does not know about is not an error — it simply never gets read. In
/// practice that has meant operators running for months with settings that do
/// nothing (`tox.local_discovery_enabled` is a real example: it looks
/// plausible, appears in several hand-written configs, and is not a config key
/// at all — LAN discovery follows `tox.bootstrap_mode: lan`). Every typo
/// (`idle_timeout` for `idle_timeout_seconds`, a block indented one level too
/// deep) fails the same silent way.
///
/// This is deliberately a **warning** pass, not part of validation: rejecting
/// unknown keys would stop an older binary from reading a newer config, and
/// would turn a harmless typo into a daemon that refuses to start. Callers log
/// what comes back; `toxtunnel config check --strict` is the place to make it
/// fatal.
///
/// Returns an empty vector for a file that cannot be read or parsed — surfacing
/// that is the loader's job, not this pass's.
[[nodiscard]] std::vector<UnknownConfigKey> find_unknown_config_keys(
    const std::filesystem::path& filepath);

/// Same, for YAML already in memory.
[[nodiscard]] std::vector<UnknownConfigKey> find_unknown_config_keys_in_string(
    std::string_view yaml_content);

}  // namespace toxtunnel::util
