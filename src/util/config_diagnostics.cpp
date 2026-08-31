#include "toxtunnel/util/config_diagnostics.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <initializer_list>
#include <set>
#include <string>

namespace toxtunnel::util {
namespace {

using KeySet = std::set<std::string, std::less<>>;

/// The keys each block understands. Kept next to the parser's shape rather than
/// derived from it: the parser reads keys ad hoc (`if (node["x"])`), so there is
/// nothing to introspect. A key missing from this table produces a false
/// warning, so when in doubt the table is deliberately generous.
const KeySet& logging_keys() {
    static const KeySet k{"level", "file"};
    return k;
}
const KeySet& service_keys() {
    static const KeySet k{"auto_start", "allow_client_daemon"};
    return k;
}
const KeySet& metrics_keys() {
    static const KeySet k{"enabled", "listen", "path"};
    return k;
}
const KeySet& inspect_keys() {
    static const KeySet k{"enabled"};
    return k;
}
const KeySet& bootstrap_node_keys() {
    static const KeySet k{"address", "port", "public_key"};
    return k;
}
const KeySet& tox_keys() {
    static const KeySet k{"udp_enabled", "ipv6_enabled", "tcp_port", "bootstrap_mode",
                          "bootstrap_nodes"};
    return k;
}
const KeySet& resume_keys() {
    static const KeySet k{"enabled", "max_age_seconds", "on_gap", "state_path"};
    return k;
}
const KeySet& tunnel_keys() {
    static const KeySet k{"coalesce_max_delay_us",
                          "coalesce_max_bytes",
                          "coalesce_mode",
                          "idle_timeout_seconds",
                          "reaper_tick_seconds",
                          "keepalive_interval_seconds",
                          "half_close_timeout_seconds",
                          "resume"};
    return k;
}
const KeySet& flow_control_keys() {
    static const KeySet k{"mode", "send_window_min_bytes", "send_window_max_bytes",
                          "safety_factor_x100", "fixed_window_bytes"};
    return k;
}
const KeySet& watchdog_keys() {
    static const KeySet k{"enabled", "deadline_seconds", "systemd_notify"};
    return k;
}
const KeySet& disclose_keys() {
    static const KeySet k{"hostname", "os", "os_version", "arch", "uptime", "toxtunnel_version"};
    return k;
}
const KeySet& server_keys() {
    // tcp_port / udp_enabled / bootstrap_nodes are accepted here for the legacy
    // pre-`tox:` layout the parser still supports.
    static const KeySet k{"rules_file", "disclose", "tcp_port", "udp_enabled", "bootstrap_nodes"};
    return k;
}
const KeySet& failover_keys() {
    static const KeySet k{"timeout_seconds", "prefer_primary_grace_seconds"};
    return k;
}
const KeySet& socks5_keys() {
    static const KeySet k{"enabled", "listen"};
    return k;
}
const KeySet& pipe_keys() {
    static const KeySet k{"remote_host", "remote_port"};
    return k;
}
const KeySet& forward_keys() {
    static const KeySet k{"local_port", "remote_host", "remote_port", "local_address"};
    return k;
}
const KeySet& client_keys() {
    static const KeySet k{"server_id", "fallback_server_ids", "forwards", "failover", "socks5",
                          "pipe"};
    return k;
}
const KeySet& root_keys() {
    // Canonical blocks plus every key the parser still honours at the root for
    // the legacy flat layout (see `convert<Config>::decode`, which falls back to
    // `node` itself when `server:` / `client:` are absent).
    static const KeySet k{"mode", "data_dir", "logging", "service", "metrics", "inspect", "tox",
                          "tunnel", "flow_control", "watchdog", "server", "client",
                          // legacy flat keys:
                          "rules_file", "disclose", "tcp_port", "udp_enabled", "bootstrap_nodes",
                          "server_id", "fallback_server_ids", "forwards", "failover", "socks5",
                          "pipe"};
    return k;
}

std::string join(std::string_view prefix, const std::string& key) {
    if (prefix.empty()) {
        return key;
    }
    return std::string(prefix) + "." + key;
}

void walk_map(const YAML::Node& node, std::string_view path, const KeySet& allowed,
              std::vector<UnknownConfigKey>& out);

/// Recurse into a child node using the sub-block table that applies to it.
void walk_child(const YAML::Node& child, const std::string& child_path, const std::string& key,
                std::vector<UnknownConfigKey>& out) {
    if (key == "logging" && child.IsMap()) {
        walk_map(child, child_path, logging_keys(), out);
    } else if (key == "service" && child.IsMap()) {
        walk_map(child, child_path, service_keys(), out);
    } else if (key == "metrics" && child.IsMap()) {
        walk_map(child, child_path, metrics_keys(), out);
    } else if (key == "inspect" && child.IsMap()) {
        walk_map(child, child_path, inspect_keys(), out);
    } else if (key == "tox" && child.IsMap()) {
        walk_map(child, child_path, tox_keys(), out);
    } else if (key == "tunnel" && child.IsMap()) {
        walk_map(child, child_path, tunnel_keys(), out);
    } else if (key == "resume" && child.IsMap()) {
        walk_map(child, child_path, resume_keys(), out);
    } else if (key == "flow_control" && child.IsMap()) {
        walk_map(child, child_path, flow_control_keys(), out);
    } else if (key == "watchdog" && child.IsMap()) {
        walk_map(child, child_path, watchdog_keys(), out);
    } else if (key == "server" && child.IsMap()) {
        walk_map(child, child_path, server_keys(), out);
    } else if (key == "client" && child.IsMap()) {
        walk_map(child, child_path, client_keys(), out);
    } else if (key == "disclose" && child.IsMap()) {
        // `disclose: true` is also valid; only a map has keys to check.
        walk_map(child, child_path, disclose_keys(), out);
    } else if (key == "failover" && child.IsMap()) {
        walk_map(child, child_path, failover_keys(), out);
    } else if (key == "socks5" && child.IsMap()) {
        walk_map(child, child_path, socks5_keys(), out);
    } else if (key == "pipe" && child.IsMap()) {
        walk_map(child, child_path, pipe_keys(), out);
    } else if (key == "forwards" && child.IsSequence()) {
        std::size_t i = 0;
        for (const auto& item : child) {
            if (item.IsMap()) {
                walk_map(item, child_path + "[" + std::to_string(i) + "]", forward_keys(), out);
            }
            ++i;
        }
    } else if (key == "bootstrap_nodes" && child.IsSequence()) {
        std::size_t i = 0;
        for (const auto& item : child) {
            if (item.IsMap()) {
                walk_map(item, child_path + "[" + std::to_string(i) + "]", bootstrap_node_keys(),
                         out);
            }
            ++i;
        }
    }
}

void walk_map(const YAML::Node& node, std::string_view path, const KeySet& allowed,
              std::vector<UnknownConfigKey>& out) {
    if (!node.IsMap()) {
        return;
    }
    for (const auto& entry : node) {
        std::string key;
        try {
            key = entry.first.as<std::string>();
        } catch (const YAML::Exception&) {
            continue;  // non-scalar key: not something the parser reads either
        }
        const std::string child_path = join(path, key);
        if (allowed.find(key) == allowed.end()) {
            out.push_back(UnknownConfigKey{child_path});
            continue;  // do not descend into a block we do not understand
        }
        walk_child(entry.second, child_path, key, out);
    }
}

std::vector<UnknownConfigKey> scan(const YAML::Node& root) {
    std::vector<UnknownConfigKey> out;
    walk_map(root, "", root_keys(), out);
    return out;
}

}  // namespace

std::vector<UnknownConfigKey> find_unknown_config_keys(const std::filesystem::path& filepath) {
    try {
        return scan(YAML::LoadFile(filepath.string()));
    } catch (const YAML::Exception&) {
        return {};
    }
}

std::vector<UnknownConfigKey> find_unknown_config_keys_in_string(std::string_view yaml_content) {
    try {
        return scan(YAML::Load(std::string(yaml_content)));
    } catch (const YAML::Exception&) {
        return {};
    }
}

}  // namespace toxtunnel::util
