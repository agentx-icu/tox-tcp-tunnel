#include "toxtunnel/util/config_reload.hpp"

#include <algorithm>
#include <sstream>
#include <string>

namespace toxtunnel::util {

namespace {

/// Build a clear error message for a non-reloadable field change. Including
/// the field name lets the operator immediately tell which line in the YAML
/// is rejecting the reload and act on it.
[[nodiscard]] std::string field_rejection(std::string_view field_name) {
    std::ostringstream oss;
    oss << "config reload rejected: field '" << field_name
        << "' requires a restart (not in the reloadable subset)";
    return oss.str();
}

}  // namespace

Expected<void, std::string> check_reloadable(const Config& current, const Config& next) {
    // Top-level mode + paths are immutable for the life of the process.
    if (current.mode != next.mode) {
        return make_unexpected(field_rejection("mode"));
    }
    if (current.data_dir != next.data_dir) {
        return make_unexpected(field_rejection("data_dir"));
    }

    // Logging file path needs a re-open we don't currently support; only the
    // level is reloadable. (level itself is checked at the apply step, not
    // here — we accept any level change.)
    if (current.logging.file != next.logging.file) {
        return make_unexpected(field_rejection("logging.file"));
    }

    if (!(current.service == next.service)) {
        return make_unexpected(field_rejection("service"));
    }
    if (!(current.metrics == next.metrics)) {
        return make_unexpected(field_rejection("metrics"));
    }
    if (!(current.inspect == next.inspect)) {
        return make_unexpected(field_rejection("inspect"));
    }
    if (!(current.tunnel == next.tunnel)) {
        return make_unexpected(field_rejection("tunnel"));
    }
    if (!(current.flow_control == next.flow_control)) {
        return make_unexpected(field_rejection("flow_control"));
    }

    // Server-side: only `rules_file` is reloadable (path can change; the
    // referenced content is re-read). disclose/tcp_port/udp_enabled/bootstrap
    // all require a Tox restart. We check these *before* the generic
    // `effective_tox` comparison so we can surface a more specific error.
    if (current.server.has_value() != next.server.has_value()) {
        return make_unexpected(field_rejection("server"));
    }
    if (current.server.has_value() && next.server.has_value()) {
        const auto& a = *current.server;
        const auto& b = *next.server;
        if (a.tcp_port != b.tcp_port) {
            return make_unexpected(field_rejection("server.tcp_port"));
        }
        if (a.udp_enabled != b.udp_enabled) {
            return make_unexpected(field_rejection("server.udp_enabled"));
        }
        if (a.bootstrap_nodes != b.bootstrap_nodes) {
            return make_unexpected(field_rejection("server.bootstrap_nodes"));
        }
        if (!(a.disclose == b.disclose)) {
            return make_unexpected(field_rejection("server.disclose"));
        }
        // rules_file path itself is allowed to change.
    }

    // Tox network config (compare effective_tox so YAML legacy fallbacks
    // don't trigger false positives). This catches changes to top-level
    // `tox.*` that the per-mode checks above don't see.
    if (current.effective_tox_config() != next.effective_tox_config()) {
        return make_unexpected(field_rejection("tox"));
    }

    // Client-side: only `forwards` is reloadable. server_id and pipe_target
    // both require a restart (changing the peer mid-flight would orphan all
    // open tunnels, and pipe_target swaps a wholly different IO model).
    if (current.client.has_value() != next.client.has_value()) {
        return make_unexpected(field_rejection("client"));
    }
    if (current.client.has_value() && next.client.has_value()) {
        const auto& a = *current.client;
        const auto& b = *next.client;
        if (a.server_id != b.server_id) {
            return make_unexpected(field_rejection("client.server_id"));
        }
        if (a.pipe_target != b.pipe_target) {
            return make_unexpected(field_rejection("client.pipe_target"));
        }
        if (!(a.socks5 == b.socks5)) {
            return make_unexpected(field_rejection("client.socks5"));
        }
        // forwards is the reloadable bit.
    }

    return {};
}

ForwardDiff diff_forwards(const std::vector<ForwardRule>& current,
                          const std::vector<ForwardRule>& next) {
    ForwardDiff out;
    out.added.reserve(next.size());
    out.removed.reserve(current.size());

    // O(n*m) is fine: forward lists are typically a handful of rules, and a
    // linear scan keeps the implementation order-stable (and the rule type
    // doesn't have a natural hash key).
    for (const auto& rule : next) {
        if (std::find(current.begin(), current.end(), rule) == current.end()) {
            out.added.push_back(rule);
        }
    }
    for (const auto& rule : current) {
        if (std::find(next.begin(), next.end(), rule) == next.end()) {
            out.removed.push_back(rule);
        }
    }
    return out;
}

}  // namespace toxtunnel::util
