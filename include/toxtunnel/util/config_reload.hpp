#pragma once

// Minimal forward stub for the SIGHUP config-reload feature owned by a sibling
// agent. The full implementation will land alongside #9 and override this
// file. We provide just enough to satisfy `tunnel_server.cpp` and
// `tunnel_client.cpp`'s call sites so the rest of the library can build.

#include <string>
#include <vector>

#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

/// Verify that `next` only differs from `current` in fields the daemon
/// supports hot-reloading. The real implementation rejects changes to
/// non-reloadable fields with a descriptive error; this stub accepts any
/// `next` so the build is unblocked until #9 lands.
[[nodiscard]] inline Expected<void, std::string> check_reloadable(const Config& /*current*/,
                                                                  const Config& /*next*/) {
    return {};
}

/// Sets of ForwardRules added vs removed between a current and new config.
struct ForwardDiff {
    std::vector<ForwardRule> added;
    std::vector<ForwardRule> removed;

    [[nodiscard]] bool empty() const noexcept { return added.empty() && removed.empty(); }
};

/// Compute (added, removed) sets between two ordered ForwardRule lists.
/// Stub implementation: linear scan with std::find. Will be replaced by #9
/// with an order-preserving diff that matches the real reload semantics.
[[nodiscard]] inline ForwardDiff diff_forwards(const std::vector<ForwardRule>& current,
                                               const std::vector<ForwardRule>& next) {
    ForwardDiff out;
    for (const auto& rule : next) {
        bool found = false;
        for (const auto& c : current) {
            if (c == rule) {
                found = true;
                break;
            }
        }
        if (!found)
            out.added.push_back(rule);
    }
    for (const auto& rule : current) {
        bool found = false;
        for (const auto& n : next) {
            if (n == rule) {
                found = true;
                break;
            }
        }
        if (!found)
            out.removed.push_back(rule);
    }
    return out;
}

}  // namespace toxtunnel::util
