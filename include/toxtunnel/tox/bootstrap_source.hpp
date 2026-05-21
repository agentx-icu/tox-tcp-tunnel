#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tox {

struct BootstrapFetchError {
    std::string message;
};

class BootstrapSource {
   public:
    using Fetcher = std::function<util::Expected<std::string, BootstrapFetchError>()>;

    static constexpr std::size_t kDefaultMaxNodes = 8;
    static constexpr std::string_view kDefaultNodesUrl = "https://nodes.tox.chat/json";

    [[nodiscard]] static util::Expected<std::vector<BootstrapNode>, std::string> parse_nodes_json(
        std::string_view json, std::size_t max_nodes = kDefaultMaxNodes);

    [[nodiscard]] static util::Expected<std::vector<BootstrapNode>, std::string>
    resolve_bootstrap_nodes(const std::vector<BootstrapNode>& configured_nodes,
                            BootstrapMode bootstrap_mode, const std::filesystem::path& data_dir,
                            Fetcher fetcher = {}, std::size_t max_nodes = kDefaultMaxNodes);

    [[nodiscard]] static util::Expected<std::string, BootstrapFetchError>
    fetch_default_nodes_json();

    [[nodiscard]] static std::filesystem::path cache_file_path(
        const std::filesystem::path& data_dir);

    /// Signal any in-flight background refresh thread spawned by
    /// `resolve_bootstrap_nodes` to bail out before its next
    /// observation point. Idempotent. The application should call this
    /// from `ToxAdapter::stop` (or any other "we're shutting down"
    /// hook) so that detached refresh threads don't outlive the
    /// process's still-needed globals (H-S-6 in the 2026-05-20
    /// fix-storm review).
    static void cancel_pending_refreshes() noexcept;

    /// Re-arm the cancellation flag so a *subsequent*
    /// `resolve_bootstrap_nodes` call can spawn refresh threads again.
    /// Required because the flag is process-global: without an
    /// explicit reset, `ToxAdapter::start` after a previous `stop`
    /// would inherit a permanently-cancelled refresh path
    /// (Finding-3 user-reported, 2026-05-21). Called by
    /// `ToxAdapter::start`. Idempotent.
    static void arm_refreshes() noexcept;
};

}  // namespace toxtunnel::tox
