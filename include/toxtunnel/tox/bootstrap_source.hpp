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
};

}  // namespace toxtunnel::tox
