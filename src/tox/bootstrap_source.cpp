#include "toxtunnel/tox/bootstrap_source.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include "toxtunnel/util/atomic_file.hpp"

namespace toxtunnel::tox {
namespace {

constexpr const char* kCacheFileName = "bootstrap_nodes.json";

std::string trim_trailing_whitespace(std::string value) {
    while (!value.empty()) {
        const char ch = value.back();
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t') {
            value.pop_back();
            continue;
        }
        break;
    }
    return value;
}

util::Expected<std::vector<BootstrapNode>, std::string> load_cached_nodes(
    const std::filesystem::path& cache_path, std::size_t max_nodes) {
    if (!std::filesystem::exists(cache_path)) {
        return util::unexpected(std::string("bootstrap cache file not found"));
    }

    std::ifstream input(cache_path);
    if (!input) {
        return util::unexpected(std::string("failed to open bootstrap cache"));
    }

    std::stringstream buffer;
    buffer << input.rdbuf();
    return BootstrapSource::parse_nodes_json(buffer.str(), max_nodes);
}

void write_cache(const std::filesystem::path& cache_path, std::string_view json) {
    std::error_code ec;
    std::filesystem::create_directories(cache_path.parent_path(), ec);
    if (ec) {
        return;
    }

    // Bootstrap cache is best-effort recovery: a corrupted file from a
    // mid-write crash would leave the daemon with no DHT nodes on the next
    // boot. atomic_write_file removes that failure mode. Parent-dir fsync
    // off because the cache is not security-critical.
    util::AtomicFileOptions opts{};
    opts.fsync_parent_dir = false;
    opts.use_full_fsync_macos = false;
    (void)util::atomic_write_file(cache_path, json, opts);
}

}  // namespace

util::Expected<std::vector<BootstrapNode>, std::string> BootstrapSource::parse_nodes_json(
    std::string_view json, std::size_t max_nodes) {
    YAML::Node root;
    try {
        root = YAML::Load(std::string(json));
    } catch (const std::exception& ex) {
        return util::unexpected(std::string("failed to parse nodes JSON: ") + ex.what());
    }

    YAML::Node nodes_node = root;
    if (root.IsMap() && root["nodes"]) {
        nodes_node = root["nodes"];
    }

    if (!nodes_node.IsSequence()) {
        return util::unexpected(std::string("nodes JSON root must contain a nodes array"));
    }

    std::vector<BootstrapNode> nodes;
    nodes.reserve(std::min<std::size_t>(nodes_node.size(), max_nodes));

    for (const auto& entry : nodes_node) {
        if (nodes.size() >= max_nodes) {
            break;
        }

        if (!entry.IsMap()) {
            continue;
        }

        const bool status_udp = entry["status_udp"] && entry["status_udp"].as<bool>();
        if (!status_udp) {
            continue;
        }

        std::string host;
        if (entry["ipv4"] && !entry["ipv4"].as<std::string>().empty()) {
            host = entry["ipv4"].as<std::string>();
        } else if (entry["ipv6"] && !entry["ipv6"].as<std::string>().empty()) {
            host = entry["ipv6"].as<std::string>();
        } else {
            continue;
        }

        if (!entry["port"] || !entry["public_key"]) {
            continue;
        }

        const auto key_result = parse_public_key(entry["public_key"].as<std::string>());
        if (!key_result) {
            continue;
        }

        BootstrapNode node;
        node.ip = std::move(host);
        node.port = entry["port"].as<uint16_t>();
        node.public_key = key_result.value();
        nodes.push_back(std::move(node));
    }

    if (nodes.empty()) {
        return util::unexpected(std::string("nodes JSON did not contain any usable UDP nodes"));
    }

    return nodes;
}

util::Expected<std::vector<BootstrapNode>, std::string> BootstrapSource::resolve_bootstrap_nodes(
    const std::vector<BootstrapNode>& configured_nodes, BootstrapMode bootstrap_mode,
    const std::filesystem::path& data_dir, Fetcher fetcher, std::size_t max_nodes) {
    if (!configured_nodes.empty()) {
        return configured_nodes;
    }

    if (bootstrap_mode == BootstrapMode::Lan) {
        return std::vector<BootstrapNode>{};
    }

    if (!fetcher) {
        fetcher = [] { return fetch_default_nodes_json(); };
    }

    const auto cache_path = cache_file_path(data_dir);

    // Cache-first: if we have a usable cache, return it immediately and
    // refresh in the background. Previously this code synchronously called
    // `curl` via popen on the caller's thread, blocking startup for up to
    // 20 seconds on every boot (C-15 in the 2026-05-20 review). The
    // fire-and-forget refresh keeps subsequent boots current without
    // blocking initialisation.
    auto cached = load_cached_nodes(cache_path, max_nodes);
    if (cached) {
        // `std::async` with a detached future would run-to-completion in
        // the destructor of std::future (which blocks). A bare thread
        // with `detach()` matches the fire-and-forget intent.
        try {
            std::thread([fetcher = std::move(fetcher), cache_path, max_nodes]() mutable {
                const auto fetched = fetcher();
                if (!fetched)
                    return;
                const auto parsed = parse_nodes_json(fetched.value(), max_nodes);
                if (!parsed)
                    return;
                write_cache(cache_path, fetched.value());
            }).detach();
        } catch (...) {
            // Failure to spawn a refresher is non-fatal; cache stays as-is.
        }
        return cached;
    }

    // No (usable) cache — we have no choice but to block, otherwise the
    // first-ever startup has no DHT entry points at all.
    const auto fetched_json = fetcher();
    if (fetched_json) {
        auto parsed = parse_nodes_json(fetched_json.value(), max_nodes);
        if (parsed) {
            write_cache(cache_path, fetched_json.value());
            return parsed;
        }
    }

    return load_cached_nodes(cache_path, max_nodes);
}

util::Expected<std::string, BootstrapFetchError> BootstrapSource::fetch_default_nodes_json() {
    static constexpr const char* kCommand =
        "curl -fsSL --connect-timeout 10 --max-time 20 https://nodes.tox.chat/json";

#if defined(_WIN32)
    FILE* pipe = _popen(kCommand, "r");
#else
    FILE* pipe = popen(kCommand, "r");
#endif

    if (!pipe) {
        return util::unexpected(
            BootstrapFetchError{std::string("failed to execute curl for bootstrap nodes")});
    }

    std::array<char, 4096> buffer{};
    std::string output;
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output.append(buffer.data());
    }

#if defined(_WIN32)
    const int exit_code = _pclose(pipe);
#else
    const int exit_code = pclose(pipe);
#endif
    if (exit_code != 0) {
        return util::unexpected(BootstrapFetchError{std::string("curl exited with status ") +
                                                    std::to_string(exit_code)});
    }

    output = trim_trailing_whitespace(std::move(output));
    if (output.empty()) {
        return util::unexpected(
            BootstrapFetchError{std::string("bootstrap node fetch returned empty output")});
    }

    return output;
}

std::filesystem::path BootstrapSource::cache_file_path(const std::filesystem::path& data_dir) {
    if (data_dir.empty()) {
        return std::filesystem::path(kCacheFileName);
    }
    return data_dir / kCacheFileName;
}

}  // namespace toxtunnel::tox
