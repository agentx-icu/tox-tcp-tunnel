#include "toxtunnel/tox/bootstrap_source.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

#include "toxtunnel/util/atomic_file.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tox {
namespace {

constexpr const char* kCacheFileName = "bootstrap_nodes.json";

// Portable cooperative stop token. Apple Clang's libc++ still lacks
// std::jthread / std::stop_token, so we hand-roll the minimum the worker needs:
// a shared atomic flag the worker polls at each observation point. A fresh flag
// is created per worker so cancelling one never affects a later one.
struct RefreshStopToken {
    std::shared_ptr<std::atomic<bool>> flag;
    [[nodiscard]] bool stop_requested() const noexcept {
        return flag && flag->load(std::memory_order_acquire);
    }
};

// H-11 (2026-05-26): owned, joinable background-refresh worker.
//
// The previous design spawned a *detached* std::thread and relied on a
// process-global cancel flag, so the thread could outlive the owning
// ToxAdapter and touch freed/global state (spdlog, std::filesystem,
// atomic_write_file) during teardown. RefreshManager replaces that with a
// single owned std::thread + per-worker stop flag (std::jthread/std::stop_token
// would be cleaner but are unavailable on Apple's libc++):
//   * spawn() joins any prior worker before launching a new one, so at most
//     one refresh runs at a time and none ever leaks.
//   * cancel_and_join() (wired to BootstrapSource::cancel_pending_refreshes)
//     sets the worker's stop flag AND joins, so by the time ToxAdapter::stop()
//     returns no refresh thread is still running.
//   * arm()/cancel state gates whether new refreshes may be spawned across
//     stop -> start cycles, preserving the previous arm_refreshes() contract.
// The manager itself is a function-local static; its destructor joins the
// worker as a final backstop.
class RefreshManager {
   public:
    static RefreshManager& instance() {
        static RefreshManager manager;
        return manager;
    }

    /// Allow subsequent spawn() calls again after a cancel.
    void arm() {
        std::lock_guard<std::mutex> lock(mutex_);
        accepting_ = true;
    }

    /// Request the in-flight worker (if any) to stop and join it. Also blocks
    /// further spawns until arm() is called again.
    void cancel_and_join() {
        std::thread worker;
        std::shared_ptr<std::atomic<bool>> flag;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            accepting_ = false;
            worker = std::move(worker_);  // take ownership, join outside lock
            flag = std::move(stop_flag_);
        }
        if (flag) {
            flag->store(true, std::memory_order_release);
        }
        if (worker.joinable()) {
            worker.join();
        }
    }

    /// Launch @p task on an owned thread, joining any previous worker first.
    /// @p task receives a RefreshStopToken it must poll at its observation
    /// points. No-op while cancelled (not armed).
    template <typename Task>
    void spawn(Task&& task) {
        std::thread previous;
        std::shared_ptr<std::atomic<bool>> prev_flag;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!accepting_) {
                return;
            }
            // Take the previous worker so it can be joined below; threads
            // never leak because at most one is ever live.
            previous = std::move(worker_);
            prev_flag = std::move(stop_flag_);
        }
        if (prev_flag) {
            prev_flag->store(true, std::memory_order_release);
        }
        if (previous.joinable()) {
            previous.join();
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Re-check: a concurrent cancel_and_join() may have flipped
            // accepting_ false while we were joining the previous worker.
            if (!accepting_) {
                return;
            }
            auto flag = std::make_shared<std::atomic<bool>>(false);
            stop_flag_ = flag;
            RefreshStopToken token{flag};
            worker_ =
                std::thread([task = std::forward<Task>(task), token]() mutable { task(token); });
        }
    }

   private:
    RefreshManager() = default;
    ~RefreshManager() { cancel_and_join(); }

    RefreshManager(const RefreshManager&) = delete;
    RefreshManager& operator=(const RefreshManager&) = delete;

    std::mutex mutex_;
    bool accepting_{true};
    std::thread worker_;
    std::shared_ptr<std::atomic<bool>> stop_flag_;
};

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
    // Bootstrap cache is best-effort recovery: a corrupted file from a
    // mid-write crash would leave the daemon with no DHT nodes on the next
    // boot. atomic_write_file removes that failure mode (and creates the
    // parent directory itself — no fs::path decomposition here, which the
    // manylinux2014 toolchain gets wrong). Parent-dir fsync off because the
    // cache is not security-critical.
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
    // refresh in the background. The synchronous `curl` path used to block
    // startup for up to 20 seconds on every boot (C-15 in the 2026-05-20
    // review); the background refresh keeps subsequent boots current without
    // blocking initialisation.
    auto cached = load_cached_nodes(cache_path, max_nodes);
    if (cached) {
        // H-11 (2026-05-26): the refresh runs on an OWNED, joinable thread
        // managed by RefreshManager. It polls the provided RefreshStopToken at
        // each observation point (fetch return, parse return, write_cache) so
        // cancel_pending_refreshes() — wired to ToxAdapter::stop — can request
        // stop and join it before any application globals are torn down.
        RefreshManager::instance().spawn(
            [fetcher = std::move(fetcher), cache_path, max_nodes](RefreshStopToken stop) mutable {
                if (stop.stop_requested()) {
                    return;
                }
                const auto fetched = fetcher();
                if (stop.stop_requested()) {
                    return;
                }
                if (!fetched) {
                    util::Logger::debug("Background bootstrap refresh failed: {}",
                                        fetched.error().message);
                    return;
                }
                const auto parsed = parse_nodes_json(fetched.value(), max_nodes);
                if (stop.stop_requested()) {
                    return;
                }
                if (!parsed) {
                    util::Logger::debug("Background bootstrap refresh parse failed: {}",
                                        parsed.error());
                    return;
                }
                write_cache(cache_path, fetched.value());
            });
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
        util::Logger::warn("Bootstrap node fetch parse failed: {}", parsed.error());
    } else {
        util::Logger::warn("Bootstrap node fetch failed: {}", fetched_json.error().message);
    }

    return load_cached_nodes(cache_path, max_nodes);
}

util::Expected<std::string, BootstrapFetchError> BootstrapSource::fetch_default_nodes_json() {
    // H-11 (2026-05-26): popen()/curl cannot be interrupted mid-call, so the
    // background-refresh worker — which cancel_pending_refreshes() joins during
    // ToxAdapter::stop() — blocks for the full curl timeout if a refresh is in
    // flight at shutdown. Keep the timeout short so that join is bounded to a
    // few seconds. The node list is a few KB of JSON, so 8s is ample on any
    // working network and fails fast on a dead one (we then fall back to cache).
    static constexpr const char* kCommand =
        "curl -fsSL --connect-timeout 5 --max-time 8 https://nodes.tox.chat/json";

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

void BootstrapSource::cancel_pending_refreshes() noexcept {
    // Deterministically stop and join the in-flight refresh worker (if any)
    // so it cannot touch application globals during shutdown. Joining can
    // block briefly; swallow any exception to honour noexcept.
    try {
        RefreshManager::instance().cancel_and_join();
    } catch (...) {
    }
}

void BootstrapSource::arm_refreshes() noexcept {
    try {
        RefreshManager::instance().arm();
    } catch (...) {
    }
}

}  // namespace toxtunnel::tox
