#include "toxtunnel/app/known_servers.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include <system_error>

#include "toxtunnel/util/atomic_file.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::app {

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

std::string to_string(KnownConnectionType type) {
    switch (type) {
        case KnownConnectionType::None:
            return "none";
        case KnownConnectionType::Tcp:
            return "tcp";
        case KnownConnectionType::Udp:
            return "udp";
    }
    return "none";
}

std::optional<KnownConnectionType> known_connection_type_from_string(std::string_view str) {
    if (str == "none")
        return KnownConnectionType::None;
    if (str == "tcp")
        return KnownConnectionType::Tcp;
    if (str == "udp")
        return KnownConnectionType::Udp;
    return std::nullopt;
}

std::string iso8601_utc_now() {
    using namespace std::chrono;
    const auto t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    // strftime gives us a fixed-width ISO-8601 form, then we append the 'Z'.
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

bool KnownServerInfo::empty() const noexcept {
    return !hostname && !os && !os_version && !arch && !uptime_seconds && !toxtunnel_version &&
           !reported_at;
}

// ---------------------------------------------------------------------------
// KnownServersStore
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kToxIdHexLen = 76;

bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

}  // namespace

bool KnownServersStore::is_valid_tox_id(std::string_view candidate) {
    if (candidate.size() != kToxIdHexLen)
        return false;
    return std::all_of(candidate.begin(), candidate.end(), is_hex_char);
}

std::string KnownServersStore::to_upper_hex(std::string_view input) {
    std::string out(input);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

KnownServersStore::KnownServersStore(std::filesystem::path data_dir)
    : data_dir_(std::move(data_dir)), path_(data_dir_ / "known_servers.yaml") {
    std::lock_guard<std::mutex> lock(mu_);
    auto load_result = load_from_disk_locked();
    if (!load_result) {
        last_load_error_ = load_result.error();
    }
}

util::Expected<void, std::string> KnownServersStore::reload() {
    std::lock_guard<std::mutex> lock(mu_);
    last_load_error_.reset();
    auto result = load_from_disk_locked();
    if (!result) {
        last_load_error_ = result.error();
        return result;
    }
    return {};
}

util::Expected<void, std::string> KnownServersStore::load_from_disk_locked() {
    servers_.clear();

    std::error_code ec;
    if (!std::filesystem::exists(path_, ec)) {
        // Missing file is fine — empty registry.
        return {};
    }

    YAML::Node root;
    try {
        root = YAML::LoadFile(path_.string());
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("Failed to parse known_servers.yaml: ") +
                                     e.what());
    }

    if (!root.IsMap() && !root.IsNull()) {
        return util::make_unexpected(std::string("known_servers.yaml: top-level must be a map"));
    }

    if (root["servers"]) {
        const auto& list = root["servers"];
        if (!list.IsSequence()) {
            return util::make_unexpected(
                std::string("known_servers.yaml: 'servers' must be a sequence"));
        }
        for (const auto& node : list) {
            if (!node.IsMap())
                continue;

            KnownServer entry;
            if (!node["tox_id"])
                continue;
            entry.tox_id = to_upper_hex(node["tox_id"].as<std::string>());
            if (!is_valid_tox_id(entry.tox_id)) {
                util::Logger::warn("known_servers.yaml: skipping entry with invalid tox_id '{}'",
                                   entry.tox_id);
                continue;
            }

            if (node["alias"])
                entry.alias = node["alias"].as<std::string>();
            if (node["first_connected_at"]) {
                entry.first_connected_at = node["first_connected_at"].as<std::string>();
            }
            if (node["last_connected_at"]) {
                entry.last_connected_at = node["last_connected_at"].as<std::string>();
            }
            if (node["last_connection_type"]) {
                auto parsed = known_connection_type_from_string(
                    node["last_connection_type"].as<std::string>());
                if (parsed)
                    entry.last_connection_type = *parsed;
            }
            if (node["notes"])
                entry.notes = node["notes"].as<std::string>();

            if (node["info"] && node["info"].IsMap()) {
                const auto& info = node["info"];
                if (info["hostname"])
                    entry.info.hostname = info["hostname"].as<std::string>();
                if (info["os"])
                    entry.info.os = info["os"].as<std::string>();
                if (info["os_version"])
                    entry.info.os_version = info["os_version"].as<std::string>();
                if (info["arch"])
                    entry.info.arch = info["arch"].as<std::string>();
                if (info["uptime_seconds"]) {
                    entry.info.uptime_seconds = info["uptime_seconds"].as<uint64_t>();
                }
                if (info["toxtunnel_version"]) {
                    entry.info.toxtunnel_version = info["toxtunnel_version"].as<std::string>();
                }
                if (info["reported_at"]) {
                    entry.info.reported_at = info["reported_at"].as<std::string>();
                }
            }

            servers_.push_back(std::move(entry));
        }
    }

    return {};
}

util::Expected<void, std::string> KnownServersStore::save() const {
    std::lock_guard<std::mutex> lock(mu_);
    return save_locked();
}

util::Expected<void, std::string> KnownServersStore::save_locked() const {
    std::error_code ec;
    if (!data_dir_.empty()) {
        std::filesystem::create_directories(data_dir_, ec);
        if (ec) {
            return util::make_unexpected(std::string("Failed to create ") + data_dir_.string() +
                                         ": " + ec.message());
        }
    }

    YAML::Emitter out;
    out << YAML::BeginMap;
    out << YAML::Key << "servers" << YAML::Value << YAML::BeginSeq;
    for (const auto& s : servers_) {
        out << YAML::BeginMap;
        out << YAML::Key << "tox_id" << YAML::Value << s.tox_id;
        if (s.alias)
            out << YAML::Key << "alias" << YAML::Value << *s.alias;
        if (s.first_connected_at) {
            out << YAML::Key << "first_connected_at" << YAML::Value << *s.first_connected_at;
        }
        if (s.last_connected_at) {
            out << YAML::Key << "last_connected_at" << YAML::Value << *s.last_connected_at;
        }
        out << YAML::Key << "last_connection_type" << YAML::Value
            << to_string(s.last_connection_type);
        if (!s.info.empty()) {
            out << YAML::Key << "info" << YAML::Value << YAML::BeginMap;
            if (s.info.hostname)
                out << YAML::Key << "hostname" << YAML::Value << *s.info.hostname;
            if (s.info.os)
                out << YAML::Key << "os" << YAML::Value << *s.info.os;
            if (s.info.os_version) {
                out << YAML::Key << "os_version" << YAML::Value << *s.info.os_version;
            }
            if (s.info.arch)
                out << YAML::Key << "arch" << YAML::Value << *s.info.arch;
            if (s.info.uptime_seconds) {
                out << YAML::Key << "uptime_seconds" << YAML::Value << *s.info.uptime_seconds;
            }
            if (s.info.toxtunnel_version) {
                out << YAML::Key << "toxtunnel_version" << YAML::Value << *s.info.toxtunnel_version;
            }
            if (s.info.reported_at) {
                out << YAML::Key << "reported_at" << YAML::Value << *s.info.reported_at;
            }
            out << YAML::EndMap;
        }
        if (!s.notes.empty())
            out << YAML::Key << "notes" << YAML::Value << s.notes;
        out << YAML::EndMap;
    }
    out << YAML::EndSeq;
    out << YAML::EndMap;

    // Shared atomic-write helper: temp + fsync + rename + parent-dir fsync.
    std::string yaml(out.c_str());
    yaml += '\n';
    util::AtomicFileOptions opts;
    opts.fsync_parent_dir = true;
    auto write_result = util::atomic_write_file(path_, yaml, opts);
    if (!write_result) {
        return util::make_unexpected(write_result.error());
    }
    return {};
}

std::optional<KnownServer> KnownServersStore::find_by_tox_id(std::string_view tox_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    const auto upper = to_upper_hex(tox_id);
    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.tox_id == upper; });
    return it == servers_.end() ? std::nullopt : std::optional<KnownServer>(*it);
}

std::optional<KnownServer> KnownServersStore::find_by_alias(std::string_view alias) const {
    std::lock_guard<std::mutex> lock(mu_);
    const KnownServer* hit = find_by_alias_locked(alias);
    return hit == nullptr ? std::nullopt : std::optional<KnownServer>(*hit);
}

const KnownServer* KnownServersStore::find_by_alias_locked(std::string_view alias) const {
    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.alias && *s.alias == alias; });
    return it == servers_.end() ? nullptr : &*it;
}

std::string KnownServersStore::resolve_tox_id(std::string_view id_or_alias) const {
    std::lock_guard<std::mutex> lock(mu_);
    return resolve_tox_id_locked(id_or_alias);
}

std::string KnownServersStore::resolve_tox_id_locked(std::string_view id_or_alias) const {
    if (is_valid_tox_id(id_or_alias)) {
        return to_upper_hex(id_or_alias);
    }
    if (auto* hit = find_by_alias_locked(id_or_alias)) {
        return hit->tox_id;
    }
    return std::string(id_or_alias);
}

bool KnownServersStore::upsert(const KnownServer& entry) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!is_valid_tox_id(entry.tox_id))
        return false;

    const auto upper = to_upper_hex(entry.tox_id);

    // Reject alias collision with a different tox_id.
    if (entry.alias) {
        auto it = std::find_if(servers_.begin(), servers_.end(), [&](const KnownServer& s) {
            return s.alias && *s.alias == *entry.alias && s.tox_id != upper;
        });
        if (it != servers_.end())
            return false;
    }

    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.tox_id == upper; });
    KnownServer normalized = entry;
    normalized.tox_id = upper;
    if (it == servers_.end()) {
        servers_.push_back(std::move(normalized));
    } else {
        *it = std::move(normalized);
    }
    return true;
}

bool KnownServersStore::record_connection(std::string_view tox_id, KnownConnectionType type) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!is_valid_tox_id(tox_id))
        return false;
    const auto upper = to_upper_hex(tox_id);
    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.tox_id == upper; });
    const auto now = iso8601_utc_now();
    if (it == servers_.end()) {
        KnownServer entry;
        entry.tox_id = upper;
        entry.first_connected_at = now;
        entry.last_connected_at = now;
        entry.last_connection_type = type;
        servers_.push_back(std::move(entry));
    } else {
        if (!it->first_connected_at)
            it->first_connected_at = now;
        it->last_connected_at = now;
        it->last_connection_type = type;
    }
    return true;
}

bool KnownServersStore::record_info(std::string_view tox_id, const KnownServerInfo& info) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!is_valid_tox_id(tox_id))
        return false;
    const auto upper = to_upper_hex(tox_id);
    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.tox_id == upper; });
    if (it == servers_.end()) {
        KnownServer entry;
        entry.tox_id = upper;
        entry.info = info;
        if (!entry.info.reported_at)
            entry.info.reported_at = iso8601_utc_now();
        servers_.push_back(std::move(entry));
    } else {
        it->info = info;
        if (!it->info.reported_at)
            it->info.reported_at = iso8601_utc_now();
    }
    return true;
}

bool KnownServersStore::remove(std::string_view alias_or_tox_id) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto target = resolve_tox_id_locked(alias_or_tox_id);
    auto it = std::find_if(servers_.begin(), servers_.end(),
                           [&](const KnownServer& s) { return s.tox_id == target; });
    if (it == servers_.end())
        return false;
    servers_.erase(it);
    return true;
}

std::vector<KnownServer> KnownServersStore::entries() const {
    std::lock_guard<std::mutex> lock(mu_);
    auto sorted = servers_;
    std::sort(sorted.begin(), sorted.end(), [](const KnownServer& a, const KnownServer& b) {
        // Entries with alias come first, alphabetical; others sorted by tox_id.
        if (a.alias && b.alias)
            return *a.alias < *b.alias;
        if (a.alias && !b.alias)
            return true;
        if (!a.alias && b.alias)
            return false;
        return a.tox_id < b.tox_id;
    });
    return sorted;
}

std::size_t KnownServersStore::size() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return servers_.size();
}

bool KnownServersStore::empty() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return servers_.empty();
}

}  // namespace toxtunnel::app
