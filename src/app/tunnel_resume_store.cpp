#include "toxtunnel/app/tunnel_resume_store.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>

#include "toxtunnel/util/atomic_file.hpp"

namespace toxtunnel::app {

namespace {

// system_clock (not steady_clock) is mandatory here: the saved value is
// persisted to YAML and compared against `now_ns()` on the *next* process
// run, possibly after a reboot. steady_clock's epoch is arbitrary and
// resets per boot, so the old `saved_at_ns - cutoff` comparison was
// essentially random across restarts (C-9 in the 2026-05-20 review).
[[nodiscard]] std::int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

void TunnelResumeStore::set_path(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mu_);
    path_ = path;
}

void TunnelResumeStore::set_server_tox_id(std::string id) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!server_tox_id_.empty() && server_tox_id_ != id) {
        // Active server changed — saved entries are stale by definition.
        entries_.clear();
    }
    server_tox_id_ = std::move(id);
}

util::Expected<void, std::string> TunnelResumeStore::load() {
    std::lock_guard<std::mutex> lock(mu_);
    entries_.clear();
    if (path_.empty() || !std::filesystem::exists(path_)) {
        return {};
    }
    YAML::Node root;
    try {
        root = YAML::LoadFile(path_.string());
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("parse tunnel_resume_state.yaml: ") + e.what());
    }
    if (!root.IsMap()) {
        return {};
    }
    if (root["version"] && root["version"].as<int>() != 1) {
        return util::make_unexpected(
            std::string("tunnel_resume_state.yaml: unsupported schema version"));
    }
    if (root["server_tox_id"]) {
        const auto saved_id = root["server_tox_id"].as<std::string>();
        if (!server_tox_id_.empty() && saved_id != server_tox_id_) {
            // Different server identity — drop everything.
            return {};
        }
    }
    if (!root["tunnels"] || !root["tunnels"].IsSequence()) {
        return {};
    }
    const auto cutoff_ns = now_ns() - static_cast<std::int64_t>(max_age_seconds_) * 1'000'000'000LL;
    for (const auto& node : root["tunnels"]) {
        if (!node.IsMap())
            continue;
        TunnelResumeEntry e;
        if (node["tunnel_id"])
            e.tunnel_id = node["tunnel_id"].as<std::uint16_t>();
        if (node["target_host"])
            e.target_host = node["target_host"].as<std::string>();
        if (node["target_port"])
            e.target_port = node["target_port"].as<std::uint16_t>();
        if (node["last_local_recv_offset"])
            e.last_local_recv_offset = node["last_local_recv_offset"].as<std::uint64_t>();
        if (node["last_local_send_offset"])
            e.last_local_send_offset = node["last_local_send_offset"].as<std::uint64_t>();
        if (node["local_listener_port"])
            e.local_listener_port = node["local_listener_port"].as<std::uint16_t>();
        if (node["saved_at_ns"])
            e.saved_at_ns = node["saved_at_ns"].as<std::int64_t>();
        if (e.saved_at_ns > 0 && e.saved_at_ns < cutoff_ns) {
            continue;  // stale
        }
        entries_.push_back(std::move(e));
    }
    return {};
}

util::Expected<void, std::string> TunnelResumeStore::save() const {
    std::lock_guard<std::mutex> lock(mu_);
    if (path_.empty()) {
        return {};
    }
    YAML::Emitter out;
    out << YAML::BeginMap;
    out << YAML::Key << "version" << YAML::Value << 1;
    out << YAML::Key << "saved_at_ns" << YAML::Value << now_ns();
    if (!server_tox_id_.empty()) {
        out << YAML::Key << "server_tox_id" << YAML::Value << server_tox_id_;
    }
    out << YAML::Key << "tunnels" << YAML::Value << YAML::BeginSeq;
    for (const auto& e : entries_) {
        out << YAML::BeginMap;
        out << YAML::Key << "tunnel_id" << YAML::Value << e.tunnel_id;
        out << YAML::Key << "target_host" << YAML::Value << e.target_host;
        out << YAML::Key << "target_port" << YAML::Value << e.target_port;
        out << YAML::Key << "last_local_recv_offset" << YAML::Value << e.last_local_recv_offset;
        out << YAML::Key << "last_local_send_offset" << YAML::Value << e.last_local_send_offset;
        out << YAML::Key << "local_listener_port" << YAML::Value << e.local_listener_port;
        out << YAML::Key << "saved_at_ns" << YAML::Value << e.saved_at_ns;
        out << YAML::EndMap;
    }
    out << YAML::EndSeq;
    out << YAML::EndMap;

    std::string yaml(out.c_str());
    yaml += '\n';
    util::AtomicFileOptions opts;
    opts.fsync_parent_dir = false;  // cache-class file; rewriting next start is acceptable
    return util::atomic_write_file(path_, yaml, opts);
}

void TunnelResumeStore::upsert(const TunnelResumeEntry& entry) {
    std::lock_guard<std::mutex> lock(mu_);
    // Always stamp with wall time so the staleness comparison on the next
    // process run is meaningful (see C-9 note on now_ns). Callers don't
    // need to populate saved_at_ns; if they do, we overwrite to keep the
    // invariant local to this store.
    TunnelResumeEntry stamped = entry;
    stamped.saved_at_ns = now_ns();
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const TunnelResumeEntry& e) {
        return e.tunnel_id == stamped.tunnel_id;
    });
    if (it == entries_.end()) {
        entries_.push_back(stamped);
    } else {
        *it = stamped;
    }
}

void TunnelResumeStore::erase(std::uint16_t tunnel_id) {
    std::lock_guard<std::mutex> lock(mu_);
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [tunnel_id](const TunnelResumeEntry& e) {
                                      return e.tunnel_id == tunnel_id;
                                  }),
                   entries_.end());
}

std::vector<TunnelResumeEntry> TunnelResumeStore::entries() const {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_;
}

std::optional<TunnelResumeEntry> TunnelResumeStore::find(std::uint16_t tunnel_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it =
        std::find_if(entries_.begin(), entries_.end(),
                     [tunnel_id](const TunnelResumeEntry& e) { return e.tunnel_id == tunnel_id; });
    if (it == entries_.end())
        return std::nullopt;
    return *it;
}

std::size_t TunnelResumeStore::prune_stale() {
    std::lock_guard<std::mutex> lock(mu_);
    const auto cutoff_ns = now_ns() - static_cast<std::int64_t>(max_age_seconds_) * 1'000'000'000LL;
    const auto before = entries_.size();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [cutoff_ns](const TunnelResumeEntry& e) {
                                      return e.saved_at_ns > 0 && e.saved_at_ns < cutoff_ns;
                                  }),
                   entries_.end());
    return before - entries_.size();
}

}  // namespace toxtunnel::app
