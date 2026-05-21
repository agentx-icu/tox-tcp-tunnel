#include "toxtunnel/app/rules_engine.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

#include "toxtunnel/util/atomic_file.hpp"

namespace toxtunnel {

// ---------------------------------------------------------------------------
// RulesError category
// ---------------------------------------------------------------------------

namespace {

class RulesErrorCategory : public std::error_category {
   public:
    const char* name() const noexcept override { return "rules"; }

    std::string message(int ev) const override {
        switch (static_cast<RulesError>(ev)) {
            case RulesError::FileNotFound:
                return "Rules file not found";
            case RulesError::ParseError:
                return "Failed to parse rules file";
            case RulesError::InvalidPublicKey:
                return "Invalid public key in rule";
            case RulesError::InvalidHostPattern:
                return "Invalid host pattern in rule";
            case RulesError::InvalidIpPattern:
                return "Invalid IP pattern in rule";
            case RulesError::InvalidPort:
                return "Invalid port number in rule";
            default:
                return "Unknown rules error";
        }
    }
};

const RulesErrorCategory g_rules_error_category{};

}  // namespace

const std::error_category& rules_error_category() noexcept {
    return g_rules_error_category;
}

std::error_code make_error_code(RulesError e) noexcept {
    return {static_cast<int>(e), rules_error_category()};
}

// ---------------------------------------------------------------------------
// RulesEngine factory methods
// ---------------------------------------------------------------------------

util::Expected<RulesEngine, std::string> RulesEngine::from_file(
    const std::filesystem::path& filepath) {
    if (!std::filesystem::exists(filepath)) {
        return util::make_unexpected(std::string("Rules file not found: ") + filepath.string());
    }

    try {
        YAML::Node node = YAML::LoadFile(filepath.string());
        return from_string(YAML::Dump(node));
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("Failed to parse rules file: ") + e.what());
    }
}

util::Expected<RulesEngine, std::string> RulesEngine::from_string(std::string_view yaml_content) {
    try {
        YAML::Node node = YAML::Load(std::string(yaml_content));

        RulesEngine engine;

        // Handle both array format and object format with 'rules' key
        YAML::Node rules_node;
        if (node.IsSequence()) {
            rules_node = node;
        } else if (node.IsMap() && node["rules"]) {
            rules_node = node["rules"];
        } else if (node.IsMap() && node["friend"]) {
            // Single rule at root level (for testing convenience)
            rules_node.push_back(node);
        } else {
            // Empty or unrecognized format - return empty engine
            // (but still surface rate_limit_defaults if present)
            if (node.IsMap() && node["rate_limit_defaults"]) {
                engine.rate_limit_defaults_ = node["rate_limit_defaults"].as<RateLimitSpec>();
            }
            return engine;
        }

        // Top-level rate_limit_defaults — only meaningful when the document
        // is a map (sequence-rooted documents don't carry sibling fields).
        if (node.IsMap() && node["rate_limit_defaults"]) {
            engine.rate_limit_defaults_ = node["rate_limit_defaults"].as<RateLimitSpec>();
        }

        for (const auto& rule_node : rules_node) {
            try {
                FriendRule rule = rule_node.as<FriendRule>();

                // Validate public key
                if (rule.friend_pk.length() != tox::kPublicKeyHexLen) {
                    return util::make_unexpected(
                        std::string("Invalid public key length: expected ") +
                        std::to_string(tox::kPublicKeyHexLen) + ", got " +
                        std::to_string(rule.friend_pk.length()));
                }

                // Validate public key is valid hex
                auto pk_result = tox::parse_public_key(rule.friend_pk);
                if (!pk_result) {
                    return util::make_unexpected(std::string("Invalid public key: ") +
                                                 pk_result.error());
                }
                // C-S-3 (2026-05-20 fix-storm review): canonicalise the
                // friend_pk to uppercase hex so it compares equal to the
                // value `bytes_to_hex` produces at lookup time. Without
                // this an operator who wrote the rule in lowercase (the
                // Tox community convention) silently gets an ACL that
                // never matches — friend requests are refused (S28) and
                // TUNNEL_OPEN requests hit the default-deny path (S14).
                // Use bytes_to_hex on the parsed key so the canonical
                // form matches whatever the runtime path emits.
                rule.friend_pk =
                    tox::bytes_to_hex(pk_result.value().data(), pk_result.value().size());

                // Validate port ranges
                for (const auto& target : rule.allow) {
                    for (uint16_t port : target.ports) {
                        if (port == 0) {
                            return util::make_unexpected(
                                std::string("Invalid port 0 in allow rule"));
                        }
                    }
                }
                for (const auto& target : rule.deny) {
                    for (uint16_t port : target.ports) {
                        if (port == 0) {
                            return util::make_unexpected(
                                std::string("Invalid port 0 in deny rule"));
                        }
                    }
                }

                engine.rules_.push_back(std::move(rule));
            } catch (const YAML::Exception& e) {
                return util::make_unexpected(std::string("Failed to parse rule: ") + e.what());
            }
        }

        return engine;
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("Failed to parse rules: ") + e.what());
    }
}

RulesEngine::RulesEngine(std::vector<FriendRule> rules) : rules_(std::move(rules)) {}

// ---------------------------------------------------------------------------
// RulesEngine evaluation
// ---------------------------------------------------------------------------

AccessResult RulesEngine::evaluate(const AccessRequest& request) const {
    const FriendRule* rule = find_friend_rule(request.friend_pk);
    if (!rule) {
        // No rules for this friend - use default deny
        return AccessResult::Default;
    }

    // Check deny rules first (deny takes precedence)
    for (const auto& deny_target : rule->deny) {
        if (target_matches(request, deny_target)) {
            return AccessResult::Denied;
        }
    }

    // Check allow rules
    for (const auto& allow_target : rule->allow) {
        if (target_matches(request, allow_target)) {
            return AccessResult::Allowed;
        }
    }

    // No matching rule - use default deny
    return AccessResult::Default;
}

bool RulesEngine::has_rules_for_friend(const std::string& friend_pk) const {
    return find_friend_rule(friend_pk) != nullptr;
}

const FriendRule* RulesEngine::find_friend_rule(const std::string& friend_pk) const {
    auto it = std::find_if(rules_.begin(), rules_.end(), [&friend_pk](const FriendRule& rule) {
        return rule.friend_pk == friend_pk;
    });
    return it != rules_.end() ? &(*it) : nullptr;
}

// ---------------------------------------------------------------------------
// Pattern matching utilities
// ---------------------------------------------------------------------------

bool RulesEngine::host_matches(std::string_view host, std::string_view pattern) {
    // Empty pattern matches nothing
    if (pattern.empty()) {
        return false;
    }

    // Single wildcard matches everything (no normalisation needed).
    if (pattern == "*") {
        return true;
    }

    // Hostnames are case-insensitive (RFC 1035 §2.3.3); IPv4 literals are
    // unaffected by tolower (digits/dots only). Normalise both sides
    // *before* taking the exact/wildcard branches so that, e.g.,
    // `deny: *.EXAMPLE.COM` correctly blocks `sub.example.com` and vice
    // versa. The previous implementation only lowered for the exact-match
    // fallback and let the wildcard path through case-sensitive, which
    // allowed callers to bypass deny rules with a single uppercase letter
    // (C-3 in the 2026-05-20 review).
    std::string host_lower(host);
    std::string pattern_lower(pattern);
    std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Exact match
    if (pattern_lower == host_lower) {
        return true;
    }

    // Handle wildcard patterns
    if (pattern_lower.find('*') != std::string::npos) {
        // Simple wildcard matching
        // We support patterns like:
        // - *.example.com (matches subdomain.example.com)
        // - 192.168.*.* (matches 192.168.1.100)
        // - localhost* (matches localhost, localhost:8080)

        // Find the wildcard position
        size_t wildcard_pos = pattern_lower.find('*');
        std::string prefix = pattern_lower.substr(0, wildcard_pos);
        std::string suffix = pattern_lower.substr(wildcard_pos + 1);

        // Check prefix match
        if (!prefix.empty()) {
            if (host_lower.length() < prefix.length()) {
                return false;
            }
            if (host_lower.substr(0, prefix.length()) != prefix) {
                return false;
            }
        }

        // Check suffix match
        if (!suffix.empty()) {
            if (host_lower.length() < suffix.length()) {
                return false;
            }
            if (host_lower.substr(host_lower.length() - suffix.length()) != suffix) {
                return false;
            }
        }

        return true;
    }

    return false;
}

bool RulesEngine::ip_matches(std::string_view ip, std::string_view pattern) {
    // Empty pattern matches nothing
    if (pattern.empty()) {
        return false;
    }

    // Single wildcard matches any IP
    if (pattern == "*") {
        return true;
    }

    // Exact match
    if (pattern == ip) {
        return true;
    }

    // Handle octet wildcards (e.g., "192.168.*.*")
    if (pattern.find('*') != std::string_view::npos) {
        std::string ip_str(ip);
        std::string pattern_str(pattern);

        // Split by '.'
        std::vector<std::string> ip_parts;
        std::vector<std::string> pattern_parts;

        std::istringstream ip_ss(ip_str);
        std::string part;
        while (std::getline(ip_ss, part, '.')) {
            ip_parts.push_back(part);
        }

        std::istringstream pattern_ss(pattern_str);
        while (std::getline(pattern_ss, part, '.')) {
            pattern_parts.push_back(part);
        }

        // Must have same number of parts
        if (ip_parts.size() != pattern_parts.size()) {
            return false;
        }

        // Compare each part
        for (size_t i = 0; i < ip_parts.size(); ++i) {
            if (pattern_parts[i] != "*" && pattern_parts[i] != ip_parts[i]) {
                return false;
            }
        }

        return true;
    }

    return false;
}

bool RulesEngine::port_allowed(uint16_t port, const std::vector<uint16_t>& allowed_ports) {
    // Empty list means all ports are allowed
    if (allowed_ports.empty()) {
        return true;
    }

    return std::find(allowed_ports.begin(), allowed_ports.end(), port) != allowed_ports.end();
}

bool RulesEngine::target_matches(const AccessRequest& request, const TargetSpec& spec) {
    // Check host match
    if (!host_matches(request.target_host, spec.host)) {
        return false;
    }

    // Check port match
    if (!port_allowed(request.target_port, spec.ports)) {
        return false;
    }

    return true;
}

bool RulesEngine::source_matches(const AccessRequest& request, const SourceSpec& spec) {
    // Check IP match
    if (spec.ip.has_value()) {
        if (!request.source_ip.has_value()) {
            return false;
        }
        if (!ip_matches(*request.source_ip, *spec.ip)) {
            return false;
        }
    }

    // Check port match
    if (spec.port.has_value()) {
        if (!request.source_port.has_value()) {
            return false;
        }
        if (*spec.port != *request.source_port) {
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

std::string RulesEngine::to_yaml() const {
    YAML::Emitter out;
    out << YAML::BeginSeq;

    for (const auto& rule : rules_) {
        out << YAML::BeginMap;

        out << YAML::Key << "friend" << YAML::Value << rule.friend_pk;

        if (!rule.allow.empty()) {
            out << YAML::Key << "allow";
            out << YAML::BeginSeq;
            for (const auto& target : rule.allow) {
                out << YAML::BeginMap;
                out << YAML::Key << "host" << YAML::Value << target.host;
                if (!target.ports.empty()) {
                    out << YAML::Key << "ports" << YAML::Value << target.ports;
                }
                out << YAML::EndMap;
            }
            out << YAML::EndSeq;
        }

        if (!rule.deny.empty()) {
            out << YAML::Key << "deny";
            out << YAML::BeginSeq;
            for (const auto& target : rule.deny) {
                out << YAML::BeginMap;
                out << YAML::Key << "host" << YAML::Value << target.host;
                if (!target.ports.empty()) {
                    out << YAML::Key << "ports" << YAML::Value << target.ports;
                }
                out << YAML::EndMap;
            }
            out << YAML::EndSeq;
        }

        out << YAML::EndMap;
    }

    out << YAML::EndSeq;
    return out.c_str();
}

util::Expected<void, std::string> RulesEngine::save(const std::filesystem::path& filepath) const {
    try {
        // Atomic write so a crash mid-save can't leave a truncated rules.yaml
        // (which would then fail to parse on the next SIGHUP reload — the
        // rules file is the *core* reloadable artefact, so corrupting it
        // during a routine save is a high-impact bug).
        const std::string serialised = to_yaml();
        util::AtomicFileOptions opts{};
        opts.fsync_parent_dir = true;
        auto written = util::atomic_write_file(filepath, serialised, opts);
        if (!written) {
            return util::make_unexpected(std::string("Failed to write rules: ") + written.error());
        }
        return {};
    } catch (const std::exception& e) {
        return util::make_unexpected(std::string("Failed to save rules: ") + e.what());
    }
}

void RulesEngine::add_rule(FriendRule rule) {
    rules_.push_back(std::move(rule));
}

}  // namespace toxtunnel

// ---------------------------------------------------------------------------
// YAML encoding/decoding implementations
// ---------------------------------------------------------------------------

namespace YAML {

using toxtunnel::FriendRule;
using toxtunnel::SourceSpec;
using toxtunnel::TargetSpec;

// ---------------------------------------------------------------------------
// TargetSpec
// ---------------------------------------------------------------------------

Node convert<TargetSpec>::encode(const TargetSpec& rhs) {
    Node node;
    node["host"] = rhs.host;
    if (!rhs.ports.empty()) {
        node["ports"] = rhs.ports;
    }
    return node;
}

bool convert<TargetSpec>::decode(const Node& node, TargetSpec& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (!node["host"]) {
        return false;
    }
    rhs.host = node["host"].as<std::string>();

    if (node["ports"]) {
        rhs.ports = node["ports"].as<std::vector<uint16_t>>();
    }

    return true;
}

// ---------------------------------------------------------------------------
// SourceSpec
// ---------------------------------------------------------------------------

Node convert<SourceSpec>::encode(const SourceSpec& rhs) {
    Node node;
    if (rhs.ip) {
        node["ip"] = *rhs.ip;
    }
    if (rhs.port) {
        node["port"] = *rhs.port;
    }
    return node;
}

bool convert<SourceSpec>::decode(const Node& node, SourceSpec& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (node["ip"]) {
        rhs.ip = node["ip"].as<std::string>();
    }

    if (node["port"]) {
        rhs.port = node["port"].as<uint16_t>();
    }

    return true;
}

// ---------------------------------------------------------------------------
// FriendRule
// ---------------------------------------------------------------------------

Node convert<FriendRule>::encode(const FriendRule& rhs) {
    Node node;
    node["friend"] = rhs.friend_pk;

    if (!rhs.allow.empty()) {
        node["allow"] = rhs.allow;
    }

    if (!rhs.deny.empty()) {
        node["deny"] = rhs.deny;
    }

    return node;
}

bool convert<FriendRule>::decode(const Node& node, FriendRule& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    // Support both "friend" and "friend_pk" keys
    if (node["friend"]) {
        rhs.friend_pk = node["friend"].as<std::string>();
    } else if (node["friend_pk"]) {
        rhs.friend_pk = node["friend_pk"].as<std::string>();
    } else {
        return false;
    }

    if (node["allow"]) {
        rhs.allow = node["allow"].as<std::vector<TargetSpec>>();
    }

    if (node["deny"]) {
        rhs.deny = node["deny"].as<std::vector<TargetSpec>>();
    }

    if (node["rate_limit"]) {
        rhs.rate_limit = node["rate_limit"].as<toxtunnel::RateLimitSpec>();
    }

    return true;
}

// ---------------------------------------------------------------------------
// RateLimitSpec
// ---------------------------------------------------------------------------

Node convert<toxtunnel::RateLimitSpec>::encode(const toxtunnel::RateLimitSpec& rhs) {
    Node node;
    node["mode"] = std::string(toxtunnel::to_string(rhs.mode));
    if (rhs.open_per_sec)
        node["open_per_sec"] = rhs.open_per_sec;
    if (rhs.open_burst)
        node["open_burst"] = rhs.open_burst;
    if (rhs.bytes_per_sec)
        node["bytes_per_sec"] = rhs.bytes_per_sec;
    if (rhs.bytes_burst)
        node["bytes_burst"] = rhs.bytes_burst;
    if (rhs.max_concurrent_tunnels)
        node["max_concurrent_tunnels"] = rhs.max_concurrent_tunnels;
    return node;
}

bool convert<toxtunnel::RateLimitSpec>::decode(const Node& node, toxtunnel::RateLimitSpec& rhs) {
    if (!node.IsMap()) {
        return false;
    }
    if (node["mode"]) {
        const auto s = node["mode"].as<std::string>();
        if (!toxtunnel::parse_rate_limit_mode(s, rhs.mode)) {
            return false;
        }
    } else {
        // Mode defaults to enforce if any limit values are present and no
        // explicit mode is set; this matches the design doc default of
        // "tighten by default once configured".
        rhs.mode = toxtunnel::RateLimitMode::Enforce;
    }
    if (node["open_per_sec"])
        rhs.open_per_sec = node["open_per_sec"].as<std::uint32_t>();
    if (node["open_burst"])
        rhs.open_burst = node["open_burst"].as<std::uint32_t>();
    if (node["bytes_per_sec"])
        rhs.bytes_per_sec = node["bytes_per_sec"].as<std::uint64_t>();
    if (node["bytes_burst"])
        rhs.bytes_burst = node["bytes_burst"].as<std::uint64_t>();
    if (node["max_concurrent_tunnels"]) {
        rhs.max_concurrent_tunnels = node["max_concurrent_tunnels"].as<std::uint32_t>();
    }
    return true;
}

}  // namespace YAML
