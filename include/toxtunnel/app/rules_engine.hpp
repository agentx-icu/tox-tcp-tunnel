#pragma once

#include <yaml-cpp/yaml.h>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "toxtunnel/app/rate_limiter.hpp"
#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/expected.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel {

// ---------------------------------------------------------------------------
// Access rule structures
// ---------------------------------------------------------------------------

/// Represents a target specification in an access rule.
/// Can match hosts (with optional wildcard patterns) and ports.
struct TargetSpec {
    std::string host;             ///< Host pattern (supports '*' wildcards)
    std::vector<uint16_t> ports;  ///< List of allowed/denied ports (empty = all ports)

    bool operator==(const TargetSpec& other) const {
        return host == other.host && ports == other.ports;
    }
};

/// Represents a source specification in an access rule.
/// Can match IP addresses (with optional wildcard patterns) and ports.
struct SourceSpec {
    std::optional<std::string> ip;  ///< IP pattern (supports '*' wildcards, nullopt = any)
    std::optional<uint16_t> port;   ///< Port (nullopt = any port)

    bool operator==(const SourceSpec& other) const { return ip == other.ip && port == other.port; }
};

/// Represents an access rule for a specific friend.
/// A friend can have multiple allow and deny target specifications.
struct FriendRule {
    std::string friend_pk;          ///< Friend's hex-encoded public key (64 chars)
    std::vector<TargetSpec> allow;  ///< Targets this friend is allowed to access
    std::vector<TargetSpec> deny;   ///< Targets this friend is denied from accessing
    /// Per-friend rate-limit override. Empty / default means "use the
    /// top-level `rate_limit_defaults`" or no limit at all.
    RateLimitSpec rate_limit{};

    bool operator==(const FriendRule& other) const {
        return friend_pk == other.friend_pk && allow == other.allow && deny == other.deny &&
               rate_limit == other.rate_limit;
    }
};

/// Request context for access evaluation.
/// Contains information about the incoming tunnel request.
struct AccessRequest {
    std::string friend_pk;                 ///< Friend's hex-encoded public key (64 chars)
    std::string target_host;               ///< Target host being requested
    uint16_t target_port;                  ///< Target port being requested
    std::optional<std::string> source_ip;  ///< Optional source IP of the request
    std::optional<uint16_t> source_port;   ///< Optional source port

    bool operator==(const AccessRequest& other) const {
        return friend_pk == other.friend_pk && target_host == other.target_host &&
               target_port == other.target_port && source_ip == other.source_ip &&
               source_port == other.source_port;
    }
};

/// Result of an access evaluation.
enum class AccessResult {
    Allowed,  ///< Access is explicitly allowed
    Denied,   ///< Access is explicitly denied
    Default,  ///< No matching rule, use default policy
};

// ---------------------------------------------------------------------------
// RulesEngine
// ---------------------------------------------------------------------------

/// Access control engine for tunnel requests.
///
/// The RulesEngine parses access rules from a YAML configuration file and
/// evaluates incoming tunnel requests against those rules. It follows a
/// default-deny policy unless explicitly allowed.
///
/// Rule evaluation order:
/// 1. Check explicit deny rules first (deny takes precedence)
/// 2. Check explicit allow rules
/// 3. Apply default policy (deny by default)
///
/// Typical usage:
/// @code
///   auto result = RulesEngine::from_file("/etc/toxtunnel/rules.yaml");
///   if (result) {
///       auto& engine = result.value();
///       AccessRequest req{friend_pk, "localhost", 22, {}, {}};
///       if (engine.evaluate(req) == AccessResult::Allowed) {
///           // Allow the connection
///       }
///   }
/// @endcode
class RulesEngine {
   public:
    /// Default constructor creates an empty ruleset (default deny all).
    RulesEngine() = default;

    /// Load rules from a YAML file.
    /// Returns the RulesEngine on success, or an error description string.
    [[nodiscard]] static util::Expected<RulesEngine, std::string> from_file(
        const std::filesystem::path& filepath);

    /// Load rules from a YAML string.
    /// Useful for testing or embedding rules in code.
    [[nodiscard]] static util::Expected<RulesEngine, std::string> from_string(
        std::string_view yaml_content);

    /// Create a RulesEngine from a list of friend rules.
    explicit RulesEngine(std::vector<FriendRule> rules);

    /// Evaluate an access request against the rules.
    /// Returns the access decision.
    [[nodiscard]] AccessResult evaluate(const AccessRequest& request) const;

    /// Check if a friend has any rules defined.
    [[nodiscard]] bool has_rules_for_friend(const std::string& friend_pk) const;

    /// Get all friend rules.
    [[nodiscard]] const std::vector<FriendRule>& rules() const noexcept { return rules_; }

    /// Top-level `rate_limit_defaults:` block parsed from the rules file.
    /// Used by the `RateLimiter` when a friend has no explicit override.
    [[nodiscard]] const RateLimitSpec& rate_limit_defaults() const noexcept {
        return rate_limit_defaults_;
    }
    void set_rate_limit_defaults(const RateLimitSpec& spec) { rate_limit_defaults_ = spec; }

    /// Serialize rules to YAML.
    [[nodiscard]] std::string to_yaml() const;

    /// Save rules to a YAML file.
    [[nodiscard]] util::Expected<void, std::string> save(
        const std::filesystem::path& filepath) const;

    /// Add a friend rule (for programmatic construction).
    void add_rule(FriendRule rule);

    // -----------------------------------------------------------------------
    // Pattern matching utilities (public for testing)
    // -----------------------------------------------------------------------

    /// Check if a host matches a pattern.
    /// Supports '*' as a wildcard that matches any characters.
    [[nodiscard]] static bool host_matches(std::string_view host, std::string_view pattern);

    /// Check if an IP address matches a pattern.
    /// Supports '*' as a wildcard for octets (e.g., "192.168.*.*").
    [[nodiscard]] static bool ip_matches(std::string_view ip, std::string_view pattern);

    /// Check if a port is in the allowed list.
    /// Empty list means all ports are allowed.
    [[nodiscard]] static bool port_allowed(uint16_t port,
                                           const std::vector<uint16_t>& allowed_ports);

   private:
    std::vector<FriendRule> rules_;
    RateLimitSpec rate_limit_defaults_;

    /// Find rules for a specific friend.
    [[nodiscard]] const FriendRule* find_friend_rule(const std::string& friend_pk) const;

    /// Check if a target matches a target specification.
    [[nodiscard]] static bool target_matches(const AccessRequest& request, const TargetSpec& spec);

    /// Check if a source matches a source specification.
    [[nodiscard]] static bool source_matches(const AccessRequest& request, const SourceSpec& spec);
};

// ---------------------------------------------------------------------------
// RulesError enum for std::error_code integration
// ---------------------------------------------------------------------------

enum class RulesError {
    FileNotFound = 1,
    ParseError,
    InvalidPublicKey,
    InvalidHostPattern,
    InvalidIpPattern,
    InvalidPort,
};

/// Returns the singleton error_category for RulesError codes.
const std::error_category& rules_error_category() noexcept;

/// make_error_code overload for RulesError (found via ADL).
std::error_code make_error_code(RulesError e) noexcept;

}  // namespace toxtunnel

// Enable implicit conversion to std::error_code
template <>
struct std::is_error_code_enum<toxtunnel::RulesError> : std::true_type {};

// ---------------------------------------------------------------------------
// YAML-CPP encoding specializations
// ---------------------------------------------------------------------------

namespace YAML {

template <>
struct convert<toxtunnel::TargetSpec> {
    static Node encode(const toxtunnel::TargetSpec& rhs);
    static bool decode(const Node& node, toxtunnel::TargetSpec& rhs);
};

template <>
struct convert<toxtunnel::SourceSpec> {
    static Node encode(const toxtunnel::SourceSpec& rhs);
    static bool decode(const Node& node, toxtunnel::SourceSpec& rhs);
};

template <>
struct convert<toxtunnel::FriendRule> {
    static Node encode(const toxtunnel::FriendRule& rhs);
    static bool decode(const Node& node, toxtunnel::FriendRule& rhs);
};

template <>
struct convert<toxtunnel::RateLimitSpec> {
    static Node encode(const toxtunnel::RateLimitSpec& rhs);
    static bool decode(const Node& node, toxtunnel::RateLimitSpec& rhs);
};

}  // namespace YAML
