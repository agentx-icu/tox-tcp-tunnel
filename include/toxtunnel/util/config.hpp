#pragma once

#include <yaml-cpp/yaml.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/endpoint_label.hpp"
#include "toxtunnel/util/expected.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel {

// ---------------------------------------------------------------------------
// Configuration structures
// ---------------------------------------------------------------------------

/// The address a forward binds when the operator did not name one.
///
/// A LEGACY COMPATIBILITY FALLBACK, not a recommendation: it is the wildcard,
/// so the forward is reachable from anything that can route to this host. It
/// stays the default only because changing it would silently break existing
/// deployments that rely on it. New configs should set `local_address`
/// explicitly — `127.0.0.1` unless the forward is genuinely meant to serve
/// other machines.
inline constexpr std::string_view kLegacyForwardBindAddress = "0.0.0.0";

/// Represents a port forwarding rule for client mode.
struct ForwardRule {
    uint16_t local_port = 0;   ///< Local port to listen on
    std::string remote_host;   ///< Remote host to connect to (via tunnel)
    uint16_t remote_port = 0;  ///< Remote port to connect to

    /// Local address to bind the listener to. NUMERIC IP LITERALS ONLY —
    /// IPv4 or IPv6 (`127.0.0.1`, `::1`, `192.168.1.10`, `0.0.0.0`, `::`).
    ///
    /// Deliberately NOT named `local_host`, even though it sits beside
    /// `remote_host`: `remote_host` accepts a hostname, which the *server*
    /// resolves, whereas this goes to `asio::ip::make_address`, which parses
    /// literals only. `localhost` is rejected here — use `127.0.0.1`.
    ///
    /// OPTIONAL ON PURPOSE, and absence is preserved rather than collapsed
    /// into a default string: "the operator never set this" and "the operator
    /// deliberately chose the wildcard" must stay distinguishable, because the
    /// first earns a migration warning and the second must be met with
    /// silence.
    ///
    /// Declared last, and DEFAULT-INITIALISED, so the three-field aggregate
    /// form keeps compiling: this project builds `-Werror` with
    /// `-Wmissing-field-initializers`, and without the initialiser here every
    /// existing `{port, "host", port}` site becomes a hard error on both Clang
    /// and GCC. The type stays an aggregate, so brace initialisation with
    /// three or four fields both work.
    std::optional<std::string> local_address = std::nullopt;

    /// The address this rule actually binds: the explicit value, or the
    /// legacy wildcard fallback.
    [[nodiscard]] std::string effective_local_address() const {
        return local_address.value_or(std::string(kLegacyForwardBindAddress));
    }

    /// "127.0.0.1:2222", or "[::1]:2222" for IPv6. The brackets are not
    /// decoration: without them "::1:2222" is ambiguous — a reader cannot tell
    /// where the address ends and the port begins.
    [[nodiscard]] std::string local_endpoint_label() const {
        return format_endpoint_label(effective_local_address(), local_port);
    }

    /// True when the operator named an address, whatever it was. The warning
    /// path keys off this, not off the resulting address.
    [[nodiscard]] bool has_explicit_local_address() const noexcept {
        return local_address.has_value();
    }

    /// Compares the EFFECTIVE address, so an absent value and an explicit
    /// `0.0.0.0` are equal. `diff_forwards()` turns inequality into a
    /// stop-and-rebind, and adding the key to a config that was already
    /// binding the wildcard changes nothing observable — it must not drop a
    /// live listener. A genuinely different address still compares unequal
    /// and does rebind.
    bool operator==(const ForwardRule& other) const {
        return local_port == other.local_port && remote_host == other.remote_host &&
               remote_port == other.remote_port &&
               effective_local_address() == other.effective_local_address();
    }
};

/// Migration advisory for a forward that is about to bind, or is bound, to a
/// non-loopback address WITHOUT the operator having asked for one.
///
/// Returns the message to show, or `std::nullopt` when there is nothing to say
/// — which includes every rule that names an address explicitly, `0.0.0.0`
/// included. An operator who wrote the wildcard made an informed choice and
/// gets silence; the warning exists for the operator who does not know their
/// forward is exposed.
[[nodiscard]] std::optional<std::string> forward_bind_advisory(const ForwardRule& rule);

/// Represents a pipe-mode target for client stdio forwarding.
struct PipeTarget {
    std::string remote_host;   ///< Remote host to connect to
    uint16_t remote_port = 0;  ///< Remote port to connect to

    bool operator==(const PipeTarget& other) const {
        return remote_host == other.remote_host && remote_port == other.remote_port;
    }
};

/// Represents a DHT bootstrap node configuration (YAML-friendly).
struct BootstrapNodeConfig {
    std::string address;     ///< Hostname or IP address
    uint16_t port = 33445;   ///< UDP port (default: 33445)
    std::string public_key;  ///< Hex-encoded public key (64 chars)

    /// Convert to a BootstrapNode (parses public key).
    /// Returns error string if public key is invalid.
    [[nodiscard]] util::Expected<tox::BootstrapNode, std::string> to_bootstrap_node() const;

    bool operator==(const BootstrapNodeConfig& other) const {
        return address == other.address && port == other.port && public_key == other.public_key;
    }
};

using BootstrapMode = tox::BootstrapMode;

/// Shared toxcore network configuration.
struct ToxConfig {
    bool udp_enabled = true;  ///< Enable UDP for toxcore
    /// Enable IPv6 (and a dual-stack UDP bind). Defaults to true, matching
    /// toxcore's own default. A dual-stack bind is not just for IPv6 reach: it
    /// stops ToxTunnel from silently monopolising the IPv4 wildcard on the DHT
    /// port. With an IPv4-only bind, a second Tox app's `[::]:33445` bind still
    /// succeeds (separate pcbs), so its port walk never advances and it goes
    /// deaf on inbound IPv4 while looking healthy. See
    /// docs/FIELD_NOTES_SSH_TUNNEL.md #8.
    bool ipv6_enabled = true;
    uint16_t tcp_port = 33445;                           ///< TCP relay port (server use)
    BootstrapMode bootstrap_mode = BootstrapMode::Auto;  ///< Bootstrap behavior
    std::vector<BootstrapNodeConfig> bootstrap_nodes;    ///< Explicit bootstrap nodes

    bool operator==(const ToxConfig& other) const {
        return udp_enabled == other.udp_enabled && ipv6_enabled == other.ipv6_enabled &&
               tcp_port == other.tcp_port && bootstrap_mode == other.bootstrap_mode &&
               bootstrap_nodes == other.bootstrap_nodes;
    }
};

/// Logging configuration.
struct LoggingConfig {
    util::LogLevel level = util::LogLevel::Info;  ///< Minimum log level
    std::optional<std::string> file;              ///< Optional log file path

    bool operator==(const LoggingConfig& other) const {
        return level == other.level && file == other.file;
    }
};

/// Optional Prometheus /metrics HTTP endpoint configuration.
///
/// Off by default — operators opt in by setting `enabled: true`. The endpoint
/// binds to a single host:port and serves one URL path; everything else 404s.
struct MetricsConfig {
    bool enabled = false;
    std::string listen = "127.0.0.1:9100";
    std::string path = "/metrics";

    bool operator==(const MetricsConfig& other) const {
        return enabled == other.enabled && listen == other.listen && path == other.path;
    }
};

/// Runtime inspection (local IPC) configuration.
struct InspectConfig {
    bool enabled = true;

    bool operator==(const InspectConfig& other) const = default;
};

/// Tunnel-resume sub-block. Default off; opcodes 0x08/0x09 are wire-
/// inactive when `enabled: false` and v0.3.0 peers see no change.
struct TunnelResumeConfig {
    bool enabled = false;
    std::string state_path;              ///< default: <data_dir>/tunnel_resume_state.yaml
    uint32_t max_age_seconds = 300;      ///< entries older than this are dropped on load
    std::string on_gap = "passthrough";  ///< passthrough | close

    bool operator==(const TunnelResumeConfig& other) const = default;
};

/// Per-tunnel data-path tunables (write coalescing + idle reaper).
struct TunnelConfig {
    uint32_t coalesce_max_delay_us = 200;
    uint32_t coalesce_max_bytes = 1362;
    /// Coalesce mode: "fixed" (v0.3.0 behaviour, current default), "adaptive"
    /// (state-machine policy selection), "bypass" (always emit), "drain"
    /// (no hold timer).
    std::string coalesce_mode = "fixed";
    uint32_t idle_timeout_seconds = 0;
    uint32_t reaper_tick_seconds = 10;
    /// Half-close linger cap (seconds). After a tunnel does a local half-close
    /// (TCP read-EOF on one side -> it sends TUNNEL_CLOSE and enters
    /// Disconnecting), it waits for the peer's reciprocal TUNNEL_CLOSE before
    /// finalizing. If the peer never sends it (its app reads everything and
    /// abandons the socket without closing), the tunnel would otherwise linger
    /// forever holding a half-open TCP fd. After this many seconds with no
    /// TUNNEL_DATA in either direction, the maintenance scan force-closes such a
    /// tunnel (analogous to Linux tcp_fin_timeout for orphaned FIN_WAIT_2
    /// sockets). On by default; 0 disables the cap. Distinct from
    /// `idle_timeout_seconds`: the general idle reaper stays opt-in (0), while
    /// this cap applies only to tunnels stuck in Disconnecting.
    uint32_t half_close_timeout_seconds = 120;
    /// Application-level PING/PONG keepalive interval (seconds). 0 disables it
    /// (the default — toxcore's own connection tracking is relied upon). When
    /// set, each peer is PINGed every interval and declared dead — closing its
    /// tunnels (server) / triggering failover (client) — after
    /// `keepalive_interval_seconds * 3` of no PONG. Detects an application that
    /// is wedged while its toxcore link still looks alive (M-02).
    uint32_t keepalive_interval_seconds = 0;
    TunnelResumeConfig resume;

    [[nodiscard]] bool reaper_enabled() const noexcept { return idle_timeout_seconds > 0; }
    [[nodiscard]] bool half_close_reaper_enabled() const noexcept {
        return half_close_timeout_seconds > 0;
    }
    [[nodiscard]] bool keepalive_enabled() const noexcept { return keepalive_interval_seconds > 0; }

    bool operator==(const TunnelConfig& other) const = default;
};

/// Tox-thread watchdog. On by default — the in-process detector calls
/// `std::abort()` after `deadline_seconds` of no heartbeat from the Tox
/// thread. systemd / launchd handles the restart.
struct WatchdogConfig {
    bool enabled = true;
    uint32_t deadline_seconds = 30;  ///< minimum enforced 5 by the implementation
    bool systemd_notify = true;      ///< no-op on non-Linux platforms

    bool operator==(const WatchdogConfig& other) const = default;
};

/// BDP-aware flow control configuration. `mode: bdp` (default since v0.4.1)
/// lets the per-tunnel `BdpFlowControl` resize the window from RTT × bandwidth
/// estimates fed by `handle_tunnel_ack_frame`. Use `mode: fixed` to lock to
/// the legacy v0.3.0 256 KiB / 16 KiB window (e.g. for soak-test reproducibility).
struct FlowControlConfig {
    std::string mode = "bdp";                          ///< "bdp" or "fixed"
    uint32_t send_window_min_bytes = 65536;            ///< 64 KiB clamp floor
    uint32_t send_window_max_bytes = 4 * 1024 * 1024;  ///< 4 MiB clamp ceiling
    uint32_t safety_factor_x100 = 150;                 ///< 1.5× BDP headroom
    uint32_t fixed_window_bytes = 262144;  ///< 256 KiB — used in fixed mode and as the initial BDP
                                           ///< window before any RTT samples are observed.

    bool operator==(const FlowControlConfig& other) const = default;
};

/// Service / daemon policy for packaged installs (`--service`).
/// Controls whether a platform service manager should keep the process running.
///
/// Defaults are intentionally asymmetric to match the packaging policy:
/// - server: defaults to "online" so `dpkg -i` / pkg / MSI install -> reachable immediately,
///   and so existing server YAML configs without a `service:` section keep running after upgrade.
/// - client: defaults to "idle" so installing the package never silently opens local forward
///   ports on a desktop that's only meant to dial out.
struct ServiceConfig {
    /// When true in server mode, `toxtunnel --service` runs the tunnel server.
    /// Defaults to true: server installs are expected to be online.
    bool auto_start = true;

    /// When true in client mode, `toxtunnel --service` runs the tunnel client (local forwards).
    /// Defaults to false: client installs do not auto-bind local ports.
    bool allow_client_daemon = false;

    bool operator==(const ServiceConfig& other) const {
        return auto_start == other.auto_start && allow_client_daemon == other.allow_client_daemon;
    }
};

// ---------------------------------------------------------------------------
// Mode-specific configuration
// ---------------------------------------------------------------------------

/// Server-side INFO_REPLY disclosure policy. Each field is independently opt-in
/// — defaults are all `false` (the server discloses nothing). Used by
/// `gather_system_info` to decide which probes to actually run.
struct ServerInfoDisclose {
    bool hostname = false;
    bool os = false;
    bool os_version = false;
    bool arch = false;
    bool uptime = false;
    bool toxtunnel_version = false;

    [[nodiscard]] bool any() const noexcept {
        return hostname || os || os_version || arch || uptime || toxtunnel_version;
    }

    bool operator==(const ServerInfoDisclose& other) const = default;
};

/// Server-specific configuration options.
struct ServerConfig {
    uint16_t tcp_port = 33445;                         ///< TCP relay port
    bool udp_enabled = true;                           ///< Enable UDP for DHT
    std::vector<BootstrapNodeConfig> bootstrap_nodes;  ///< DHT bootstrap nodes
    std::optional<std::string> rules_file;             ///< Optional access rules file
    ServerInfoDisclose disclose;                       ///< INFO_REPLY opt-in fields

    bool operator==(const ServerConfig& other) const {
        return tcp_port == other.tcp_port && udp_enabled == other.udp_enabled &&
               bootstrap_nodes == other.bootstrap_nodes && rules_file == other.rules_file &&
               disclose == other.disclose;
    }
};

/// Dynamic-destination SOCKS5 (and HTTP CONNECT) listener on the client.
///
/// Off by default — operators opt in. The server still enforces access via
/// `rules.yaml`, so enabling this on the client does not change the server's
/// trust boundary; it only lets the client dial arbitrary destinations
/// without enumerating them in `forwards`.
struct Socks5Config {
    bool enabled = false;
    std::string listen = "127.0.0.1:1080";

    bool operator==(const Socks5Config& other) const = default;
};

/// Failover policy for multi-server clients.
///
/// When `client.server_id` resolves to more than one Tox ID, the client adds
/// every server as a Tox friend at startup and tracks one "active" server at
/// a time. If the active server stays offline for `timeout_seconds`, the
/// client promotes the next online candidate. Once the configured primary
/// (index 0) comes back online and stays online for `prefer_primary_grace_seconds`,
/// the client switches back.
struct FailoverConfig {
    /// How long the active server must stay offline before failing over.
    uint32_t timeout_seconds = 60;
    /// How long the primary must be continuously online before we switch back
    /// to it from a fallback.
    uint32_t prefer_primary_grace_seconds = 30;

    bool operator==(const FailoverConfig& other) const = default;
};

/// Client-specific configuration options.
struct ClientConfig {
    /// Primary server's Tox ID (76 hex chars) or known-servers alias.
    /// When the YAML provides a list, this holds the first entry.
    std::string server_id;
    /// Additional fallback servers tried, in order, when the primary is
    /// unreachable. May be Tox IDs or known-servers aliases. When the YAML
    /// provides a list under `server_id`, entries 1..N populate this.
    std::vector<std::string> fallback_server_ids;
    std::vector<ForwardRule> forwards;      ///< Port forwarding rules
    std::optional<PipeTarget> pipe_target;  ///< Optional stdio pipe target
    FailoverConfig failover;                ///< Multi-server failover policy
    Socks5Config socks5;                    ///< Optional dynamic-destination listener

    /// Return the ordered list of all server IDs (primary first, then fallbacks).
    /// Skips empty entries.
    [[nodiscard]] std::vector<std::string> all_server_ids() const {
        std::vector<std::string> ids;
        ids.reserve(1 + fallback_server_ids.size());
        if (!server_id.empty()) {
            ids.push_back(server_id);
        }
        for (const auto& id : fallback_server_ids) {
            if (!id.empty()) {
                ids.push_back(id);
            }
        }
        return ids;
    }

    bool operator==(const ClientConfig& other) const {
        return server_id == other.server_id && fallback_server_ids == other.fallback_server_ids &&
               forwards == other.forwards && pipe_target == other.pipe_target &&
               failover == other.failover && socks5 == other.socks5;
    }
};

/// Parse a pipe target of the form "host:port".
[[nodiscard]] util::Expected<PipeTarget, std::string> parse_pipe_target(std::string_view spec);

// ---------------------------------------------------------------------------
// Main configuration
// ---------------------------------------------------------------------------

/// Operating mode of the application.
enum class Mode {
    Server,  ///< Act as a tunnel server
    Client,  ///< Act as a tunnel client
};

/// Main configuration structure containing all options.
struct Config {
    // Common options
    Mode mode = Mode::Server;
    std::filesystem::path data_dir;  ///< Directory for Tox save data
    LoggingConfig logging;
    ServiceConfig service;
    ToxConfig tox;
    MetricsConfig metrics;
    InspectConfig inspect;
    TunnelConfig tunnel;
    FlowControlConfig flow_control;
    WatchdogConfig watchdog;

    // Mode-specific options
    std::optional<ServerConfig> server;
    std::optional<ClientConfig> client;

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /// Load configuration from a YAML file.
    /// Returns the Config on success, or an error description string.
    [[nodiscard]] static util::Expected<Config, std::string> from_file(
        const std::filesystem::path& filepath);

    /// Load configuration from a YAML string.
    /// Useful for testing or loading from command-line argument.
    [[nodiscard]] static util::Expected<Config, std::string> from_string(
        std::string_view yaml_content);

    /// Create default server configuration.
    [[nodiscard]] static Config default_server();

    /// Create default client configuration.
    [[nodiscard]] static Config default_client();

    // -----------------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------------

    /// Validate the configuration.
    /// Returns success or an error description.
    [[nodiscard]] util::Expected<void, std::string> validate() const;

    /// Merge CLI overrides into this configuration.
    /// Non-empty / non-nullopt values in @p overrides replace existing values.
    void merge_cli_overrides(const Config& overrides);

    /// Serialize configuration to YAML.
    [[nodiscard]] std::string to_yaml() const;

    /// Save configuration to a YAML file.
    [[nodiscard]] util::Expected<void, std::string> save(
        const std::filesystem::path& filepath) const;

    /// Return the effective tox configuration after applying compatibility fallbacks.
    [[nodiscard]] ToxConfig effective_tox_config() const;

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Check if running in server mode.
    [[nodiscard]] bool is_server() const { return mode == Mode::Server; }

    /// Check if running in client mode.
    [[nodiscard]] bool is_client() const { return mode == Mode::Client; }

    /// Get server configuration (throws if not in server mode).
    [[nodiscard]] const ServerConfig& server_config() const;

    /// Get client configuration (throws if not in client mode).
    [[nodiscard]] const ClientConfig& client_config() const;

    /// Whether `--service` should run the tunnel (vs exiting successfully without binding ports).
    [[nodiscard]] bool should_run_as_service_daemon() const;

    bool operator==(const Config& other) const {
        return mode == other.mode && data_dir == other.data_dir && logging == other.logging &&
               service == other.service && effective_tox_config() == other.effective_tox_config() &&
               metrics == other.metrics && inspect == other.inspect && tunnel == other.tunnel &&
               flow_control == other.flow_control && watchdog == other.watchdog &&
               server == other.server && client == other.client;
    }
};

// ---------------------------------------------------------------------------
// ConfigError enum for std::error_code integration
// ---------------------------------------------------------------------------

enum class ConfigError {
    FileNotFound = 1,
    ParseError,
    ValidationError,
    InvalidMode,
    InvalidPort,
    InvalidToxId,
    InvalidPublicKey,
    MissingRequired,
};

/// Returns the singleton error_category for ConfigError codes.
const std::error_category& config_error_category() noexcept;

/// make_error_code overload for ConfigError (found via ADL).
std::error_code make_error_code(ConfigError e) noexcept;

}  // namespace toxtunnel

// Enable implicit conversion to std::error_code
template <>
struct std::is_error_code_enum<toxtunnel::ConfigError> : std::true_type {};

// ---------------------------------------------------------------------------
// YAML-CPP encoding specializations
// ---------------------------------------------------------------------------

namespace YAML {

template <>
struct convert<toxtunnel::ForwardRule> {
    static Node encode(const toxtunnel::ForwardRule& rhs);
    static bool decode(const Node& node, toxtunnel::ForwardRule& rhs);
};

template <>
struct convert<toxtunnel::PipeTarget> {
    static Node encode(const toxtunnel::PipeTarget& rhs);
    static bool decode(const Node& node, toxtunnel::PipeTarget& rhs);
};

template <>
struct convert<toxtunnel::BootstrapNodeConfig> {
    static Node encode(const toxtunnel::BootstrapNodeConfig& rhs);
    static bool decode(const Node& node, toxtunnel::BootstrapNodeConfig& rhs);
};

template <>
struct convert<toxtunnel::tox::BootstrapMode> {
    static Node encode(const toxtunnel::tox::BootstrapMode& rhs);
    static bool decode(const Node& node, toxtunnel::tox::BootstrapMode& rhs);
};

template <>
struct convert<toxtunnel::ToxConfig> {
    static Node encode(const toxtunnel::ToxConfig& rhs);
    static bool decode(const Node& node, toxtunnel::ToxConfig& rhs);
};

template <>
struct convert<toxtunnel::LoggingConfig> {
    static Node encode(const toxtunnel::LoggingConfig& rhs);
    static bool decode(const Node& node, toxtunnel::LoggingConfig& rhs);
};

template <>
struct convert<toxtunnel::ServiceConfig> {
    static Node encode(const toxtunnel::ServiceConfig& rhs);
    static bool decode(const Node& node, toxtunnel::ServiceConfig& rhs);
};

template <>
struct convert<toxtunnel::MetricsConfig> {
    static Node encode(const toxtunnel::MetricsConfig& rhs);
    static bool decode(const Node& node, toxtunnel::MetricsConfig& rhs);
};

template <>
struct convert<toxtunnel::InspectConfig> {
    static Node encode(const toxtunnel::InspectConfig& rhs);
    static bool decode(const Node& node, toxtunnel::InspectConfig& rhs);
};

template <>
struct convert<toxtunnel::TunnelResumeConfig> {
    static Node encode(const toxtunnel::TunnelResumeConfig& rhs);
    static bool decode(const Node& node, toxtunnel::TunnelResumeConfig& rhs);
};

template <>
struct convert<toxtunnel::TunnelConfig> {
    static Node encode(const toxtunnel::TunnelConfig& rhs);
    static bool decode(const Node& node, toxtunnel::TunnelConfig& rhs);
};

template <>
struct convert<toxtunnel::FlowControlConfig> {
    static Node encode(const toxtunnel::FlowControlConfig& rhs);
    static bool decode(const Node& node, toxtunnel::FlowControlConfig& rhs);
};

template <>
struct convert<toxtunnel::WatchdogConfig> {
    static Node encode(const toxtunnel::WatchdogConfig& rhs);
    static bool decode(const Node& node, toxtunnel::WatchdogConfig& rhs);
};

template <>
struct convert<toxtunnel::ServerInfoDisclose> {
    static Node encode(const toxtunnel::ServerInfoDisclose& rhs);
    static bool decode(const Node& node, toxtunnel::ServerInfoDisclose& rhs);
};

template <>
struct convert<toxtunnel::ServerConfig> {
    static Node encode(const toxtunnel::ServerConfig& rhs);
    static bool decode(const Node& node, toxtunnel::ServerConfig& rhs);
};

template <>
struct convert<toxtunnel::Socks5Config> {
    static Node encode(const toxtunnel::Socks5Config& rhs);
    static bool decode(const Node& node, toxtunnel::Socks5Config& rhs);
};

template <>
struct convert<toxtunnel::ClientConfig> {
    static Node encode(const toxtunnel::ClientConfig& rhs);
    static bool decode(const Node& node, toxtunnel::ClientConfig& rhs);
};

template <>
struct convert<toxtunnel::Mode> {
    static Node encode(const toxtunnel::Mode& rhs);
    static bool decode(const Node& node, toxtunnel::Mode& rhs);
};

template <>
struct convert<toxtunnel::util::LogLevel> {
    static Node encode(const toxtunnel::util::LogLevel& rhs);
    static bool decode(const Node& node, toxtunnel::util::LogLevel& rhs);
};

template <>
struct convert<toxtunnel::Config> {
    static Node encode(const toxtunnel::Config& rhs);
    static bool decode(const Node& node, toxtunnel::Config& rhs);
};

}  // namespace YAML
