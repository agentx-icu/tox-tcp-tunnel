#include "toxtunnel/util/config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel {

// ---------------------------------------------------------------------------
// ConfigError category
// ---------------------------------------------------------------------------

namespace {

class ConfigErrorCategory : public std::error_category {
   public:
    const char* name() const noexcept override { return "config"; }

    std::string message(int ev) const override {
        switch (static_cast<ConfigError>(ev)) {
            case ConfigError::FileNotFound:
                return "Configuration file not found";
            case ConfigError::ParseError:
                return "Failed to parse configuration file";
            case ConfigError::ValidationError:
                return "Configuration validation failed";
            case ConfigError::InvalidMode:
                return "Invalid operating mode";
            case ConfigError::InvalidPort:
                return "Invalid port number";
            case ConfigError::InvalidToxId:
                return "Invalid Tox ID";
            case ConfigError::InvalidPublicKey:
                return "Invalid public key";
            case ConfigError::MissingRequired:
                return "Missing required configuration field";
            default:
                return "Unknown configuration error";
        }
    }
};

const ConfigErrorCategory g_config_error_category{};

const char* bootstrap_mode_to_string(toxtunnel::tox::BootstrapMode mode) {
    switch (mode) {
        case toxtunnel::tox::BootstrapMode::Auto:
            return "auto";
        case toxtunnel::tox::BootstrapMode::Lan:
            return "lan";
        default:
            return "auto";
    }
}

// Expand leading `~` / `~/` in a YAML-supplied path to the user's home directory.
// Shells normally do this before exec, but YAML strings are passed verbatim — so
// `data_dir: ~/.config/toxtunnel` would otherwise reach KnownServersStore as a
// literal `~/...` and silently miss the registry file.
//
// POSIX: HOME is authoritative. Windows: USERPROFILE is the standard, with
// HOMEDRIVE+HOMEPATH as the documented fallback.
//
// `~username` (POSIX-only, requires getpwnam) is not supported — left unchanged.
std::string expand_user_path(const std::string& path) {
    if (path.empty() || path[0] != '~') {
        return path;
    }
    // Reject `~user/...` form: only bare `~` or `~/...`.
    if (path.size() > 1 && path[1] != '/' && path[1] != '\\') {
        return path;
    }

    std::string home;
    if (const char* h = std::getenv("HOME"); h && *h) {
        home = h;
    } else if (const char* up = std::getenv("USERPROFILE"); up && *up) {
        home = up;
    } else {
        const char* drive = std::getenv("HOMEDRIVE");
        const char* hpath = std::getenv("HOMEPATH");
        if (drive && hpath) {
            home = std::string(drive) + hpath;
        }
    }
    if (home.empty()) {
        return path;  // No home to expand against — fall back to literal.
    }

    if (path.size() == 1) {
        return home;
    }
    return home + path.substr(1);
}

util::Expected<void, std::string> validate_bootstrap_nodes(
    const std::vector<toxtunnel::BootstrapNodeConfig>& nodes) {
    for (const auto& node : nodes) {
        if (node.address.empty()) {
            return util::make_unexpected(std::string("Bootstrap node address cannot be empty"));
        }
        if (node.port == 0) {
            return util::make_unexpected(std::string("Bootstrap node port cannot be 0"));
        }
        if (node.public_key.length() != toxtunnel::tox::kPublicKeyHexLen) {
            return util::make_unexpected(std::string("Bootstrap node public key must be ") +
                                         std::to_string(toxtunnel::tox::kPublicKeyHexLen) +
                                         std::string(" characters, got ") +
                                         std::to_string(node.public_key.length()));
        }
        auto pk_result = toxtunnel::tox::parse_public_key(node.public_key);
        if (!pk_result) {
            return util::make_unexpected(std::string("Invalid bootstrap node public key: ") +
                                         pk_result.error());
        }
    }

    return {};
}

// SOCKS5 has no authentication in v1, so the listener must bind to a loopback
// address. Accepts: "localhost" (case-insensitive), any 127.0.0.0/8 address,
// or "::1". Anything else exposes an unauthenticated proxy on the LAN and is
// rejected at config-validation time.
bool is_loopback_host(const std::string& host) {
    if (host.empty()) {
        return false;
    }
    if (host == "::1") {
        return true;
    }
    if (host.size() >= 4 && host.compare(0, 4, "127.") == 0) {
        return true;
    }
    std::string lower;
    lower.reserve(host.size());
    for (char c : host) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lower == "localhost";
}

void sync_legacy_server_tox_fields(toxtunnel::Config& config) {
    if (!config.server.has_value()) {
        return;
    }

    config.server->tcp_port = config.tox.tcp_port;
    config.server->udp_enabled = config.tox.udp_enabled;
    config.server->bootstrap_nodes = config.tox.bootstrap_nodes;
}

}  // namespace

const std::error_category& config_error_category() noexcept {
    return g_config_error_category;
}

std::error_code make_error_code(ConfigError e) noexcept {
    return {static_cast<int>(e), config_error_category()};
}

// ---------------------------------------------------------------------------
// BootstrapNodeConfig
// ---------------------------------------------------------------------------

util::Expected<tox::BootstrapNode, std::string> BootstrapNodeConfig::to_bootstrap_node() const {
    tox::BootstrapNode node;
    node.ip = address;
    node.port = port;

    auto pk_result = tox::parse_public_key(public_key);
    if (!pk_result) {
        return util::make_unexpected(std::string("Invalid public key: ") + pk_result.error());
    }
    node.public_key = pk_result.value();

    return node;
}

util::Expected<PipeTarget, std::string> parse_pipe_target(std::string_view spec) {
    // Handle IPv6 addresses in bracket notation: [host]:port
    if (!spec.empty() && spec[0] == '[') {
        const auto bracket_end = spec.find(']');
        if (bracket_end == std::string_view::npos) {
            return util::make_unexpected(
                std::string("Invalid IPv6 address: missing closing bracket"));
        }
        if (bracket_end + 1 >= spec.size() || spec[bracket_end + 1] != ':') {
            return util::make_unexpected(
                std::string("Pipe target must be in the form [ipv6]:port"));
        }

        PipeTarget target;
        target.remote_host = std::string(spec.substr(1, bracket_end - 1));

        try {
            const auto port_str = std::string(spec.substr(bracket_end + 2));
            const auto parsed = std::stoul(port_str);
            if (parsed == 0 || parsed > 65535) {
                return util::make_unexpected(
                    std::string("Pipe target port must be between 1 and 65535"));
            }
            target.remote_port = static_cast<uint16_t>(parsed);
        } catch (const std::exception&) {
            return util::make_unexpected(std::string("Pipe target port must be numeric"));
        }

        return target;
    }

    // Handle IPv4 addresses and hostnames: host:port
    const auto colon = spec.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon == spec.size() - 1) {
        return util::make_unexpected(
            std::string("Pipe target must be in the form host:port or [ipv6]:port"));
    }

    PipeTarget target;
    target.remote_host = std::string(spec.substr(0, colon));

    try {
        const auto port_str = std::string(spec.substr(colon + 1));
        const auto parsed = std::stoul(port_str);
        if (parsed == 0 || parsed > 65535) {
            return util::make_unexpected(
                std::string("Pipe target port must be between 1 and 65535"));
        }
        target.remote_port = static_cast<uint16_t>(parsed);
    } catch (const std::exception&) {
        return util::make_unexpected(std::string("Pipe target port must be numeric"));
    }

    return target;
}

// ---------------------------------------------------------------------------
// Config factory methods
// ---------------------------------------------------------------------------

util::Expected<Config, std::string> Config::from_file(const std::filesystem::path& filepath) {
    if (!std::filesystem::exists(filepath)) {
        return util::make_unexpected(std::string("Configuration file not found: ") +
                                     filepath.string());
    }

    try {
        YAML::Node node = YAML::LoadFile(filepath.string());
        return node.as<Config>();
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("Failed to parse configuration: ") + e.what());
    }
}

util::Expected<Config, std::string> Config::from_string(std::string_view yaml_content) {
    try {
        YAML::Node node = YAML::Load(std::string(yaml_content));
        return node.as<Config>();
    } catch (const YAML::Exception& e) {
        return util::make_unexpected(std::string("Failed to parse configuration: ") + e.what());
    }
}

Config Config::default_server() {
    Config config;
    config.mode = Mode::Server;
    config.data_dir = "/var/lib/toxtunnel";
    // service.auto_start defaults to true at the struct level (see ServiceConfig);
    // do not override here so that YAML-loaded server configs without a `service:` section
    // pick up the same "server is online" default.
    config.server = ServerConfig{};
    sync_legacy_server_tox_fields(config);
    return config;
}

Config Config::default_client() {
    Config config;
    config.mode = Mode::Client;
    config.data_dir =
        std::filesystem::path(getenv("HOME") ? getenv("HOME") : ".") / ".config" / "toxtunnel";
    // ServiceConfig::auto_start defaults to true (server-oriented). Override to false here so
    // that a client config dumped via to_yaml() doesn't carry a misleading auto_start: true
    // (the field is ignored in client mode — should_run_as_service_daemon() reads
    // allow_client_daemon — but writing true would suggest otherwise).
    config.service.auto_start = false;
    config.client = ClientConfig{};
    return config;
}

ToxConfig Config::effective_tox_config() const {
    ToxConfig effective = tox;
    const ToxConfig defaults{};

    if (mode == Mode::Server && server.has_value()) {
        if (effective.tcp_port == defaults.tcp_port && server->tcp_port != defaults.tcp_port) {
            effective.tcp_port = server->tcp_port;
        }
        if (effective.udp_enabled == defaults.udp_enabled &&
            server->udp_enabled != defaults.udp_enabled) {
            effective.udp_enabled = server->udp_enabled;
        }
        if (effective.bootstrap_nodes.empty() && !server->bootstrap_nodes.empty()) {
            effective.bootstrap_nodes = server->bootstrap_nodes;
        }
    }

    return effective;
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

util::Expected<void, std::string> Config::validate() const {
    const ToxConfig effective_tox = effective_tox_config();

    // Validate mode
    if (mode != Mode::Server && mode != Mode::Client) {
        return util::make_unexpected(std::string("Invalid mode"));
    }

    auto bootstrap_validation = validate_bootstrap_nodes(effective_tox.bootstrap_nodes);
    if (!bootstrap_validation) {
        return bootstrap_validation;
    }

    if (metrics.enabled) {
        std::string host;
        uint16_t port = 0;
        if (!util::parse_listen_spec(metrics.listen, host, port)) {
            return util::make_unexpected(std::string("Invalid metrics.listen value: ") +
                                         metrics.listen);
        }
        if (metrics.path.empty() || metrics.path.front() != '/') {
            return util::make_unexpected(std::string("metrics.path must start with '/'"));
        }
    }

    if (effective_tox.bootstrap_mode == BootstrapMode::Lan && !effective_tox.udp_enabled) {
        return util::make_unexpected(
            std::string("LAN bootstrap mode requires tox.udp_enabled to be true"));
    }

    // Validate mode-specific configuration
    if (mode == Mode::Server) {
        if (!server) {
            return util::make_unexpected(
                std::string("Server configuration is required in server mode"));
        }

        // Validate TCP port
        if (effective_tox.tcp_port == 0) {
            return util::make_unexpected(std::string("TCP port cannot be 0"));
        }
    } else {  // Client mode
        if (!client) {
            return util::make_unexpected(
                std::string("Client configuration is required in client mode"));
        }

        // Validate server_id
        if (client->server_id.empty()) {
            return util::make_unexpected(std::string("Server ID is required in client mode"));
        }
        if (client->server_id.length() != tox::kToxIdHexLen) {
            return util::make_unexpected(
                std::string("Server ID must be ") + std::to_string(tox::kToxIdHexLen) +
                std::string(" characters, got ") + std::to_string(client->server_id.length()));
        }
        auto toxid_result = tox::ToxId::from_hex(client->server_id);
        if (!toxid_result) {
            return util::make_unexpected(std::string("Invalid server Tox ID: ") +
                                         toxid_result.error());
        }

        // Validate fallback server IDs (must already be resolved to 76-hex by
        // the alias-resolution step in main.cpp). Empty list is fine.
        for (const auto& fb : client->fallback_server_ids) {
            if (fb.empty()) {
                return util::make_unexpected(std::string("Fallback server ID cannot be empty"));
            }
            if (fb.length() != tox::kToxIdHexLen) {
                return util::make_unexpected(
                    std::string("Fallback server ID must be ") + std::to_string(tox::kToxIdHexLen) +
                    std::string(" characters, got ") + std::to_string(fb.length()));
            }
            auto fb_result = tox::ToxId::from_hex(fb);
            if (!fb_result) {
                return util::make_unexpected(std::string("Invalid fallback server Tox ID: ") +
                                             fb_result.error());
            }
            if (fb == client->server_id) {
                return util::make_unexpected(
                    std::string("Fallback server ID duplicates the primary server ID"));
            }
        }
        // Reject duplicates within the fallback list itself.
        for (std::size_t i = 0; i < client->fallback_server_ids.size(); ++i) {
            for (std::size_t j = i + 1; j < client->fallback_server_ids.size(); ++j) {
                if (client->fallback_server_ids[i] == client->fallback_server_ids[j]) {
                    return util::make_unexpected(std::string("Duplicate fallback server ID: ") +
                                                 client->fallback_server_ids[i]);
                }
            }
        }

        // Failover policy sanity (zero would never trigger a failover, which
        // defeats the point of listing fallbacks).
        if (!client->fallback_server_ids.empty()) {
            if (client->failover.timeout_seconds == 0) {
                return util::make_unexpected(
                    std::string("client.failover.timeout_seconds must be > 0 when "
                                "fallback servers are configured"));
            }
        }

        // Validate forwarding rules
        for (const auto& fwd : client->forwards) {
            if (fwd.local_port == 0) {
                return util::make_unexpected(std::string("Forward rule local_port cannot be 0"));
            }
            if (fwd.remote_host.empty()) {
                return util::make_unexpected(
                    std::string("Forward rule remote_host cannot be empty"));
            }
            if (fwd.remote_port == 0) {
                return util::make_unexpected(std::string("Forward rule remote_port cannot be 0"));
            }
        }

        if (client->pipe_target.has_value()) {
            if (client->pipe_target->remote_host.empty()) {
                return util::make_unexpected(
                    std::string("Pipe target remote_host cannot be empty"));
            }
            if (client->pipe_target->remote_port == 0) {
                return util::make_unexpected(std::string("Pipe target remote_port cannot be 0"));
            }
        }

        if (client->socks5.enabled) {
            std::string host;
            uint16_t s5_port = 0;
            if (!util::parse_listen_spec(client->socks5.listen, host, s5_port)) {
                return util::make_unexpected(std::string("Invalid client.socks5.listen value: ") +
                                             client->socks5.listen);
            }
            if (!is_loopback_host(host)) {
                return util::make_unexpected(
                    std::string("client.socks5.listen must bind to a loopback address "
                                "(127.0.0.0/8, ::1, or localhost); SOCKS5 v1 is unauthenticated. "
                                "Got: ") +
                    host);
            }
            if (client->pipe_target.has_value()) {
                return util::make_unexpected(
                    std::string("client.socks5.enabled and client.pipe cannot be used together"));
            }
        }
    }

    return {};
}

// ---------------------------------------------------------------------------
// Config operations
// ---------------------------------------------------------------------------

void Config::merge_cli_overrides(const Config& overrides) {
    // Override mode if set
    // (Always override mode since there's no "unset" state)

    // Override data_dir if non-empty
    if (!overrides.data_dir.empty()) {
        data_dir = overrides.data_dir;
    }

    // Override logging settings
    if (overrides.logging.level != util::LogLevel::Info || overrides.logging.file.has_value()) {
        if (overrides.logging.level != util::LogLevel::Info) {
            logging.level = overrides.logging.level;
        }
        if (overrides.logging.file.has_value()) {
            logging.file = overrides.logging.file;
        }
    }

    if (!overrides.tox.udp_enabled) {
        tox.udp_enabled = overrides.tox.udp_enabled;
    }
    if (overrides.tox.tcp_port != 33445) {
        tox.tcp_port = overrides.tox.tcp_port;
    }
    if (overrides.tox.bootstrap_mode != BootstrapMode::Auto) {
        tox.bootstrap_mode = overrides.tox.bootstrap_mode;
    }
    if (!overrides.tox.bootstrap_nodes.empty()) {
        tox.bootstrap_nodes = overrides.tox.bootstrap_nodes;
    }

    // Handle mode change
    if (overrides.mode != mode) {
        mode = overrides.mode;
        if (mode == Mode::Server && !server) {
            server = ServerConfig{};
            client.reset();
        } else if (mode == Mode::Client && !client) {
            client = ClientConfig{};
            server.reset();
        }
    }

    // Merge server overrides
    if (overrides.server && server) {
        if (overrides.server->tcp_port != 33445) {
            server->tcp_port = overrides.server->tcp_port;
            tox.tcp_port = overrides.server->tcp_port;
        }
        if (!overrides.server->udp_enabled) {
            server->udp_enabled = overrides.server->udp_enabled;
            tox.udp_enabled = overrides.server->udp_enabled;
        }
        if (!overrides.server->bootstrap_nodes.empty()) {
            server->bootstrap_nodes = overrides.server->bootstrap_nodes;
            tox.bootstrap_nodes = overrides.server->bootstrap_nodes;
        }
        if (overrides.server->rules_file.has_value()) {
            server->rules_file = overrides.server->rules_file;
        }
    }

    // Merge client overrides
    if (overrides.client && client) {
        if (!overrides.client->server_id.empty()) {
            client->server_id = overrides.client->server_id;
        }
        if (!overrides.client->fallback_server_ids.empty()) {
            // CLI replaces the YAML list rather than appending — same
            // policy as forwards and bootstrap_nodes above.
            client->fallback_server_ids = overrides.client->fallback_server_ids;
        }
        if (!overrides.client->forwards.empty()) {
            client->forwards = overrides.client->forwards;
        }
        if (overrides.client->pipe_target.has_value()) {
            client->pipe_target = overrides.client->pipe_target;
        }
        if (!(overrides.client->socks5 == Socks5Config{})) {
            client->socks5 = overrides.client->socks5;
        }
    }

    sync_legacy_server_tox_fields(*this);
}

// Helper function to encode LogLevel to string
static const char* log_level_to_string(util::LogLevel level) {
    switch (level) {
        case util::LogLevel::Trace:
            return "trace";
        case util::LogLevel::Debug:
            return "debug";
        case util::LogLevel::Info:
            return "info";
        case util::LogLevel::Warn:
            return "warn";
        case util::LogLevel::Error:
            return "error";
        case util::LogLevel::Critical:
            return "critical";
        case util::LogLevel::Off:
            return "off";
        default:
            return "info";
    }
}

std::string Config::to_yaml() const {
    const ToxConfig effective_tox = effective_tox_config();

    YAML::Emitter out;
    out << YAML::BeginMap;

    // Mode
    out << YAML::Key << "mode" << YAML::Value << (mode == Mode::Server ? "server" : "client");

    // Data directory
    out << YAML::Key << "data_dir" << YAML::Value << data_dir.string();

    // Logging
    out << YAML::Key << "logging";
    out << YAML::BeginMap;
    out << YAML::Key << "level" << YAML::Value << log_level_to_string(logging.level);
    if (logging.file) {
        out << YAML::Key << "file" << YAML::Value << *logging.file;
    }
    out << YAML::EndMap;

    out << YAML::Key << "service";
    out << YAML::BeginMap;
    out << YAML::Key << "auto_start" << YAML::Value << service.auto_start;
    out << YAML::Key << "allow_client_daemon" << YAML::Value << service.allow_client_daemon;
    out << YAML::EndMap;

    if (metrics != MetricsConfig{}) {
        out << YAML::Key << "metrics";
        out << YAML::BeginMap;
        out << YAML::Key << "enabled" << YAML::Value << metrics.enabled;
        out << YAML::Key << "listen" << YAML::Value << metrics.listen;
        out << YAML::Key << "path" << YAML::Value << metrics.path;
        out << YAML::EndMap;
    }

    out << YAML::Key << "tox" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "udp_enabled" << YAML::Value << effective_tox.udp_enabled;
    out << YAML::Key << "tcp_port" << YAML::Value << effective_tox.tcp_port;
    out << YAML::Key << "bootstrap_mode" << YAML::Value
        << bootstrap_mode_to_string(effective_tox.bootstrap_mode);
    if (!effective_tox.bootstrap_nodes.empty()) {
        out << YAML::Key << "bootstrap_nodes";
        out << YAML::BeginSeq;
        for (const auto& node : effective_tox.bootstrap_nodes) {
            out << YAML::BeginMap;
            out << YAML::Key << "address" << YAML::Value << node.address;
            out << YAML::Key << "port" << YAML::Value << node.port;
            out << YAML::Key << "public_key" << YAML::Value << node.public_key;
            out << YAML::EndMap;
        }
        out << YAML::EndSeq;
    }
    out << YAML::EndMap;

    // Server config
    if (server) {
        out << YAML::Key << "server" << YAML::Value << YAML::BeginMap;
        if (server->rules_file) {
            out << YAML::Key << "rules_file" << YAML::Value << *server->rules_file;
        }
        if (server->disclose.any()) {
            out << YAML::Key << "disclose" << YAML::Value << YAML::BeginMap;
            out << YAML::Key << "hostname" << YAML::Value << server->disclose.hostname;
            out << YAML::Key << "os" << YAML::Value << server->disclose.os;
            out << YAML::Key << "os_version" << YAML::Value << server->disclose.os_version;
            out << YAML::Key << "arch" << YAML::Value << server->disclose.arch;
            out << YAML::Key << "uptime" << YAML::Value << server->disclose.uptime;
            out << YAML::Key << "toxtunnel_version" << YAML::Value
                << server->disclose.toxtunnel_version;
            out << YAML::EndMap;
        }
        out << YAML::EndMap;
    }

    // Client config
    if (client) {
        out << YAML::Key << "client" << YAML::Value << YAML::BeginMap;
        if (!client->server_id.empty()) {
            if (!client->fallback_server_ids.empty()) {
                out << YAML::Key << "server_id" << YAML::Value << YAML::BeginSeq;
                out << client->server_id;
                for (const auto& fb : client->fallback_server_ids) {
                    out << fb;
                }
                out << YAML::EndSeq;
            } else {
                out << YAML::Key << "server_id" << YAML::Value << client->server_id;
            }
        }
        {
            const FailoverConfig defaults{};
            if (!(client->failover == defaults)) {
                out << YAML::Key << "failover" << YAML::Value << YAML::BeginMap;
                out << YAML::Key << "timeout_seconds" << YAML::Value
                    << client->failover.timeout_seconds;
                out << YAML::Key << "prefer_primary_grace_seconds" << YAML::Value
                    << client->failover.prefer_primary_grace_seconds;
                out << YAML::EndMap;
            }
        }
        if (client->pipe_target.has_value()) {
            out << YAML::Key << "pipe" << YAML::Value << YAML::BeginMap;
            out << YAML::Key << "remote_host" << YAML::Value << client->pipe_target->remote_host;
            out << YAML::Key << "remote_port" << YAML::Value << client->pipe_target->remote_port;
            out << YAML::EndMap;
        }
        if (!client->forwards.empty()) {
            out << YAML::Key << "forwards";
            out << YAML::BeginSeq;
            for (const auto& fwd : client->forwards) {
                out << YAML::BeginMap;
                out << YAML::Key << "local_port" << YAML::Value << fwd.local_port;
                out << YAML::Key << "remote_host" << YAML::Value << fwd.remote_host;
                out << YAML::Key << "remote_port" << YAML::Value << fwd.remote_port;
                out << YAML::EndMap;
            }
            out << YAML::EndSeq;
        }
        if (!(client->socks5 == Socks5Config{})) {
            out << YAML::Key << "socks5" << YAML::Value << YAML::BeginMap;
            out << YAML::Key << "enabled" << YAML::Value << client->socks5.enabled;
            out << YAML::Key << "listen" << YAML::Value << client->socks5.listen;
            out << YAML::EndMap;
        }
        out << YAML::EndMap;
    }

    out << YAML::EndMap;
    return out.c_str();
}

util::Expected<void, std::string> Config::save(const std::filesystem::path& filepath) const {
    try {
        std::ofstream ofs(filepath);
        if (!ofs) {
            return util::make_unexpected(std::string("Failed to open file for writing: ") +
                                         filepath.string());
        }
        ofs << to_yaml();
        return {};
    } catch (const std::exception& e) {
        return util::make_unexpected(std::string("Failed to save config: ") + e.what());
    }
}

// ---------------------------------------------------------------------------
// Config accessors
// ---------------------------------------------------------------------------

const ServerConfig& Config::server_config() const {
    if (!server) {
        throw std::runtime_error("Not in server mode");
    }
    return *server;
}

const ClientConfig& Config::client_config() const {
    if (!client) {
        throw std::runtime_error("Not in client mode");
    }
    return *client;
}

bool Config::should_run_as_service_daemon() const {
    if (mode == Mode::Client) {
        return service.allow_client_daemon;
    }
    return service.auto_start;
}

}  // namespace toxtunnel

// ---------------------------------------------------------------------------
// YAML encoding/decoding implementations
// ---------------------------------------------------------------------------

namespace YAML {

using toxtunnel::BootstrapNodeConfig;
using toxtunnel::ClientConfig;
using toxtunnel::Config;
using toxtunnel::ForwardRule;
using toxtunnel::LoggingConfig;
using toxtunnel::MetricsConfig;
using toxtunnel::Mode;
using toxtunnel::PipeTarget;
using toxtunnel::ServerConfig;
using toxtunnel::ServiceConfig;
using toxtunnel::Socks5Config;
using toxtunnel::ToxConfig;
using toxtunnel::tox::BootstrapMode;
using toxtunnel::tox::kPublicKeyHexLen;

// ---------------------------------------------------------------------------
// PipeTarget
// ---------------------------------------------------------------------------

Node convert<PipeTarget>::encode(const PipeTarget& rhs) {
    Node node;
    node["remote_host"] = rhs.remote_host;
    node["remote_port"] = rhs.remote_port;
    return node;
}

bool convert<PipeTarget>::decode(const Node& node, PipeTarget& rhs) {
    if (node.IsScalar()) {
        auto result = toxtunnel::parse_pipe_target(node.as<std::string>());
        if (!result) {
            return false;
        }
        rhs = result.value();
        return true;
    }

    if (!node.IsMap()) {
        return false;
    }

    if (!node["remote_host"] || !node["remote_port"]) {
        return false;
    }

    rhs.remote_host = node["remote_host"].as<std::string>();
    rhs.remote_port = node["remote_port"].as<uint16_t>();
    return true;
}

// ---------------------------------------------------------------------------
// ForwardRule
// ---------------------------------------------------------------------------

Node convert<ForwardRule>::encode(const ForwardRule& rhs) {
    Node node;
    node["local_port"] = rhs.local_port;
    node["remote_host"] = rhs.remote_host;
    node["remote_port"] = rhs.remote_port;
    return node;
}

bool convert<ForwardRule>::decode(const Node& node, ForwardRule& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (!node["local_port"]) {
        return false;
    }
    rhs.local_port = node["local_port"].as<uint16_t>();

    if (!node["remote_host"]) {
        return false;
    }
    rhs.remote_host = node["remote_host"].as<std::string>();

    if (!node["remote_port"]) {
        return false;
    }
    rhs.remote_port = node["remote_port"].as<uint16_t>();

    return true;
}

// ---------------------------------------------------------------------------
// BootstrapNodeConfig
// ---------------------------------------------------------------------------

Node convert<BootstrapNodeConfig>::encode(const BootstrapNodeConfig& rhs) {
    Node node;
    node["address"] = rhs.address;
    node["port"] = rhs.port;
    node["public_key"] = rhs.public_key;
    return node;
}

bool convert<BootstrapNodeConfig>::decode(const Node& node, BootstrapNodeConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (!node["address"]) {
        return false;
    }
    rhs.address = node["address"].as<std::string>();

    rhs.port = node["port"] ? node["port"].as<uint16_t>() : 33445;

    if (!node["public_key"]) {
        return false;
    }
    rhs.public_key = node["public_key"].as<std::string>();

    return true;
}

// ---------------------------------------------------------------------------
// LoggingConfig
// ---------------------------------------------------------------------------

Node convert<BootstrapMode>::encode(const BootstrapMode& rhs) {
    return Node(toxtunnel::bootstrap_mode_to_string(rhs));
}

bool convert<BootstrapMode>::decode(const Node& node, BootstrapMode& rhs) {
    if (!node.IsScalar()) {
        return false;
    }

    auto str = node.as<std::string>();
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    if (str == "auto") {
        rhs = BootstrapMode::Auto;
        return true;
    }
    if (str == "lan") {
        rhs = BootstrapMode::Lan;
        return true;
    }

    return false;
}

Node convert<ToxConfig>::encode(const ToxConfig& rhs) {
    Node node;
    node["udp_enabled"] = rhs.udp_enabled;
    node["tcp_port"] = rhs.tcp_port;
    node["bootstrap_mode"] = rhs.bootstrap_mode;
    if (!rhs.bootstrap_nodes.empty()) {
        node["bootstrap_nodes"] = rhs.bootstrap_nodes;
    }
    return node;
}

bool convert<ToxConfig>::decode(const Node& node, ToxConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (node["udp_enabled"]) {
        rhs.udp_enabled = node["udp_enabled"].as<bool>();
    }
    if (node["tcp_port"]) {
        rhs.tcp_port = node["tcp_port"].as<uint16_t>();
    }
    if (node["bootstrap_mode"]) {
        rhs.bootstrap_mode = node["bootstrap_mode"].as<BootstrapMode>();
    }
    if (node["bootstrap_nodes"]) {
        rhs.bootstrap_nodes = node["bootstrap_nodes"].as<std::vector<BootstrapNodeConfig>>();
    }

    return true;
}

Node convert<LoggingConfig>::encode(const LoggingConfig& rhs) {
    Node node;
    node["level"] = convert<toxtunnel::util::LogLevel>::encode(rhs.level);
    if (rhs.file) {
        node["file"] = *rhs.file;
    }
    return node;
}

bool convert<LoggingConfig>::decode(const Node& node, LoggingConfig& rhs) {
    if (!node.IsMap()) {
        // Allow scalar "level" for logging
        if (node.IsScalar()) {
            rhs.level = node.as<toxtunnel::util::LogLevel>();
            return true;
        }
        return false;
    }

    if (node["level"]) {
        rhs.level = node["level"].as<toxtunnel::util::LogLevel>();
    }

    if (node["file"]) {
        rhs.file = toxtunnel::expand_user_path(node["file"].as<std::string>());
    }

    return true;
}

// ---------------------------------------------------------------------------
// ServiceConfig
// ---------------------------------------------------------------------------

Node convert<ServiceConfig>::encode(const ServiceConfig& rhs) {
    Node node;
    node["auto_start"] = rhs.auto_start;
    node["allow_client_daemon"] = rhs.allow_client_daemon;
    return node;
}

bool convert<ServiceConfig>::decode(const Node& node, ServiceConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }
    if (node["auto_start"]) {
        rhs.auto_start = node["auto_start"].as<bool>();
    }
    if (node["allow_client_daemon"]) {
        rhs.allow_client_daemon = node["allow_client_daemon"].as<bool>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// MetricsConfig
// ---------------------------------------------------------------------------

Node convert<MetricsConfig>::encode(const MetricsConfig& rhs) {
    Node node;
    node["enabled"] = rhs.enabled;
    node["listen"] = rhs.listen;
    node["path"] = rhs.path;
    return node;
}

bool convert<MetricsConfig>::decode(const Node& node, MetricsConfig& rhs) {
    if (node.IsScalar()) {
        try {
            rhs.enabled = node.as<bool>();
            return true;
        } catch (const YAML::Exception&) {
            return false;
        }
    }
    if (!node.IsMap()) {
        return false;
    }
    if (node["enabled"]) {
        rhs.enabled = node["enabled"].as<bool>();
    }
    if (node["listen"]) {
        rhs.listen = node["listen"].as<std::string>();
    }
    if (node["path"]) {
        rhs.path = node["path"].as<std::string>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// InspectConfig
// ---------------------------------------------------------------------------

Node convert<toxtunnel::InspectConfig>::encode(const toxtunnel::InspectConfig& rhs) {
    Node node;
    node["enabled"] = rhs.enabled;
    return node;
}

bool convert<toxtunnel::InspectConfig>::decode(const Node& node, toxtunnel::InspectConfig& rhs) {
    if (node.IsScalar()) {
        try {
            rhs.enabled = node.as<bool>();
            return true;
        } catch (const YAML::Exception&) {
            return false;
        }
    }
    if (!node.IsMap()) {
        return false;
    }
    if (node["enabled"]) {
        rhs.enabled = node["enabled"].as<bool>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// TunnelConfig
// ---------------------------------------------------------------------------

Node convert<toxtunnel::TunnelConfig>::encode(const toxtunnel::TunnelConfig& rhs) {
    Node node;
    node["coalesce_max_delay_us"] = rhs.coalesce_max_delay_us;
    node["coalesce_max_bytes"] = rhs.coalesce_max_bytes;
    node["coalesce_mode"] = rhs.coalesce_mode;
    node["idle_timeout_seconds"] = rhs.idle_timeout_seconds;
    node["reaper_tick_seconds"] = rhs.reaper_tick_seconds;
    return node;
}

bool convert<toxtunnel::TunnelConfig>::decode(const Node& node, toxtunnel::TunnelConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }
    if (node["coalesce_max_delay_us"]) {
        rhs.coalesce_max_delay_us = node["coalesce_max_delay_us"].as<uint32_t>();
    }
    if (node["coalesce_max_bytes"]) {
        rhs.coalesce_max_bytes = node["coalesce_max_bytes"].as<uint32_t>();
    }
    if (node["coalesce_mode"]) {
        rhs.coalesce_mode = node["coalesce_mode"].as<std::string>();
    }
    if (node["idle_timeout_seconds"]) {
        rhs.idle_timeout_seconds = node["idle_timeout_seconds"].as<uint32_t>();
    }
    if (node["reaper_tick_seconds"]) {
        rhs.reaper_tick_seconds = node["reaper_tick_seconds"].as<uint32_t>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// FlowControlConfig
// ---------------------------------------------------------------------------

Node convert<toxtunnel::FlowControlConfig>::encode(const toxtunnel::FlowControlConfig& rhs) {
    Node node;
    node["mode"] = rhs.mode;
    node["send_window_min_bytes"] = rhs.send_window_min_bytes;
    node["send_window_max_bytes"] = rhs.send_window_max_bytes;
    node["safety_factor_x100"] = rhs.safety_factor_x100;
    node["fixed_window_bytes"] = rhs.fixed_window_bytes;
    return node;
}

bool convert<toxtunnel::FlowControlConfig>::decode(const Node& node,
                                                   toxtunnel::FlowControlConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }
    if (node["mode"]) {
        rhs.mode = node["mode"].as<std::string>();
    }
    if (node["send_window_min_bytes"]) {
        rhs.send_window_min_bytes = node["send_window_min_bytes"].as<uint32_t>();
    }
    if (node["send_window_max_bytes"]) {
        rhs.send_window_max_bytes = node["send_window_max_bytes"].as<uint32_t>();
    }
    if (node["safety_factor_x100"]) {
        rhs.safety_factor_x100 = node["safety_factor_x100"].as<uint32_t>();
    }
    if (node["fixed_window_bytes"]) {
        rhs.fixed_window_bytes = node["fixed_window_bytes"].as<uint32_t>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// WatchdogConfig
// ---------------------------------------------------------------------------

Node convert<toxtunnel::WatchdogConfig>::encode(const toxtunnel::WatchdogConfig& rhs) {
    Node node;
    node["enabled"] = rhs.enabled;
    node["deadline_seconds"] = rhs.deadline_seconds;
    node["systemd_notify"] = rhs.systemd_notify;
    return node;
}

bool convert<toxtunnel::WatchdogConfig>::decode(const Node& node, toxtunnel::WatchdogConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }
    if (node["enabled"])
        rhs.enabled = node["enabled"].as<bool>();
    if (node["deadline_seconds"])
        rhs.deadline_seconds = node["deadline_seconds"].as<uint32_t>();
    if (node["systemd_notify"])
        rhs.systemd_notify = node["systemd_notify"].as<bool>();
    return true;
}

// ---------------------------------------------------------------------------
// ServerInfoDisclose
// ---------------------------------------------------------------------------

Node convert<toxtunnel::ServerInfoDisclose>::encode(const toxtunnel::ServerInfoDisclose& rhs) {
    Node node;
    node["hostname"] = rhs.hostname;
    node["os"] = rhs.os;
    node["os_version"] = rhs.os_version;
    node["arch"] = rhs.arch;
    node["uptime"] = rhs.uptime;
    node["toxtunnel_version"] = rhs.toxtunnel_version;
    return node;
}

bool convert<toxtunnel::ServerInfoDisclose>::decode(const Node& node,
                                                    toxtunnel::ServerInfoDisclose& rhs) {
    if (node.IsScalar()) {
        // Convenience: `disclose: false` / `disclose: true` as a global
        // toggle that flips every field at once. Explicit per-field maps
        // are still preferred for production use; this is only a shorthand.
        bool flag = false;
        try {
            flag = node.as<bool>();
        } catch (const YAML::Exception&) {
            return false;
        }
        rhs.hostname = flag;
        rhs.os = flag;
        rhs.os_version = flag;
        rhs.arch = flag;
        rhs.uptime = flag;
        rhs.toxtunnel_version = flag;
        return true;
    }
    if (!node.IsMap()) {
        return false;
    }
    if (node["hostname"])
        rhs.hostname = node["hostname"].as<bool>();
    if (node["os"])
        rhs.os = node["os"].as<bool>();
    if (node["os_version"])
        rhs.os_version = node["os_version"].as<bool>();
    if (node["arch"])
        rhs.arch = node["arch"].as<bool>();
    if (node["uptime"])
        rhs.uptime = node["uptime"].as<bool>();
    if (node["toxtunnel_version"])
        rhs.toxtunnel_version = node["toxtunnel_version"].as<bool>();
    return true;
}

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

Node convert<ServerConfig>::encode(const ServerConfig& rhs) {
    Node node;
    node["tcp_port"] = rhs.tcp_port;
    node["udp_enabled"] = rhs.udp_enabled;
    if (!rhs.bootstrap_nodes.empty()) {
        node["bootstrap_nodes"] = rhs.bootstrap_nodes;
    }
    if (rhs.rules_file) {
        node["rules_file"] = *rhs.rules_file;
    }
    if (rhs.disclose.any()) {
        node["disclose"] = rhs.disclose;
    }
    return node;
}

bool convert<ServerConfig>::decode(const Node& node, ServerConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (node["tcp_port"]) {
        rhs.tcp_port = node["tcp_port"].as<uint16_t>();
    }

    if (node["udp_enabled"]) {
        rhs.udp_enabled = node["udp_enabled"].as<bool>();
    }

    if (node["bootstrap_nodes"]) {
        rhs.bootstrap_nodes = node["bootstrap_nodes"].as<std::vector<BootstrapNodeConfig>>();
    }

    if (node["rules_file"]) {
        rhs.rules_file = toxtunnel::expand_user_path(node["rules_file"].as<std::string>());
    }

    if (node["disclose"]) {
        rhs.disclose = node["disclose"].as<toxtunnel::ServerInfoDisclose>();
    }

    return true;
}

// ---------------------------------------------------------------------------
// Socks5Config
// ---------------------------------------------------------------------------

Node convert<toxtunnel::Socks5Config>::encode(const toxtunnel::Socks5Config& rhs) {
    Node node;
    node["enabled"] = rhs.enabled;
    node["listen"] = rhs.listen;
    return node;
}

bool convert<toxtunnel::Socks5Config>::decode(const Node& node, toxtunnel::Socks5Config& rhs) {
    if (node.IsScalar()) {
        try {
            rhs.enabled = node.as<bool>();
            return true;
        } catch (const YAML::Exception&) {
            return false;
        }
    }
    if (!node.IsMap()) {
        return false;
    }
    if (node["enabled"]) {
        rhs.enabled = node["enabled"].as<bool>();
    }
    if (node["listen"]) {
        rhs.listen = node["listen"].as<std::string>();
    }
    return true;
}

// ---------------------------------------------------------------------------
// ClientConfig
// ---------------------------------------------------------------------------

Node convert<ClientConfig>::encode(const ClientConfig& rhs) {
    Node node;
    // Emit as a list only when there are fallbacks, otherwise stay
    // backwards-compatible with the simple string form.
    if (!rhs.fallback_server_ids.empty()) {
        Node ids(NodeType::Sequence);
        ids.push_back(rhs.server_id);
        for (const auto& fb : rhs.fallback_server_ids) {
            ids.push_back(fb);
        }
        node["server_id"] = ids;
    } else {
        node["server_id"] = rhs.server_id;
    }
    if (rhs.pipe_target.has_value()) {
        node["pipe"] = *rhs.pipe_target;
    }
    if (!rhs.forwards.empty()) {
        node["forwards"] = rhs.forwards;
    }
    // Only emit failover block when it differs from defaults.
    const toxtunnel::FailoverConfig defaults{};
    if (!(rhs.failover == defaults)) {
        Node fo;
        fo["timeout_seconds"] = rhs.failover.timeout_seconds;
        fo["prefer_primary_grace_seconds"] = rhs.failover.prefer_primary_grace_seconds;
        node["failover"] = fo;
    }
    if (!(rhs.socks5 == toxtunnel::Socks5Config{})) {
        node["socks5"] = rhs.socks5;
    }
    return node;
}

bool convert<ClientConfig>::decode(const Node& node, ClientConfig& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    if (node["server_id"]) {
        const auto& sid_node = node["server_id"];
        if (sid_node.IsSequence()) {
            // List form: first entry is primary, rest are fallbacks.
            rhs.server_id.clear();
            rhs.fallback_server_ids.clear();
            for (const auto& item : sid_node) {
                auto s = item.as<std::string>();
                if (rhs.server_id.empty()) {
                    rhs.server_id = std::move(s);
                } else {
                    rhs.fallback_server_ids.push_back(std::move(s));
                }
            }
        } else {
            rhs.server_id = sid_node.as<std::string>();
        }
    }

    if (node["pipe"]) {
        rhs.pipe_target = node["pipe"].as<PipeTarget>();
    }

    if (node["forwards"]) {
        rhs.forwards = node["forwards"].as<std::vector<ForwardRule>>();
    }

    if (node["failover"] && node["failover"].IsMap()) {
        const auto& fo = node["failover"];
        if (fo["timeout_seconds"]) {
            rhs.failover.timeout_seconds = fo["timeout_seconds"].as<uint32_t>();
        }
        if (fo["prefer_primary_grace_seconds"]) {
            rhs.failover.prefer_primary_grace_seconds =
                fo["prefer_primary_grace_seconds"].as<uint32_t>();
        }
    }

    if (node["socks5"]) {
        rhs.socks5 = node["socks5"].as<toxtunnel::Socks5Config>();
    }

    return true;
}

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

Node convert<Mode>::encode(const Mode& rhs) {
    return Node(rhs == Mode::Server ? "server" : "client");
}

bool convert<Mode>::decode(const Node& node, Mode& rhs) {
    if (!node.IsScalar()) {
        return false;
    }

    auto str = node.as<std::string>();
    if (str == "server") {
        rhs = Mode::Server;
        return true;
    } else if (str == "client") {
        rhs = Mode::Client;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// LogLevel
// ---------------------------------------------------------------------------

Node convert<toxtunnel::util::LogLevel>::encode(const toxtunnel::util::LogLevel& rhs) {
    switch (rhs) {
        case toxtunnel::util::LogLevel::Trace:
            return Node("trace");
        case toxtunnel::util::LogLevel::Debug:
            return Node("debug");
        case toxtunnel::util::LogLevel::Info:
            return Node("info");
        case toxtunnel::util::LogLevel::Warn:
            return Node("warn");
        case toxtunnel::util::LogLevel::Error:
            return Node("error");
        case toxtunnel::util::LogLevel::Critical:
            return Node("critical");
        case toxtunnel::util::LogLevel::Off:
            return Node("off");
        default:
            return Node("info");
    }
}

bool convert<toxtunnel::util::LogLevel>::decode(const Node& node, toxtunnel::util::LogLevel& rhs) {
    if (!node.IsScalar()) {
        return false;
    }

    auto str = node.as<std::string>();
    // Case-insensitive comparison
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);

    if (str == "trace") {
        rhs = toxtunnel::util::LogLevel::Trace;
    } else if (str == "debug") {
        rhs = toxtunnel::util::LogLevel::Debug;
    } else if (str == "info") {
        rhs = toxtunnel::util::LogLevel::Info;
    } else if (str == "warn" || str == "warning") {
        rhs = toxtunnel::util::LogLevel::Warn;
    } else if (str == "error") {
        rhs = toxtunnel::util::LogLevel::Error;
    } else if (str == "critical") {
        rhs = toxtunnel::util::LogLevel::Critical;
    } else if (str == "off") {
        rhs = toxtunnel::util::LogLevel::Off;
    } else {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

Node convert<Config>::encode(const Config& rhs) {
    Node node;
    const auto effective_tox = rhs.effective_tox_config();
    node["mode"] = rhs.mode;
    node["data_dir"] = rhs.data_dir.string();
    node["logging"] = rhs.logging;
    node["service"] = rhs.service;
    if (rhs.metrics != toxtunnel::MetricsConfig{}) {
        node["metrics"] = rhs.metrics;
    }
    node["tox"] = effective_tox;
    if (rhs.metrics.enabled || rhs.metrics.listen != MetricsConfig{}.listen ||
        rhs.metrics.path != MetricsConfig{}.path) {
        node["metrics"] = rhs.metrics;
    }
    if (!(rhs.tunnel == toxtunnel::TunnelConfig{})) {
        node["tunnel"] = rhs.tunnel;
    }
    if (!(rhs.flow_control == toxtunnel::FlowControlConfig{})) {
        node["flow_control"] = rhs.flow_control;
    }
    if (!(rhs.watchdog == toxtunnel::WatchdogConfig{})) {
        node["watchdog"] = rhs.watchdog;
    }

    if (rhs.server) {
        Node server_node;
        if (rhs.server->rules_file) {
            server_node["rules_file"] = *rhs.server->rules_file;
        }
        node["server"] = std::move(server_node);
    }

    if (rhs.client) {
        Node client_node;
        if (!rhs.client->server_id.empty()) {
            if (!rhs.client->fallback_server_ids.empty()) {
                Node ids(NodeType::Sequence);
                ids.push_back(rhs.client->server_id);
                for (const auto& fb : rhs.client->fallback_server_ids) {
                    ids.push_back(fb);
                }
                client_node["server_id"] = ids;
            } else {
                client_node["server_id"] = rhs.client->server_id;
            }
        }
        const toxtunnel::FailoverConfig defaults{};
        if (!(rhs.client->failover == defaults)) {
            Node fo;
            fo["timeout_seconds"] = rhs.client->failover.timeout_seconds;
            fo["prefer_primary_grace_seconds"] = rhs.client->failover.prefer_primary_grace_seconds;
            client_node["failover"] = fo;
        }
        if (rhs.client->pipe_target.has_value()) {
            client_node["pipe"] = *rhs.client->pipe_target;
        }
        if (!rhs.client->forwards.empty()) {
            client_node["forwards"] = rhs.client->forwards;
        }
        if (!(rhs.client->socks5 == toxtunnel::Socks5Config{})) {
            client_node["socks5"] = rhs.client->socks5;
        }
        node["client"] = std::move(client_node);
    }

    return node;
}

bool convert<Config>::decode(const Node& node, Config& rhs) {
    if (!node.IsMap()) {
        return false;
    }

    // Mode is required
    if (!node["mode"]) {
        return false;
    }
    rhs.mode = node["mode"].as<Mode>();

    // Data directory
    if (node["data_dir"]) {
        rhs.data_dir = toxtunnel::expand_user_path(node["data_dir"].as<std::string>());
    }

    // Logging
    if (node["logging"]) {
        rhs.logging = node["logging"].as<LoggingConfig>();
    }

    if (node["service"]) {
        rhs.service = node["service"].as<ServiceConfig>();
    }

    if (node["metrics"]) {
        rhs.metrics = node["metrics"].as<toxtunnel::MetricsConfig>();
    }

    if (node["tox"]) {
        rhs.tox = node["tox"].as<ToxConfig>();
    }

    if (node["metrics"]) {
        rhs.metrics = node["metrics"].as<MetricsConfig>();
    }

    if (node["tunnel"]) {
        rhs.tunnel = node["tunnel"].as<toxtunnel::TunnelConfig>();
    }

    if (node["flow_control"]) {
        rhs.flow_control = node["flow_control"].as<toxtunnel::FlowControlConfig>();
    }

    if (node["watchdog"]) {
        rhs.watchdog = node["watchdog"].as<toxtunnel::WatchdogConfig>();
    }

    // Mode-specific config
    if (rhs.mode == Mode::Server) {
        rhs.server = ServerConfig{};
        const Node server_node = node["server"] ? node["server"] : node;
        const bool has_canonical_tox = node["tox"] && node["tox"].IsMap();

        if (server_node["rules_file"]) {
            rhs.server->rules_file =
                toxtunnel::expand_user_path(server_node["rules_file"].as<std::string>());
        }

        if (server_node["disclose"]) {
            rhs.server->disclose = server_node["disclose"].as<toxtunnel::ServerInfoDisclose>();
        }

        if (!has_canonical_tox) {
            if (server_node["tcp_port"]) {
                rhs.tox.tcp_port = server_node["tcp_port"].as<uint16_t>();
            } else if (node["tcp_port"]) {
                rhs.tox.tcp_port = node["tcp_port"].as<uint16_t>();
            }

            if (server_node["udp_enabled"]) {
                rhs.tox.udp_enabled = server_node["udp_enabled"].as<bool>();
            } else if (node["udp_enabled"]) {
                rhs.tox.udp_enabled = node["udp_enabled"].as<bool>();
            }

            if (server_node["bootstrap_nodes"]) {
                rhs.tox.bootstrap_nodes =
                    server_node["bootstrap_nodes"].as<std::vector<BootstrapNodeConfig>>();
            } else if (node["bootstrap_nodes"]) {
                rhs.tox.bootstrap_nodes =
                    node["bootstrap_nodes"].as<std::vector<BootstrapNodeConfig>>();
            }
        }

        toxtunnel::sync_legacy_server_tox_fields(rhs);
    } else {  // Client mode
        rhs.client = ClientConfig{};
        const Node client_node = node["client"] ? node["client"] : node;

        if (client_node["server_id"]) {
            const auto& sid_node = client_node["server_id"];
            if (sid_node.IsSequence()) {
                rhs.client->server_id.clear();
                rhs.client->fallback_server_ids.clear();
                for (const auto& item : sid_node) {
                    auto s = item.as<std::string>();
                    if (rhs.client->server_id.empty()) {
                        rhs.client->server_id = std::move(s);
                    } else {
                        rhs.client->fallback_server_ids.push_back(std::move(s));
                    }
                }
            } else {
                rhs.client->server_id = sid_node.as<std::string>();
            }
        }

        if (client_node["pipe"]) {
            rhs.client->pipe_target = client_node["pipe"].as<PipeTarget>();
        }

        if (client_node["forwards"]) {
            rhs.client->forwards = client_node["forwards"].as<std::vector<ForwardRule>>();
        }

        if (client_node["failover"] && client_node["failover"].IsMap()) {
            const auto& fo = client_node["failover"];
            if (fo["timeout_seconds"]) {
                rhs.client->failover.timeout_seconds = fo["timeout_seconds"].as<uint32_t>();
            }
            if (fo["prefer_primary_grace_seconds"]) {
                rhs.client->failover.prefer_primary_grace_seconds =
                    fo["prefer_primary_grace_seconds"].as<uint32_t>();
            }
        }

        if (client_node["socks5"]) {
            rhs.client->socks5 = client_node["socks5"].as<toxtunnel::Socks5Config>();
        }
    }

    return true;
}

}  // namespace YAML
