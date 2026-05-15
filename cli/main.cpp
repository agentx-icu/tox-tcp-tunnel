#include <CLI/CLI.hpp>
#include <asio.hpp>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include "toxtunnel/app/known_servers.hpp"
#include "toxtunnel/app/tunnel_client.hpp"
#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/qr_code.hpp"
#include "toxtunnel/util/systemd_notify.hpp"
#include "toxtunnel/util/windows_service.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace {

#ifndef TOXTUNNEL_VERSION
#define TOXTUNNEL_VERSION "0.0.0-dev"
#endif

constexpr const char* kVersion = TOXTUNNEL_VERSION;

/// Map from CLI string to LogLevel.
const std::map<std::string, toxtunnel::util::LogLevel> kLogLevelMap = {
    {"trace", toxtunnel::util::LogLevel::Trace}, {"debug", toxtunnel::util::LogLevel::Debug},
    {"info", toxtunnel::util::LogLevel::Info},   {"warn", toxtunnel::util::LogLevel::Warn},
    {"error", toxtunnel::util::LogLevel::Error},
};

/// Parse a log level string into a LogLevel enum value.
/// Returns true on success, false on failure.
bool parse_log_level(const std::string& str, toxtunnel::util::LogLevel& out) {
    auto it = kLogLevelMap.find(str);
    if (it != kLogLevelMap.end()) {
        out = it->second;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// `servers` subcommand helpers
// ---------------------------------------------------------------------------

/// Resolve the data_dir for the `servers` subcommands.
///
/// Priority:
///   1. explicit --data-dir flag
///   2. config file from --config (uses Config.data_dir)
///   3. Config::default_client().data_dir
///
/// If `--config` is given but the file cannot be loaded (or the loaded config
/// has an empty data_dir), this returns nullopt and writes a clear error to
/// stderr — silently falling back to `~/.config/toxtunnel` would let the user
/// believe they were operating on a specific data_dir while in fact the
/// `add`/`remove` mutated the default registry.
[[nodiscard]] std::optional<std::filesystem::path> resolve_servers_data_dir(
    const std::string& explicit_data_dir, const std::string& config_path) {
    if (!explicit_data_dir.empty()) {
        return std::filesystem::path(explicit_data_dir);
    }
    if (!config_path.empty()) {
        auto loaded = toxtunnel::Config::from_file(config_path);
        if (!loaded) {
            std::cerr << "Failed to load config '" << config_path << "': " << loaded.error()
                      << "\n";
            return std::nullopt;
        }
        if (loaded.value().data_dir.empty()) {
            std::cerr << "Config '" << config_path
                      << "' has an empty data_dir; specify --data-dir explicitly.\n";
            return std::nullopt;
        }
        return loaded.value().data_dir;
    }
    return toxtunnel::Config::default_client().data_dir;
}

/// Truncate a long Tox ID for table display: first 12 + ellipsis + last 4.
std::string short_tox_id(std::string_view tox_id) {
    if (tox_id.size() <= 20)
        return std::string(tox_id);
    return std::string(tox_id.substr(0, 12)) + ".." + std::string(tox_id.substr(tox_id.size() - 4));
}

int cmd_servers_list(const std::filesystem::path& data_dir, bool full_ids) {
    toxtunnel::app::KnownServersStore store(data_dir);
    if (auto& err = store.last_load_error(); err.has_value()) {
        std::cerr << "Warning: " << *err << "\n";
    }

    if (store.empty()) {
        std::cout << "(no known servers in " << store.path().string() << ")\n";
        return 0;
    }

    const auto entries = store.entries();
    std::cout << "Known servers (" << store.path().string() << "):\n";
    for (const auto& s : entries) {
        const auto id_to_print = full_ids ? s.tox_id : short_tox_id(s.tox_id);
        std::cout << "  - " << (s.alias ? *s.alias : std::string("(no alias)")) << "  "
                  << id_to_print << "  type=" << to_string(s.last_connection_type)
                  << "  last=" << s.last_connected_at.value_or("never");
        if (s.info.hostname)
            std::cout << "  host=" << *s.info.hostname;
        if (s.info.os)
            std::cout << "  os=" << *s.info.os;
        std::cout << "\n";
    }
    return 0;
}

int cmd_servers_show(const std::filesystem::path& data_dir, const std::string& alias_or_id) {
    toxtunnel::app::KnownServersStore store(data_dir);
    const auto* entry = store.find_by_alias(alias_or_id);
    if (!entry) {
        const auto resolved = store.resolve_tox_id(alias_or_id);
        entry = store.find_by_tox_id(resolved);
    }
    if (!entry) {
        std::cerr << "No known server matching '" << alias_or_id << "'\n";
        return 1;
    }
    std::cout << "tox_id:               " << entry->tox_id << "\n";
    std::cout << "alias:                " << (entry->alias ? *entry->alias : "(none)") << "\n";
    std::cout << "first_connected_at:   " << entry->first_connected_at.value_or("(never)") << "\n";
    std::cout << "last_connected_at:    " << entry->last_connected_at.value_or("(never)") << "\n";
    std::cout << "last_connection_type: " << to_string(entry->last_connection_type) << "\n";
    if (!entry->notes.empty())
        std::cout << "notes:                " << entry->notes << "\n";
    if (entry->info.hostname)
        std::cout << "info.hostname:        " << *entry->info.hostname << "\n";
    if (entry->info.os)
        std::cout << "info.os:              " << *entry->info.os << "\n";
    if (entry->info.os_version)
        std::cout << "info.os_version:      " << *entry->info.os_version << "\n";
    if (entry->info.arch)
        std::cout << "info.arch:            " << *entry->info.arch << "\n";
    if (entry->info.uptime_seconds)
        std::cout << "info.uptime_seconds:  " << *entry->info.uptime_seconds << "\n";
    if (entry->info.toxtunnel_version)
        std::cout << "info.version:         " << *entry->info.toxtunnel_version << "\n";
    if (entry->info.reported_at)
        std::cout << "info.reported_at:     " << *entry->info.reported_at << "\n";
    return 0;
}

int cmd_servers_add(const std::filesystem::path& data_dir, const std::string& alias,
                    const std::string& tox_id, const std::string& notes) {
    toxtunnel::app::KnownServersStore store(data_dir);

    // If we already know this Tox ID, start from its current record so that
    // first/last_connected_at, last_connection_type, info{} and existing notes
    // survive a re-add. `upsert` does a wholesale replace by design, so the
    // merge has to happen here in the caller.
    toxtunnel::app::KnownServer entry;
    if (const auto* existing = store.find_by_tox_id(tox_id)) {
        entry = *existing;
    }
    entry.tox_id = tox_id;
    entry.alias = alias;
    if (!notes.empty()) {
        entry.notes = notes;
    }

    if (!store.upsert(entry)) {
        std::cerr << "Failed to add: tox_id is invalid (must be 76 hex chars) or alias collides "
                     "with a different tox_id.\n";
        return 1;
    }
    if (auto save = store.save(); !save) {
        std::cerr << "Failed to save: " << save.error() << "\n";
        return 1;
    }
    std::cout << "Added '" << alias << "' -> " << short_tox_id(tox_id) << " ("
              << store.path().string() << ")\n";
    return 0;
}

int cmd_servers_remove(const std::filesystem::path& data_dir, const std::string& alias_or_id) {
    toxtunnel::app::KnownServersStore store(data_dir);
    if (!store.remove(alias_or_id)) {
        std::cerr << "No known server matching '" << alias_or_id << "'\n";
        return 1;
    }
    if (auto save = store.save(); !save) {
        std::cerr << "Failed to save: " << save.error() << "\n";
        return 1;
    }
    std::cout << "Removed '" << alias_or_id << "'\n";
    return 0;
}

// ---------------------------------------------------------------------------
// `inspect` subcommand
// ---------------------------------------------------------------------------

// We deliberately do NOT link the inspect CLI client against our asio-backed
// InspectServer code — the CLI runs in its own short-lived process with no
// io_context. A direct, blocking syscall keeps the CLI binary slim and
// dependency-free.
std::optional<std::string> inspect_send_request(const std::filesystem::path& data_dir,
                                                const std::string& request) {
#if defined(_WIN32)
    // The named pipe is per-pid so the CLI has to discover it. The daemon
    // doesn't currently publish a pid file, so for now we probe the
    // hard-coded path used when the daemon shares a host with the CLI:
    // %ProgramData%\ToxTunnel\toxtunnel.pid. If absent, surface a clear
    // error so the user can supply a pid manually via env override.
    std::string pipe_name = "\\\\.\\pipe\\toxtunnel-";
    if (const char* pid_override = std::getenv("TOXTUNNEL_INSPECT_PID")) {
        pipe_name += pid_override;
    } else {
        const auto pid_path = data_dir / "toxtunnel.pid";
        std::ifstream pid_file(pid_path);
        if (!pid_file) {
            std::cerr << "Inspect: no pid file at " << pid_path.string()
                      << "; set TOXTUNNEL_INSPECT_PID to the daemon pid.\n";
            return std::nullopt;
        }
        std::string pid;
        pid_file >> pid;
        pipe_name += pid;
    }
    HANDLE pipe = CreateFileA(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Inspect: cannot connect to " << pipe_name << " (is the daemon running?)\n";
        return std::nullopt;
    }
    DWORD written = 0;
    WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()), &written, nullptr);
    std::string out;
    char buf[1024];
    DWORD read = 0;
    while (ReadFile(pipe, buf, sizeof(buf), &read, nullptr) && read > 0) {
        out.append(buf, read);
    }
    CloseHandle(pipe);
    return out;
#else
    const auto socket_path = data_dir / "toxtunnel.sock";
    if (!std::filesystem::exists(socket_path)) {
        std::cerr << "Inspect: no socket at " << socket_path.string()
                  << " (is the daemon running?)\n";
        return std::nullopt;
    }
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "Inspect: socket() failed\n";
        return std::nullopt;
    }
    ::sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto path_str = socket_path.string();
    if (path_str.size() >= sizeof(addr.sun_path)) {
        std::cerr << "Inspect: socket path too long: " << path_str << "\n";
        ::close(fd);
        return std::nullopt;
    }
    std::memcpy(addr.sun_path, path_str.data(), path_str.size());
    if (::connect(fd, reinterpret_cast< ::sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Inspect: connect() to " << path_str << " failed (is the daemon running?)\n";
        ::close(fd);
        return std::nullopt;
    }
    ::write(fd, request.data(), request.size());
    std::string out;
    char buf[1024];
    ssize_t n = 0;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
#endif
}

// Minimal best-effort JSON walker used to render the human table. We avoid
// pulling a JSON library in — the daemon's wire format is tiny and stable.
// On any unexpected shape we just fall back to printing the raw JSON so the
// operator can still see something useful.
struct JsonCursor {
    std::string_view src;
    std::size_t pos = 0;

    void skip_ws() {
        while (pos < src.size() && std::isspace(static_cast<unsigned char>(src[pos]))) ++pos;
    }
    bool consume(char c) {
        skip_ws();
        if (pos < src.size() && src[pos] == c) {
            ++pos;
            return true;
        }
        return false;
    }
    std::optional<std::string> parse_string() {
        skip_ws();
        if (pos >= src.size() || src[pos] != '"')
            return std::nullopt;
        ++pos;
        std::string out;
        while (pos < src.size() && src[pos] != '"') {
            if (src[pos] == '\\' && pos + 1 < src.size()) {
                char c = src[pos + 1];
                pos += 2;
                switch (c) {
                    case 'n':
                        out += '\n';
                        break;
                    case 't':
                        out += '\t';
                        break;
                    case '"':
                        out += '"';
                        break;
                    case '\\':
                        out += '\\';
                        break;
                    default:
                        out += c;
                        break;
                }
            } else {
                out += src[pos++];
            }
        }
        if (pos < src.size())
            ++pos;
        return out;
    }
    std::optional<std::string> parse_scalar() {
        skip_ws();
        std::size_t start = pos;
        while (pos < src.size() && src[pos] != ',' && src[pos] != '}' && src[pos] != ']') ++pos;
        std::string out(src.substr(start, pos - start));
        while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) {
            out.pop_back();
        }
        return out.empty() ? std::optional<std::string>{} : std::optional<std::string>(out);
    }
};

void render_tunnels_table(const std::string& json) {
    // Find the "tunnels":[ array. If we can't parse it, just dump the JSON.
    const auto pos = json.find("\"tunnels\"");
    if (pos == std::string::npos) {
        std::cout << json << "\n";
        return;
    }
    auto br = json.find('[', pos);
    auto end = json.find(']', br);
    if (br == std::string::npos || end == std::string::npos) {
        std::cout << json << "\n";
        return;
    }
    std::cout << "ID    TARGET                          STATE         BYTES_IN     BYTES_OUT   "
                 "IDLE_S  PEER\n";
    std::cout << "----  ------------------------------  ------------  -----------  ----------  "
                 "------  ----------\n";
    std::string_view body(json.data() + br + 1, end - br - 1);
    JsonCursor c{body};
    while (c.pos < c.src.size()) {
        c.skip_ws();
        if (!c.consume('{'))
            break;
        std::string id, target, state, bytes_in, bytes_out, idle, pk;
        while (c.pos < c.src.size() && c.src[c.pos] != '}') {
            auto key = c.parse_string();
            if (!key)
                break;
            c.consume(':');
            std::optional<std::string> v;
            c.skip_ws();
            if (c.pos < c.src.size() && c.src[c.pos] == '"') {
                v = c.parse_string();
            } else {
                v = c.parse_scalar();
            }
            if (!v)
                break;
            if (*key == "id")
                id = *v;
            else if (*key == "target")
                target = *v;
            else if (*key == "state")
                state = *v;
            else if (*key == "bytes_in")
                bytes_in = *v;
            else if (*key == "bytes_out")
                bytes_out = *v;
            else if (*key == "idle_seconds")
                idle = *v;
            else if (*key == "friend_pk_prefix")
                pk = *v;
            c.consume(',');
        }
        c.consume('}');
        c.consume(',');
        std::cout << id;
        for (int i = static_cast<int>(id.size()); i < 6; ++i) std::cout << ' ';
        std::cout << target;
        for (int i = static_cast<int>(target.size()); i < 32; ++i) std::cout << ' ';
        std::cout << state;
        for (int i = static_cast<int>(state.size()); i < 14; ++i) std::cout << ' ';
        std::cout << bytes_in;
        for (int i = static_cast<int>(bytes_in.size()); i < 13; ++i) std::cout << ' ';
        std::cout << bytes_out;
        for (int i = static_cast<int>(bytes_out.size()); i < 12; ++i) std::cout << ' ';
        std::cout << (idle.empty() ? "-" : idle);
        for (int i = static_cast<int>(idle.empty() ? 1 : idle.size()); i < 8; ++i) std::cout << ' ';
        std::cout << pk << "\n";
    }
}

int cmd_inspect(const std::filesystem::path& data_dir, const std::string& subaction, bool as_json) {
    std::string request;
    if (subaction == "status") {
        request = "GET /status\n";
    } else {
        request = "GET /tunnels\n";
    }
    auto reply = inspect_send_request(data_dir, request);
    if (!reply) {
        return 1;
    }
    // Drop trailing newline if present.
    while (!reply->empty() && (reply->back() == '\n' || reply->back() == '\r')) {
        reply->pop_back();
    }
    if (as_json || subaction == "status") {
        std::cout << *reply << "\n";
        return 0;
    }
    render_tunnels_table(*reply);
    return 0;
}

/// Drive a clean SERVICE_STOPPED transition when a packaged --service install can't
/// start (config missing or invalid). Exit code 0 so launchd KeepAlive
/// { SuccessfulExit: false }, systemd Restart=on-failure, and Windows SCM auto-restart
/// don't loop on a misconfigured install. The user creates / fixes the config and
/// restarts the service. Logger is not initialized at the call sites, so this writes
/// to stderr.
[[nodiscard]] int exit_service_idle(const std::string& reason) {
    std::cerr << "Service idle: " << reason << "\n";
#if defined(_WIN32)
    return toxtunnel::util::run_windows_service_main("ToxTunnel", []() { return 0; });
#else
    toxtunnel::util::notify_service_ready();
    return 0;
#endif
}

/// Re-read + validate the config file used at startup. Returns nullopt on any
/// failure; the caller logs and keeps the previously-loaded config (this is
/// the no-op-on-failure contract for SIGHUP reloads).
[[maybe_unused]] std::optional<toxtunnel::Config> reload_config_from_disk(
    const std::string& config_path) {
    if (config_path.empty()) {
        toxtunnel::util::Logger::warn(
            "reload requested but no --config was supplied at startup; ignoring");
        return std::nullopt;
    }
    auto result = toxtunnel::Config::from_file(config_path);
    if (!result.has_value()) {
        toxtunnel::util::Logger::error("reload failed: cannot load {}: {}", config_path,
                                       result.error());
        return std::nullopt;
    }
    auto validation = result.value().validate();
    if (!validation.has_value()) {
        toxtunnel::util::Logger::error("reload failed: invalid config in {}: {}", config_path,
                                       validation.error());
        return std::nullopt;
    }
    return std::move(result).value();
}

#if defined(_WIN32)
/// Windows lacks SIGHUP, so reload is triggered by writing "RELOAD\n" to a
/// per-pid named pipe. The pipe name encodes the pid so multiple toxtunnel
/// instances on one host don't collide. A dedicated thread serves the pipe
/// and posts the reload via `on_reload`; the thread exits when `running` is
/// cleared and any pending CreateFile probe completes.
class WindowsReloadPipeServer {
   public:
    WindowsReloadPipeServer(std::function<void()> on_reload) : on_reload_(std::move(on_reload)) {
        pipe_name_ = "\\\\.\\pipe\\toxtunnel-reload-" + std::to_string(GetCurrentProcessId());
    }

    ~WindowsReloadPipeServer() { stop(); }

    void start() {
        running_.store(true);
        thread_ = std::thread([this] { run(); });
    }

    void stop() {
        if (!running_.exchange(false)) {
            return;
        }
        // Unblock a server thread waiting in ConnectNamedPipe by opening a
        // client handle to our own pipe.
        HANDLE wake =
            CreateFileA(pipe_name_.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (wake != INVALID_HANDLE_VALUE) {
            CloseHandle(wake);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    [[nodiscard]] const std::string& pipe_name() const { return pipe_name_; }

   private:
    void run() {
        while (running_.load()) {
            HANDLE pipe = CreateNamedPipeA(pipe_name_.c_str(), PIPE_ACCESS_DUPLEX,
                                           PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512,
                                           512, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) {
                toxtunnel::util::Logger::warn(
                    "reload pipe CreateNamedPipe failed ({}); reload IPC unavailable",
                    GetLastError());
                return;
            }
            const BOOL connected =
                ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
            if (!running_.load()) {
                CloseHandle(pipe);
                return;
            }
            if (connected) {
                char buf[16] = {};
                DWORD read = 0;
                if (ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
                    std::string msg(buf, read);
                    if (msg.find("RELOAD") != std::string::npos) {
                        on_reload_();
                    }
                }
            }
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }

    std::function<void()> on_reload_;
    std::string pipe_name_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};
#endif  // _WIN32

/// Run the tunnel server until a signal is received.
int run_server(const toxtunnel::Config& config, bool run_as_service,
               [[maybe_unused]] const std::string& config_path) {
    using Logger = toxtunnel::util::Logger;

    toxtunnel::app::TunnelServer server;

    auto init_result = server.initialize(config);
    if (!init_result.has_value()) {
        Logger::error("Failed to initialize server: {}", init_result.error());
        return 1;
    }

    Logger::info("Server initialized successfully");

    if (config.server) {
        Logger::info("Listening on TCP port {}", config.server->tcp_port);
    }

    // Print the Tox address so clients can connect
    auto tox_address = server.get_tox_address();
    if (!tox_address.empty()) {
        Logger::info("Server Tox address: {}", tox_address);
    }

    // Set up signal handling via asio
    asio::io_context signal_ctx;
    asio::signal_set signals(signal_ctx, SIGINT, SIGTERM);

    signals.async_wait([&server](const asio::error_code& ec, int signum) {
        if (!ec) {
            toxtunnel::util::Logger::info("Received signal {}, shutting down...", signum);
            server.stop();
        }
    });

    // Start the server (non-blocking)
    server.start();
    Logger::info("Server started");
    if (run_as_service) {
        toxtunnel::util::notify_service_ready();
    }

#if defined(_WIN32)
    // For Windows service, poll for stop requests
    if (run_as_service) {
        while (!toxtunnel::util::is_windows_service_stopping()) {
            signal_ctx.poll_one();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        server.stop();
    } else {
        signal_ctx.run();
    }
#else
    // Block on signal wait
    signal_ctx.run();
#endif

    if (run_as_service) {
        toxtunnel::util::notify_service_stopping();
    }
    Logger::info("Server stopped");
    return 0;
}

/// Run the tunnel client until a signal is received.
int run_client(const toxtunnel::Config& config, bool run_as_service) {
    using Logger = toxtunnel::util::Logger;

    toxtunnel::app::TunnelClient client;

    auto init_result = client.initialize(config);
    if (!init_result.has_value()) {
        Logger::error("Failed to initialize client: {}", init_result.error());
        return 1;
    }

    Logger::info("Client initialized successfully");

    if (config.client && !config.client->server_id.empty()) {
        Logger::info("Connecting to server: {}", config.client->server_id);
    }

    // Set up signal handling via asio
    asio::io_context signal_ctx;
    asio::signal_set signals(signal_ctx, SIGINT, SIGTERM);

    signals.async_wait([&client](const asio::error_code& ec, int signum) {
        if (!ec) {
            toxtunnel::util::Logger::info("Received signal {}, shutting down...", signum);
            client.stop();
        }
    });

    // Start the client (non-blocking)
    client.start();
    Logger::info("Client started");
    if (run_as_service) {
        toxtunnel::util::notify_service_ready();
    }

    std::thread signal_thread([&signal_ctx] { signal_ctx.run(); });

#if defined(_WIN32)
    // For Windows service, poll for stop requests
    if (run_as_service) {
        while (!toxtunnel::util::is_windows_service_stopping() && client.is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (client.is_running()) {
            client.stop();
        }
        signal_ctx.stop();
    } else {
        client.wait_until_stopped();
        signal_ctx.stop();
    }
#else
    client.wait_until_stopped();
    signal_ctx.stop();
#endif

    if (signal_thread.joinable()) {
        signal_thread.join();
    }

    if (run_as_service) {
        toxtunnel::util::notify_service_stopping();
    }
    Logger::info("Client stopped");
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    using namespace toxtunnel;
    using Logger = util::Logger;

    // -----------------------------------------------------------------------
    // CLI argument parsing
    // -----------------------------------------------------------------------
    CLI::App app{"ToxTunnel - TCP Tunnel over Tox"};

    std::string config_path;
    std::string mode_str;
    std::string data_dir;
    std::string log_level_str;
    uint16_t port = 0;
    std::string server_id;
    std::string pipe_target;
    std::string print_id_data_dir;
    bool print_id_qr = false;
    bool print_id_color = false;
    bool run_as_service = false;

    auto* print_id_cmd = app.add_subcommand("print-id", "Print local Tox ID");
    print_id_cmd->add_option("-d,--data-dir", print_id_data_dir,
                             "Data directory for loading/creating local Tox identity");
    print_id_cmd->add_flag("--qr", print_id_qr, "Render Tox ID as terminal QR code");
    print_id_cmd->add_flag("--color", print_id_color, "Use ANSI colors with QR output");

    // ----- `servers` group ---------------------------------------------------
    // Per-client persistent registry of previously-connected servers. Each
    // subcommand resolves the registry path from --data-dir, --config, or
    // Config::default_client().data_dir.
    auto* servers_cmd =
        app.add_subcommand("servers",
                           "Manage the known-servers registry. "
                           "WARNING: the on-disk file is single-writer — stop the toxtunnel daemon "
                           "before running `add`/`remove`, otherwise your edit will race with the "
                           "daemon's on-connect updates and one side will be lost.");
    servers_cmd->require_subcommand(1);

    std::string servers_data_dir;
    std::string servers_config_path;
    auto add_common_servers_opts = [&](CLI::App* sub) {
        sub->add_option("-d,--data-dir", servers_data_dir,
                        "Data directory holding known_servers.yaml");
        sub->add_option("-c,--config", servers_config_path,
                        "Read data_dir from this config file (overridden by --data-dir)");
    };

    bool servers_list_full = false;
    auto* servers_list_cmd = servers_cmd->add_subcommand("list", "List known servers");
    add_common_servers_opts(servers_list_cmd);
    servers_list_cmd->add_flag("--full", servers_list_full, "Show full 76-char Tox IDs");

    std::string servers_show_target;
    auto* servers_show_cmd =
        servers_cmd->add_subcommand("show", "Show details for one known server");
    add_common_servers_opts(servers_show_cmd);
    servers_show_cmd
        ->add_option("alias_or_tox_id", servers_show_target, "Alias or full 76-char Tox ID")
        ->required();

    std::string servers_add_alias;
    std::string servers_add_tox_id;
    std::string servers_add_notes;
    auto* servers_add_cmd =
        servers_cmd->add_subcommand("add", "Add or update a known server entry");
    add_common_servers_opts(servers_add_cmd);
    servers_add_cmd->add_option("alias", servers_add_alias, "Short user-defined alias")->required();
    servers_add_cmd->add_option("tox_id", servers_add_tox_id, "76-char hex Tox ID")->required();
    servers_add_cmd->add_option("--notes", servers_add_notes, "Free-form notes");

    std::string servers_remove_target;
    auto* servers_remove_cmd =
        servers_cmd->add_subcommand("remove", "Remove a known server by alias or Tox ID");
    add_common_servers_opts(servers_remove_cmd);
    servers_remove_cmd
        ->add_option("alias_or_tox_id", servers_remove_target, "Alias or full 76-char Tox ID")
        ->required();

    // ----- `inspect` ---------------------------------------------------------
    // Read-only IPC client. Connects to the running daemon's Unix socket
    // (POSIX) or named pipe (Windows), sends one request line, prints the
    // JSON (or a rendered table).
    auto* inspect_cmd =
        app.add_subcommand("inspect", "Inspect a running toxtunnel daemon via local IPC");
    std::string inspect_data_dir;
    std::string inspect_config_path;
    std::string inspect_subaction = "tunnels";
    bool inspect_json = false;
    inspect_cmd->add_option("-d,--data-dir", inspect_data_dir,
                            "Daemon data directory (holds toxtunnel.sock)");
    inspect_cmd->add_option("-c,--config", inspect_config_path,
                            "Read data_dir from this config file (overridden by --data-dir)");
    inspect_cmd->add_flag("--json", inspect_json, "Print raw JSON instead of a table");
    inspect_cmd
        ->add_option("subaction", inspect_subaction,
                     "Resource to inspect: tunnels (default) | status")
        ->check(CLI::IsMember({"tunnels", "status"}));

#if defined(_WIN32)
    auto* install_win_svc =
        app.add_subcommand("install-windows-service", "Register ToxTunnel as a Windows service");
    std::string install_svc_config;
    install_win_svc->add_option("-c,--config", install_svc_config,
                                "Path to config.yaml used by the service");

    auto* uninstall_win_svc =
        app.add_subcommand("uninstall-windows-service", "Unregister the ToxTunnel Windows service");
#endif

    app.add_option("-c,--config", config_path, "Path to YAML config file");

    app.add_option("-m,--mode", mode_str, "Operating mode: server or client")
        ->check(CLI::IsMember({"server", "client"}));

    app.add_option("-d,--data-dir", data_dir, "Override data directory");

    app.add_option("-l,--log-level", log_level_str, "Override log level")
        ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error"}));

    app.add_option("-p,--port", port, "Override TCP port (server mode)")
        ->check(CLI::Range(static_cast<uint16_t>(1), static_cast<uint16_t>(65535)));

    app.add_option("--server-id", server_id, "Override server Tox ID (client mode)");
    app.add_option("--pipe", pipe_target, "Pipe mode target host:port (client mode)");
    app.add_flag("--service", run_as_service, "Run as background service");

    app.set_version_flag("-v,--version", kVersion);

    CLI11_PARSE(app, argc, argv);

#if defined(_WIN32)
    if (*install_win_svc) {
        std::string cfg = install_svc_config;
        if (cfg.empty()) {
            const char* pd = std::getenv("ProgramData");
            cfg = std::string(pd ? pd : "C:\\ProgramData") + "\\ToxTunnel\\config.yaml";
        }
        if (!util::register_packaged_toxtunnel_service(cfg)) {
            std::cerr << "Failed to register Windows service (run as Administrator).\n";
            return 1;
        }
        std::cerr << "Registered Windows service ToxTunnel.\n";
        return 0;
    }
    if (*uninstall_win_svc) {
        if (!util::unregister_packaged_toxtunnel_service()) {
            std::cerr << "Failed to unregister Windows service (run as Administrator).\n";
            return 1;
        }
        std::cerr << "Unregistered Windows service ToxTunnel.\n";
        return 0;
    }
#endif

    if (*servers_cmd) {
        // Resolve once; if the user passed --config but it's missing/invalid we
        // surface the error and refuse to silently mutate ~/.config/toxtunnel.
        auto servers_dir = resolve_servers_data_dir(servers_data_dir, servers_config_path);
        if (!servers_dir) {
            return 1;
        }
        if (*servers_list_cmd) {
            return cmd_servers_list(*servers_dir, servers_list_full);
        }
        if (*servers_show_cmd) {
            return cmd_servers_show(*servers_dir, servers_show_target);
        }
        if (*servers_add_cmd) {
            return cmd_servers_add(*servers_dir, servers_add_alias, servers_add_tox_id,
                                   servers_add_notes);
        }
        if (*servers_remove_cmd) {
            return cmd_servers_remove(*servers_dir, servers_remove_target);
        }
        std::cerr << "Unknown 'servers' subcommand. Try --help.\n";
        return 2;
    }

    if (*inspect_cmd) {
        // data_dir resolution mirrors `servers` and `print-id`: explicit
        // --data-dir wins, else a --config path, else the platform default.
        auto inspect_dir = resolve_servers_data_dir(inspect_data_dir, inspect_config_path);
        if (!inspect_dir) {
            return 1;
        }
        return cmd_inspect(*inspect_dir, inspect_subaction, inspect_json);
    }

    if (*print_id_cmd) {
        if (print_id_color && !print_id_qr) {
            std::cerr << "--color requires --qr\n";
            return 1;
        }

        std::filesystem::path id_data_dir;
        if (!print_id_data_dir.empty()) {
            id_data_dir = print_id_data_dir;
        } else {
            id_data_dir = Config::default_client().data_dir;
        }

        auto tox_id_result = tox::ToxAdapter::get_tox_id_only(id_data_dir);
        if (!tox_id_result.has_value()) {
            std::cerr << "Failed to load Tox ID: " << tox_id_result.error() << "\n";
            return 1;
        }

        if (!print_id_qr) {
            std::cout << tox_id_result.value() << "\n";
            return 0;
        }

        auto qr_result = util::generate_qr_terminal(tox_id_result.value(), print_id_color);
        if (!qr_result.has_value()) {
            std::cerr << "Failed to render QR: " << qr_result.error() << "\n";
            return 1;
        }

        std::cout << qr_result.value();
        std::cout << tox_id_result.value() << "\n";
        return 0;
    }

    // -----------------------------------------------------------------------
    // Load configuration
    // -----------------------------------------------------------------------
    Config config;

    if (!config_path.empty()) {
        // Explicit config file specified
        auto result = Config::from_file(config_path);
        if (!result.has_value()) {
            if (run_as_service) {
                return exit_service_idle("cannot load config at " + config_path + " (" +
                                         result.error() +
                                         "). Create the file and restart the service to enable.");
            }
            // Logger not initialized yet, use std::cerr for bootstrap errors
            std::cerr << "Error loading config: " << result.error() << "\n";
            return 1;
        }
        config = std::move(result).value();
    } else {
        // No config specified; use defaults based on mode
        if (mode_str == "client") {
            config = Config::default_client();
        } else {
            config = Config::default_server();
        }
    }

    // -----------------------------------------------------------------------
    // Apply CLI overrides
    // -----------------------------------------------------------------------
    Config overrides;
    bool has_overrides = false;

    if (!mode_str.empty()) {
        if (mode_str == "server") {
            overrides.mode = Mode::Server;
            overrides.server = ServerConfig{};
        } else {
            overrides.mode = Mode::Client;
            overrides.client = ClientConfig{};
        }
        has_overrides = true;
    } else {
        // Keep same mode as loaded config so merge_cli_overrides does not
        // interpret a default Mode::Server as an intentional override.
        overrides.mode = config.mode;
    }

    if (!data_dir.empty()) {
        overrides.data_dir = data_dir;
        has_overrides = true;
    }

    if (!log_level_str.empty()) {
        util::LogLevel level{};
        if (parse_log_level(log_level_str, level)) {
            overrides.logging.level = level;
            has_overrides = true;
        }
    }

    if (port != 0) {
        if (!overrides.server) {
            overrides.server = ServerConfig{};
        }
        overrides.server->tcp_port = port;
        has_overrides = true;
    }

    if (!server_id.empty()) {
        // `--server-id` may be a 76-char Tox ID or a known-servers alias.
        // The resolution itself happens after merge_cli_overrides() below, so
        // both this CLI value and any YAML `client.server_id` go through the
        // same single resolve_tox_id() call against the post-merge data_dir.
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->server_id = server_id;
        has_overrides = true;
    }

    if (!pipe_target.empty()) {
        auto pipe_result = parse_pipe_target(pipe_target);
        if (!pipe_result) {
            std::cerr << "Configuration error: " << pipe_result.error() << "\n";
            return 1;
        }
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->pipe_target = pipe_result.value();
        has_overrides = true;
    }

    if (has_overrides) {
        config.merge_cli_overrides(overrides);
    }

    // -----------------------------------------------------------------------
    // Resolve known-servers aliases in client.server_id (from YAML or
    // `--server-id`) against the registry under the post-merge data_dir.
    // Single pass so the "Resolved alias …" message fires at most once per run.
    // -----------------------------------------------------------------------
    if (config.is_client() && config.client.has_value() && !config.client->server_id.empty() &&
        config.client->server_id.size() != 76) {
        toxtunnel::app::KnownServersStore lookup(config.data_dir);
        const auto original = config.client->server_id;
        const auto resolved = lookup.resolve_tox_id(original);
        if (resolved != original) {
            std::cerr << "Resolved alias '" << original << "' to "
                      << (resolved.size() == 76 ? resolved.substr(0, 12) + "..." : resolved)
                      << "\n";
            config.client->server_id = resolved;
        }
    }

    // -----------------------------------------------------------------------
    // Validate configuration
    // -----------------------------------------------------------------------
    auto validation = config.validate();
    if (!validation.has_value()) {
        if (run_as_service) {
            return exit_service_idle(
                "invalid config at " +
                (config_path.empty() ? std::string("<defaults>") : config_path) + ": " +
                validation.error() + ". Fix the config and restart the service.");
        }
        std::cerr << "Configuration error: " << validation.error() << "\n";
        return 1;
    }

    // -----------------------------------------------------------------------
    // Initialize logging
    // -----------------------------------------------------------------------
    Logger::init("toxtunnel");
    Logger::set_level(config.logging.level);

    if (config.logging.file.has_value()) {
        Logger::add_file_sink(*config.logging.file);
    }

    Logger::info("ToxTunnel v{} starting in {} mode", kVersion,
                 config.is_server() ? "server" : "client");
    Logger::debug("Data directory: {}", config.data_dir.string());

    // -----------------------------------------------------------------------
    // Run the appropriate mode
    // -----------------------------------------------------------------------
    int exit_code = 0;

#if defined(_WIN32)
    // On Windows, use service framework if --service is specified
    if (run_as_service) {
        exit_code = util::run_windows_service_main("ToxTunnel", [&]() {
            if (!config.should_run_as_service_daemon()) {
                Logger::info(
                    "Service idle: disabled by config (service.auto_start / "
                    "service.allow_client_daemon); exiting.");
                return 0;
            }
            if (config.is_server()) {
                return run_server(config, true);
            }
            return run_client(config, true);
        });
    } else {
        if (config.is_server()) {
            exit_code = run_server(config, false);
        } else {
            exit_code = run_client(config, false);
        }
    }
#else
    if (run_as_service && !config.should_run_as_service_daemon()) {
        Logger::info(
            "Service idle: disabled by config (service.auto_start / "
            "service.allow_client_daemon); exiting.");
        util::notify_service_ready();
        Logger::info("ToxTunnel exiting with code {}", 0);
        Logger::shutdown();
        return 0;
    }

    if (config.is_server()) {
        exit_code = run_server(config, run_as_service, config_path);
    } else {
        exit_code = run_client(config, run_as_service);
    }
#endif

    Logger::info("ToxTunnel exiting with code {}", exit_code);
    Logger::shutdown();

    return exit_code;
}
