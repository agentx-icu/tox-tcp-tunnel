#include <CLI/CLI.hpp>
#include <asio.hpp>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
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
#include "toxtunnel/util/config_diagnostics.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/pid_file.hpp"
#include "toxtunnel/util/qr_code.hpp"
#include "toxtunnel/util/systemd_notify.hpp"
#include "toxtunnel/util/windows_service.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
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
    if (auto err = store.last_load_error(); err.has_value()) {
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
    auto entry = store.find_by_alias(alias_or_id);
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
    if (auto existing = store.find_by_tox_id(tox_id)) {
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
    // publishes its pid in `<data_dir>/toxtunnel.pid` (see util::PidFileGuard
    // in run_server / run_client); TOXTUNNEL_INSPECT_PID overrides that for
    // the odd case where the CLI cannot read the daemon's data_dir.
    std::string pipe_name = "\\\\.\\pipe\\toxtunnel-";
    if (const char* pid_override = std::getenv("TOXTUNNEL_INSPECT_PID")) {
        pipe_name += pid_override;
    } else {
        const auto pid = toxtunnel::util::read_pid_file(data_dir);
        if (!pid.has_value()) {
            std::cerr << "Inspect: no pid file at "
                      << (data_dir / toxtunnel::util::kPidFileName).string()
                      << " (is the daemon running with this data_dir?); "
                         "set TOXTUNNEL_INSPECT_PID to the daemon pid to override.\n";
            return std::nullopt;
        }
        pipe_name += std::to_string(*pid);
    }
    HANDLE pipe = CreateFileA(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::cerr << "Inspect: cannot connect to " << pipe_name << " (error " << err << ": "
                  << (err == ERROR_FILE_NOT_FOUND ? "no such pipe - is the daemon running?"
                      : err == ERROR_ACCESS_DENIED
                          ? "access denied - a service daemon only admits SYSTEM and "
                            "Administrators; run from an elevated prompt"
                          : "see `net helpmsg`")
                  << ")\n";
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

    // M-10: bound connect/write/read so a half-hung daemon (socket exists but
    // the daemon never accepts/responds) can't wedge the CLI forever. Use a
    // non-blocking connect with poll() for the connect deadline, then
    // SO_SNDTIMEO/SO_RCVTIMEO for the write/read loop.
    constexpr int kTimeoutMs = 5000;
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    int crc = ::connect(fd, reinterpret_cast< ::sockaddr*>(&addr), sizeof(addr));
    if (crc < 0 && errno == EINPROGRESS) {
        ::pollfd pfd{fd, POLLOUT, 0};
        const int pr = ::poll(&pfd, 1, kTimeoutMs);
        if (pr <= 0) {
            std::cerr << "Inspect: connect() to " << path_str << " timed out\n";
            ::close(fd);
            return std::nullopt;
        }
        int so_err = 0;
        ::socklen_t errlen = sizeof(so_err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &errlen) < 0 || so_err != 0) {
            std::cerr << "Inspect: connect() to " << path_str
                      << " failed (is the daemon running?)\n";
            ::close(fd);
            return std::nullopt;
        }
    } else if (crc < 0) {
        std::cerr << "Inspect: connect() to " << path_str << " failed (is the daemon running?)\n";
        ::close(fd);
        return std::nullopt;
    }
    // Back to blocking, but with send/recv deadlines.
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags);
    }
    ::timeval tv{kTimeoutMs / 1000, (kTimeoutMs % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::write(fd, request.data(), request.size()) < 0) {
        std::cerr << "Inspect: write() to " << path_str << " failed (timed out?)\n";
        ::close(fd);
        return std::nullopt;
    }
    std::string out;
    char buf[1024];
    ssize_t n = 0;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<std::size_t>(n));
    }
    if (n < 0) {
        std::cerr << "Inspect: read() from " << path_str << " failed or timed out\n";
        ::close(fd);
        return std::nullopt;
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

/// Resolve known-servers aliases in a client config to 76-character Tox IDs.
///
/// The daemon does this BEFORE `validate()`, because validation only knows how
/// to check a 76-hex id and would otherwise report a perfectly good alias as
/// "must be 76 characters" (C-21 in the 2026-05-20 review). `config check` has
/// to do the same or it contradicts the daemon: a config the daemon starts
/// happily would fail the very command operators are told to run first.
///
/// Returns an error message for an unknown alias, or nullopt on success.
[[nodiscard]] std::optional<std::string> resolve_client_aliases(toxtunnel::Config& config) {
    if (!config.is_client() || !config.client.has_value()) {
        return std::nullopt;
    }
    toxtunnel::app::KnownServersStore lookup(config.data_dir);
    std::string resolve_err;
    // Replaces an alias with its tox_id in place. Anything that is neither a
    // 76-hex id nor a known alias is reported as an unknown alias rather than
    // being left to surface later as a length complaint.
    auto try_resolve = [&](std::string& id, const char* which) -> bool {
        if (id.empty() || id.size() == 76) {
            return true;
        }
        const auto original = id;
        const auto resolved = lookup.resolve_tox_id(original);
        if (resolved == original) {
            resolve_err = std::string("Unknown server alias '") + original + "' in " + which +
                          " (run `toxtunnel servers list` to see known aliases, or "
                          "supply a 76-character Tox ID)";
            return false;
        }
        std::cerr << "Resolved alias '" << original << "' to "
                  << (resolved.size() == 76 ? resolved.substr(0, 12) + "..." : resolved) << "\n";
        id = resolved;
        return true;
    };
    if (!try_resolve(config.client->server_id, "--server-id / client.server_id")) {
        return resolve_err;
    }
    for (auto& fb : config.client->fallback_server_ids) {
        if (!try_resolve(fb, "--server-id-fallback / client.fallback_server_ids")) {
            return resolve_err;
        }
    }
    return std::nullopt;
}

/// Parse, validate and lint a config file without starting anything.
///
/// Exit codes: 0 = usable, 1 = cannot be loaded or fails validation, and with
/// `--strict`, 1 as well when the file carries keys the daemon would ignore.
/// Unknown keys are always *reported*; they are only fatal under --strict, so
/// an older binary reading a newer config still works by default.
[[nodiscard]] int cmd_config_check(const std::string& config_path, bool strict) {
    auto loaded = toxtunnel::Config::from_file(config_path);
    if (!loaded.has_value()) {
        std::cerr << "config check: " << loaded.error() << "\n";
        return 1;
    }

    const auto unknown = toxtunnel::util::find_unknown_config_keys(config_path);
    for (const auto& key : unknown) {
        std::cerr << "config check: unknown key '" << key.path << "' (ignored by this build)\n";
    }

    // Resolve aliases before validating, exactly as the daemon does. Without
    // this, a registered alias in `client.server_id` fails here with "Server ID
    // must be 76 characters" on a config the daemon starts without complaint.
    if (auto alias_err = resolve_client_aliases(loaded.value())) {
        std::cerr << "config check: " << *alias_err << "\n";
        return 1;
    }

    auto validation = loaded.value().validate();
    if (!validation.has_value()) {
        std::cerr << "config check: " << validation.error() << "\n";
        return 1;
    }

    // Forward-exposure advisories. These also come out of the daemon at
    // startup, but a host running `logging.level: error` would never see that
    // one — and this command is where an operator looks before deploying.
    // Advisory only: it never changes the exit code, because the wildcard bind
    // is still valid, supported configuration.
    if (loaded.value().client.has_value()) {
        for (const auto& fwd : loaded.value().client->forwards) {
            if (auto advisory = toxtunnel::forward_bind_advisory(fwd)) {
                std::cerr << "config check: warning: " << *advisory << "\n";
            }
        }
    }

    std::cout << "config check: " << config_path << " is valid ("
              << (loaded.value().is_server() ? "server" : "client") << " mode";
    if (!unknown.empty()) {
        std::cout << ", " << unknown.size() << " unknown key" << (unknown.size() == 1 ? "" : "s");
    }
    std::cout << ")\n";

    return (strict && !unknown.empty()) ? 1 : 0;
}

/// Trigger a hot-reload on a running daemon.
///
/// The daemon records its pid in `<data_dir>/toxtunnel.pid` (util::PidFileGuard),
/// which is how both platforms find it; TOXTUNNEL_RELOAD_PID overrides the file.
///
/// POSIX: sends SIGHUP to that pid. util::pid_is_toxtunnel narrows the stale-pid
/// window (daemon crashed, pid recycled) but cannot close it — the pid could in
/// principle be reused between the check and the signal.
///
/// Windows: connects to `\\.\pipe\toxtunnel-reload-<pid>` and writes
/// "RELOAD\n".
[[nodiscard]] int cmd_reload(const std::filesystem::path& data_dir) {
    const char* env_name = "TOXTUNNEL_RELOAD_PID";
    long pid = 0;
    if (const char* pid_override = std::getenv(env_name)) {
        char* end = nullptr;
        pid = std::strtol(pid_override, &end, 10);
        if (end == pid_override || *end != '\0' || pid <= 0) {
            std::cerr << "reload: " << env_name << "='" << pid_override
                      << "' is not a positive integer\n";
            return 1;
        }
    } else {
        const auto recorded = toxtunnel::util::read_pid_file(data_dir);
        if (!recorded.has_value()) {
            std::cerr << "reload: no pid file at "
                      << (data_dir / toxtunnel::util::kPidFileName).string()
                      << " (is the daemon running with this data_dir? pass -d/-c to point at "
                         "it, or set "
                      << env_name << " to the daemon pid).\n";
            return 1;
        }
        pid = *recorded;
    }
#if defined(_WIN32)
    const std::string pipe_name = "\\\\.\\pipe\\toxtunnel-reload-" + std::to_string(pid);
    HANDLE pipe =
        CreateFileA(pipe_name.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::cerr << "reload: cannot connect to " << pipe_name << " (error " << err << ": "
                  << (err == ERROR_FILE_NOT_FOUND
                          ? "no such pipe - is the daemon running? a stale pid file is "
                            "removed on the next clean daemon start"
                      : err == ERROR_ACCESS_DENIED ? "access denied - run from an elevated prompt"
                                                   : "see `net helpmsg`")
                  << ")\n";
        return 1;
    }
    const char msg[] = "RELOAD\n";
    DWORD written = 0;
    WriteFile(pipe, msg, sizeof(msg) - 1, &written, nullptr);
    CloseHandle(pipe);
    std::cout << "Sent RELOAD to " << pipe_name << "\n";
    return 0;
#else
    if (const auto looks_right = toxtunnel::util::pid_is_toxtunnel(pid);
        looks_right.has_value() && !*looks_right) {
        std::cerr << "reload: pid " << pid << " is no longer a toxtunnel process (stale "
                  << toxtunnel::util::kPidFileName
                  << "?). Start the daemon again or send SIGHUP by hand: kill -HUP <pid>\n";
        return 1;
    }
    if (::kill(static_cast<pid_t>(pid), SIGHUP) != 0) {
        std::cerr << "reload: kill(" << pid << ", SIGHUP) failed: " << std::strerror(errno) << "\n";
        return 1;
    }
    std::cout << "Sent SIGHUP to toxtunnel pid " << pid
              << "; check the daemon log for 'config reloaded'.\n";
    return 0;
#endif
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
std::optional<toxtunnel::Config> reload_config_from_disk(const std::string& config_path) {
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
    // Resolve aliases BEFORE validating, exactly as startup and `config check`
    // do. Without this a client whose server_id is a known-servers alias starts
    // fine and then fails every SIGHUP: validate() only understands a 76-hex id,
    // so the reload is refused before any forward or log-level change is
    // applied, and the operator sees a config they can see is correct being
    // rejected by a daemon already running it.
    if (auto alias_err = resolve_client_aliases(result.value())) {
        toxtunnel::util::Logger::error("reload failed: {} in {}", *alias_err, config_path);
        return std::nullopt;
    }
    auto validation = result.value().validate();
    if (!validation.has_value()) {
        toxtunnel::util::Logger::error("reload failed: invalid config in {}: {}", config_path,
                                       validation.error());
        return std::nullopt;
    }
    for (const auto& unknown : toxtunnel::util::find_unknown_config_keys(config_path)) {
        toxtunnel::util::Logger::warn("config: ignoring unknown key '{}' in {}", unknown.path,
                                      config_path);
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
/// Decide what to do about the data-dir guard's outcome.
///
/// Returns a process exit code when the caller must stop, or nullopt to carry
/// on. Three cases:
///  * acquired — carry on.
///  * already locked by a live daemon — never carry on: sharing a data_dir
///    means sharing the Tox identity, the inspect socket and known_servers.yaml.
///  * any other failure (cannot open, lock or write) — also never carry on. A
///    guard that failed for an unexpected reason gives no protection at all, so
///    "warn and start anyway" would quietly reintroduce exactly the two-daemon
///    corruption the lock exists to prevent. The escape hatch for a filesystem
///    that genuinely cannot host a lock (some network mounts) is explicit:
///    TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR=1.
///
/// Both cases exit 1, including under `--service`: with `Restart=on-failure`
/// the supervisor retries, which is the right recovery when the holder is a
/// racing predecessor that is about to exit. Exiting 0 would leave the unit
/// `active (exited)` forever and never retry.
[[nodiscard]] std::optional<int> handle_data_dir_conflict(
    const toxtunnel::util::PidFileGuard& guard, const std::filesystem::path& data_dir) {
    using Logger = toxtunnel::util::Logger;

    if (guard.active()) {
        return std::nullopt;
    }

    if (guard.conflicted()) {
        std::string who = "another toxtunnel process";
        if (guard.holder_pid() > 0) {
            who = "toxtunnel pid " + std::to_string(guard.holder_pid());
        }
        Logger::error(
            "data directory {} is already in use by {}. Two daemons cannot share one data_dir: "
            "they would share the Tox identity, the inspect socket and known_servers.yaml. Stop "
            "the other instance, or give this one its own data_dir.",
            data_dir.string(), who);
        return 1;
    }

    // Not a conflict, but the guard gave us nothing. Starting anyway would mean
    // running with no protection at all.
    if (const char* allow = std::getenv("TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR");
        allow != nullptr && std::string_view(allow) == "1") {
        Logger::warn(
            "Could not claim the data directory ({}); continuing anyway because "
            "TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR=1. Nothing stops a second daemon from using this "
            "data_dir, and `inspect` / `reload` may need TOXTUNNEL_INSPECT_PID / "
            "TOXTUNNEL_RELOAD_PID.",
            guard.error());
        return std::nullopt;
    }

    Logger::error(
        "Could not claim the data directory: {}. Refusing to start without it — an unlocked "
        "data_dir lets a second daemon corrupt the Tox identity and known_servers.yaml. Fix the "
        "permissions/filesystem, or set TOXTUNNEL_ALLOW_UNLOCKED_DATA_DIR=1 to override.",
        guard.error());
    return 1;
}

int run_server(const toxtunnel::Config& config, bool run_as_service,
               const std::string& config_path) {
    using Logger = toxtunnel::util::Logger;

    // Claim the data dir BEFORE initialize(): that call opens tox_save.dat, the
    // inspect socket and the resume store, none of which two daemons may share.
    // The guard also publishes our pid for inspect/reload discovery.
    toxtunnel::util::PidFileGuard pid_file(config.data_dir);
    if (auto rc = handle_data_dir_conflict(pid_file, config.data_dir); rc.has_value()) {
        return *rc;
    }

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

    // POSIX: reload_signals (SIGHUP) re-arms itself inside its handler, so
    // signal_ctx always has a pending op and signal_ctx.run() never returns
    // on its own. Explicitly stop the io_context here so run() unblocks.
    signals.async_wait([&server, &signal_ctx](const asio::error_code& ec, int signum) {
        if (!ec) {
            toxtunnel::util::Logger::info("Received signal {}, shutting down...", signum);
            server.stop();
            signal_ctx.stop();
        }
    });

    // Centralised reload entry point: re-read config from disk, run it through
    // the no-op-on-failure validation gate, then ask the server to apply the
    // reloadable subset. Used both by SIGHUP (POSIX) and the named-pipe
    // server (Windows). Safe to call from a non-IO thread because
    // TunnelServer::reload is itself thread-safe.
    auto do_reload = [&server, &config_path]() {
        auto new_cfg = reload_config_from_disk(config_path);
        if (!new_cfg)
            return;
        auto apply = server.reload(*new_cfg);
        if (!apply) {
            toxtunnel::util::Logger::error("reload rejected: {}", apply.error());
        }
    };

#if !defined(_WIN32)
    // POSIX: SIGHUP triggers reload. signal_set re-arms itself in the
    // callback so repeated SIGHUPs all fire. signal_ctx is a single-threaded
    // io_context, so the reload runs serialized with shutdown signals and
    // can't race with stop().
    asio::signal_set reload_signals(signal_ctx, SIGHUP);
    std::function<void(const asio::error_code&, int)> on_reload_signal =
        [&](const asio::error_code& ec, int /*signum*/) {
            if (ec)
                return;
            toxtunnel::util::Logger::info("SIGHUP received, reloading config from {}",
                                          config_path.empty() ? "<no config>" : config_path);
            do_reload();
            reload_signals.async_wait(on_reload_signal);
        };
    reload_signals.async_wait(on_reload_signal);
#else
    // Windows: stand up a named-pipe server that listens for "RELOAD\n" from
    // the `toxtunnel reload` subcommand. The pipe lives only as long as the
    // daemon; the client uses the same per-pid naming convention.
    WindowsReloadPipeServer reload_pipe(do_reload);
    reload_pipe.start();
#endif

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
    reload_pipe.stop();
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
int run_client(const toxtunnel::Config& config, bool run_as_service,
               const std::string& config_path) {
    using Logger = toxtunnel::util::Logger;

    // See run_server(): the data dir is claimed before anything opens it.
    toxtunnel::util::PidFileGuard pid_file(config.data_dir);
    if (auto rc = handle_data_dir_conflict(pid_file, config.data_dir); rc.has_value()) {
        return *rc;
    }

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

    auto do_reload = [&client, &config_path]() {
        auto new_cfg = reload_config_from_disk(config_path);
        if (!new_cfg)
            return;
        auto apply = client.reload(*new_cfg);
        if (!apply) {
            toxtunnel::util::Logger::error("reload rejected: {}", apply.error());
        } else if (!apply.value().warnings.empty()) {
            // Applied, but some added forwards could not listen. Distinct from
            // a rejection: the rest of the new config IS live.
            toxtunnel::util::Logger::error("reload applied with warnings: {}",
                                           apply.value().warnings);
        }
    };

#if !defined(_WIN32)
    asio::signal_set reload_signals(signal_ctx, SIGHUP);
    std::function<void(const asio::error_code&, int)> on_reload_signal =
        [&](const asio::error_code& ec, int /*signum*/) {
            if (ec)
                return;
            toxtunnel::util::Logger::info("SIGHUP received, reloading config from {}",
                                          config_path.empty() ? "<no config>" : config_path);
            do_reload();
            reload_signals.async_wait(on_reload_signal);
        };
    reload_signals.async_wait(on_reload_signal);
#else
    WindowsReloadPipeServer reload_pipe(do_reload);
    reload_pipe.start();
#endif

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
    reload_pipe.stop();
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
    std::vector<std::string> fallback_server_ids;
    std::string pipe_target;
    std::string print_id_data_dir;
    bool print_id_qr = false;
    bool print_id_color = false;
    bool run_as_service = false;

    std::string print_id_config_path;
    auto* print_id_cmd = app.add_subcommand("print-id", "Print local Tox ID");
    print_id_cmd->add_option("-d,--data-dir", print_id_data_dir,
                             "Data directory for loading/creating local Tox identity");
    print_id_cmd->add_option("-c,--config", print_id_config_path,
                             "Config file to resolve the data_dir from (same as the daemon)");
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

    // ----- `reload` ----------------------------------------------------------
    // Trigger a hot-reload of the running daemon's reloadable config subset
    // (server.rules_file contents, client.forwards, logging.level). On POSIX
    // this prints the equivalent `kill -HUP <pid>`; on Windows it writes
    // "RELOAD\n" to a per-pid named pipe served by the daemon.
    auto* reload_cmd =
        app.add_subcommand("reload", "Hot-reload rules/forwards/log-level on a running daemon");
    std::string reload_data_dir;
    std::string reload_config_path;
    reload_cmd->add_option("-d,--data-dir", reload_data_dir,
                           "Daemon data directory (holds toxtunnel.pid)");
    reload_cmd->add_option("-c,--config", reload_config_path,
                           "Read data_dir from this config file (overridden by --data-dir)");

    // ----- `config check` ----------------------------------------------------
    auto* config_cmd = app.add_subcommand("config", "Configuration helpers");
    auto* config_check_cmd =
        config_cmd->add_subcommand("check", "Parse and validate a config file without starting");
    std::string config_check_path;
    bool config_check_strict = false;
    config_check_cmd->add_option("-c,--config", config_check_path, "Config file to check")
        ->required();
    config_check_cmd->add_flag("--strict", config_check_strict,
                               "Exit non-zero when unknown keys are present, not just on "
                               "parse/validation errors");

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
    app.add_option("--server-id-fallback", fallback_server_ids,
                   "Fallback server Tox ID or alias (client mode). May be repeated; "
                   "tried in order if the primary stays offline.")
        ->take_all();
    app.add_option("--pipe", pipe_target, "Pipe mode target host:port (client mode)");
    std::string socks5_listen;
    app.add_option("--socks5", socks5_listen,
                   "Enable SOCKS5 / HTTP CONNECT listener at host:port (client mode)");
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
            const auto why = util::last_windows_service_error();
            std::cerr << "Failed to register Windows service"
                      << (why.empty() ? std::string(" (run as Administrator)") : ": " + why)
                      << "\n";
            return 1;
        }
        std::cerr << "Registered Windows service ToxTunnel.\n";
        return 0;
    }
    if (*uninstall_win_svc) {
        if (!util::unregister_packaged_toxtunnel_service()) {
            const auto why = util::last_windows_service_error();
            std::cerr << "Failed to unregister Windows service"
                      << (why.empty() ? std::string(" (run as Administrator)") : ": " + why)
                      << "\n";
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

    if (*config_cmd) {
        if (*config_check_cmd) {
            return cmd_config_check(config_check_path, config_check_strict);
        }
        std::cerr << "Unknown 'config' subcommand. Try --help.\n";
        return 2;
    }

    if (*reload_cmd) {
        auto reload_dir = resolve_servers_data_dir(reload_data_dir, reload_config_path);
        if (!reload_dir) {
            return 1;
        }
        return cmd_reload(*reload_dir);
    }

    if (*print_id_cmd) {
        if (print_id_color && !print_id_qr) {
            std::cerr << "--color requires --qr\n";
            return 1;
        }

        // Resolve the data_dir the same way `servers`/`inspect`/`reload` do:
        // explicit --data-dir wins, else --config's data_dir (either the
        // subcommand's own -c or the global -c preceding the subcommand), else
        // the platform default. This fixes the field-note #1 trap where
        // `toxtunnel -c client.yaml print-id` silently ignored the config and
        // minted a *second* identity in ~/.config/toxtunnel.
        const std::string& id_config_path =
            !print_id_config_path.empty() ? print_id_config_path : config_path;
        auto resolved_dir = resolve_servers_data_dir(print_id_data_dir, id_config_path);
        if (!resolved_dir) {
            return 1;
        }
        std::filesystem::path id_data_dir = *resolved_dir;

        // A read-only lookup should not silently create a durable identity.
        // We still support the documented bootstrap workflow (generate an
        // identity by pointing print-id at a fresh dir), but announce it so
        // the user is never surprised by a new key appearing on disk.
        std::error_code exists_ec;
        const auto save_path = id_data_dir / "tox_save.dat";
        const bool had_identity = std::filesystem::is_regular_file(save_path, exists_ec);
        if (!had_identity) {
            std::cerr << "No existing Tox identity at " << save_path.string()
                      << "; creating a new one.\n";
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

    // Defer log-level application until after merge_cli_overrides — that
    // function uses "is the value != the default" as a stand-in for "was
    // it set" (C-22 in the 2026-05-20 review), so passing `--log-level
    // info` (the default LogLevel value) would not override a non-info
    // YAML level. Capture the parsed level here, and apply it directly
    // to `config.logging.level` below.
    std::optional<util::LogLevel> cli_log_level;
    if (!log_level_str.empty()) {
        util::LogLevel level{};
        if (parse_log_level(log_level_str, level)) {
            cli_log_level = level;
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

    if (!fallback_server_ids.empty()) {
        // `--server-id-fallback` is repeatable; each value may be a Tox ID or
        // alias. Resolution happens in the same alias-resolution pass below.
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->fallback_server_ids = fallback_server_ids;
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

    if (!socks5_listen.empty()) {
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->socks5.enabled = true;
        overrides.client->socks5.listen = socks5_listen;
        has_overrides = true;
    }

    if (has_overrides) {
        config.merge_cli_overrides(overrides);
    }
    if (cli_log_level.has_value()) {
        config.logging.level = *cli_log_level;
    }

    // -----------------------------------------------------------------------
    // Resolve known-servers aliases in client.server_id and
    // client.fallback_server_ids (from YAML or `--server-id` /
    // `--server-id-fallback`) against the registry under the post-merge
    // data_dir. Single pass so the "Resolved alias …" message fires at most
    // once per id per run.
    // -----------------------------------------------------------------------
    if (auto alias_err = resolve_client_aliases(config)) {
        std::cerr << *alias_err << "\n";
        return 1;
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

    // Surface keys the parser will silently ignore. A typo (or a plausible but
    // non-existent setting like `tox.local_discovery_enabled`) otherwise looks
    // exactly like a working config.
    if (!config_path.empty()) {
        for (const auto& unknown : util::find_unknown_config_keys(config_path)) {
            Logger::warn("config: ignoring unknown key '{}' in {}", unknown.path, config_path);
        }
    }
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
                return run_server(config, true, config_path);
            }
            return run_client(config, true, config_path);
        });
    } else {
        if (config.is_server()) {
            exit_code = run_server(config, false, config_path);
        } else {
            exit_code = run_client(config, false, config_path);
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
        exit_code = run_client(config, run_as_service, config_path);
    }
#endif

    Logger::info("ToxTunnel exiting with code {}", exit_code);
    Logger::shutdown();

    return exit_code;
}
