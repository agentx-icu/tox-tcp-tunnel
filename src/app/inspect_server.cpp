#include "toxtunnel/app/inspect_server.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <system_error>

#include "toxtunnel/util/logger.hpp"

#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace toxtunnel::app {

namespace {

constexpr std::size_t kMaxRequestLine = 256;

// Hand-rolled JSON helpers — the request/reply shape is small and stable so
// pulling in a JSON dependency for this would be overkill.
std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c) & 0xff);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

void append_kv_string(std::string& out, std::string_view key, std::string_view value, bool& first) {
    if (!first) {
        out += ',';
    }
    first = false;
    out += '"';
    out += key;
    out += "\":\"";
    out += json_escape(value);
    out += '"';
}

void append_kv_num(std::string& out, std::string_view key, std::size_t value, bool& first) {
    if (!first) {
        out += ',';
    }
    first = false;
    out += '"';
    out += key;
    out += "\":";
    out += std::to_string(value);
}

std::string trim_view(std::string_view s) {
    auto begin = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    if (begin == std::string_view::npos) {
        return {};
    }
    return std::string(s.substr(begin, end - begin + 1));
}

enum class Request { Tunnels, Status, Invalid };

Request parse_request_line(std::string_view line) {
    const auto trimmed = trim_view(line);
    if (trimmed == "GET /tunnels") {
        return Request::Tunnels;
    }
    if (trimmed == "GET /status") {
        return Request::Status;
    }
    return Request::Invalid;
}

}  // namespace

// ===========================================================================
// Session handling (POSIX)
// ===========================================================================

#ifndef _WIN32

class InspectSession : public std::enable_shared_from_this<InspectSession> {
   public:
    InspectSession(asio::local::stream_protocol::socket socket, const InspectProviders& providers)
        : socket_(std::move(socket)), providers_(providers) {}

    void start() {
        auto self = shared_from_this();
        asio::async_read_until(
            socket_, asio::dynamic_buffer(buffer_, kMaxRequestLine), '\n',
            [self](const asio::error_code& ec, std::size_t bytes) { self->on_read(ec, bytes); });
    }

   private:
    void on_read(const asio::error_code& ec, std::size_t bytes) {
        if (ec) {
            return;
        }
        const auto req = parse_request_line(std::string_view(buffer_.data(), bytes));
        std::string reply;
        switch (req) {
            case Request::Tunnels:
                reply = InspectServer::render_tunnels_json(providers_);
                break;
            case Request::Status:
                reply = InspectServer::render_status_json(providers_);
                break;
            case Request::Invalid:
                reply = InspectServer::render_error_json("unknown request");
                break;
        }
        reply.push_back('\n');
        auto self = shared_from_this();
        // The dynamic_buffer + sent string must outlive the async write.
        auto out = std::make_shared<std::string>(std::move(reply));
        asio::async_write(socket_, asio::buffer(*out),
                          [self, out](const asio::error_code&, std::size_t) {
                              std::error_code shutdown_ec;
                              self->socket_.shutdown(
                                  asio::local::stream_protocol::socket::shutdown_both, shutdown_ec);
                          });
    }

    asio::local::stream_protocol::socket socket_;
    const InspectProviders& providers_;
    std::string buffer_;
};

#endif  // !_WIN32

// ===========================================================================
// InspectServer
// ===========================================================================

InspectServer::InspectServer() = default;

InspectServer::~InspectServer() {
    stop();
}

#ifndef _WIN32

util::Expected<void, std::string> InspectServer::start(asio::io_context& io_ctx,
                                                       const std::filesystem::path& data_dir,
                                                       InspectProviders providers) {
    std::lock_guard lock(mutex_);
    if (running_.load(std::memory_order_acquire)) {
        return util::unexpected(std::string("InspectServer already running"));
    }
    if (data_dir.empty()) {
        return util::unexpected(std::string("InspectServer: data_dir is empty"));
    }
    std::error_code mk_ec;
    std::filesystem::create_directories(data_dir, mk_ec);
    // create_directories returns false (not an error) when the dir already
    // exists; only a non-empty error_code is a real failure.
    if (mk_ec) {
        return util::unexpected(std::string("InspectServer: cannot create data_dir: ") +
                                mk_ec.message());
    }

    io_ctx_ = &io_ctx;
    providers_ = std::move(providers);
    const auto socket_path = data_dir / "toxtunnel.sock";
    endpoint_ = socket_path.string();

    // sun_path is bounded (108 on Linux, 104 on macOS). Refuse rather than
    // silently truncate — a truncated path would either bind to the wrong
    // place or fail with a confusing EINVAL deep inside async_accept.
    constexpr std::size_t kMaxSunPath = sizeof(::sockaddr_un::sun_path) - 1;
    if (endpoint_.size() > kMaxSunPath) {
        return util::unexpected(std::string("InspectServer: socket path too long (") +
                                std::to_string(endpoint_.size()) + " > " +
                                std::to_string(kMaxSunPath) + "): " + endpoint_);
    }

    // Unlink stale socket from a previous crash. EADDRINUSE on a leftover
    // sock file would otherwise brick restart.
    if (std::filesystem::exists(socket_path)) {
        std::error_code rm_ec;
        std::filesystem::remove(socket_path, rm_ec);
        if (rm_ec) {
            return util::unexpected(std::string("InspectServer: cannot remove stale socket ") +
                                    endpoint_ + ": " + rm_ec.message());
        }
    }

    try {
        acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(
            io_ctx, asio::local::stream_protocol::endpoint(endpoint_));
    } catch (const std::system_error& e) {
        return util::unexpected(std::string("InspectServer: bind failed: ") + e.what());
    }

    if (::chmod(endpoint_.c_str(), 0600) != 0) {
        util::Logger::warn("InspectServer: chmod 0600 on {} failed ({}); proceeding", endpoint_,
                           std::strerror(errno));
    }

    running_.store(true, std::memory_order_release);
    do_accept();
    util::Logger::info("Inspect IPC listening at {}", endpoint_);
    return {};
}

void InspectServer::stop() {
    std::lock_guard lock(mutex_);
    if (!running_.exchange(false)) {
        return;
    }
    if (acceptor_) {
        std::error_code ec;
        acceptor_->close(ec);
        acceptor_.reset();
    }
    if (!endpoint_.empty()) {
        std::error_code rm_ec;
        std::filesystem::remove(endpoint_, rm_ec);
    }
    io_ctx_ = nullptr;
}

void InspectServer::do_accept() {
    if (!running_.load(std::memory_order_acquire) || !acceptor_) {
        return;
    }
    acceptor_->async_accept(
        [this](const asio::error_code& ec, asio::local::stream_protocol::socket socket) {
            if (ec) {
                if (running_.load(std::memory_order_acquire)) {
                    util::Logger::debug("InspectServer accept ended: {}", ec.message());
                }
                return;
            }
            auto session = std::make_shared<InspectSession>(std::move(socket), providers_);
            session->start();
            do_accept();
        });
}

#else  // _WIN32

namespace {

// Build a security descriptor that grants access only to the current user,
// matching POSIX chmod 0600 semantics for the named pipe.
PSECURITY_DESCRIPTOR build_current_user_sd() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return nullptr;
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buf(size);
    if (!GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        CloseHandle(token);
        return nullptr;
    }
    CloseHandle(token);
    auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());
    LPSTR sid_str = nullptr;
    if (!ConvertSidToStringSidA(user->User.Sid, &sid_str)) {
        return nullptr;
    }
    // D: discretionary ACL, single ACE granting full access to current user.
    std::string sddl = std::string("D:(A;;GA;;;") + sid_str + ")";
    LocalFree(sid_str);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                              nullptr)) {
        return nullptr;
    }
    return sd;
}

void serve_one_connection(HANDLE pipe, const InspectProviders& providers) {
    char buf[kMaxRequestLine + 1] = {};
    DWORD read = 0;
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr) || read == 0) {
        return;
    }
    std::string_view view(buf, read);
    auto newline = view.find('\n');
    if (newline != std::string_view::npos) {
        view = view.substr(0, newline);
    }
    const auto req = parse_request_line(view);
    std::string reply;
    switch (req) {
        case Request::Tunnels:
            reply = InspectServer::render_tunnels_json(providers);
            break;
        case Request::Status:
            reply = InspectServer::render_status_json(providers);
            break;
        case Request::Invalid:
            reply = InspectServer::render_error_json("unknown request");
            break;
    }
    reply.push_back('\n');
    DWORD written = 0;
    WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &written, nullptr);
    FlushFileBuffers(pipe);
}

}  // namespace

util::Expected<void, std::string> InspectServer::start(asio::io_context& io_ctx,
                                                       const std::filesystem::path& /*data_dir*/,
                                                       InspectProviders providers) {
    std::lock_guard lock(mutex_);
    if (running_.load(std::memory_order_acquire)) {
        return util::unexpected(std::string("InspectServer already running"));
    }
    io_ctx_ = &io_ctx;
    providers_ = std::move(providers);
    endpoint_ = "\\\\.\\pipe\\toxtunnel-" + std::to_string(GetCurrentProcessId());

    running_.store(true, std::memory_order_release);

    auto pipe_name = endpoint_;
    auto providers_copy = providers_;
    pipe_thread_ = std::thread([this, pipe_name, providers_copy] {
        while (running_.load(std::memory_order_acquire)) {
            PSECURITY_DESCRIPTOR sd = build_current_user_sd();
            SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
            // PIPE_UNLIMITED_INSTANCES (S22 in the 2026-05-20 follow-up):
            // the previous nMaxInstances = 1 meant a stale handle from a
            // racing client could keep CreateNamedPipeA returning
            // ERROR_PIPE_BUSY until the OS reclaimed it. With unlimited
            // instances the new request is always accepted; we still only
            // ever have one connection in flight here because the loop is
            // single-threaded.
            HANDLE pipe =
                CreateNamedPipeA(pipe_name.c_str(), PIPE_ACCESS_DUPLEX,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                 PIPE_UNLIMITED_INSTANCES, 8192, 8192, 0, sd ? &sa : nullptr);
            if (sd) {
                LocalFree(sd);
            }
            if (pipe == INVALID_HANDLE_VALUE) {
                // Don't permanently brick IPC just because one create
                // call failed (transient EMFILE, racing client holding
                // the pipe instance, etc.). Sleep briefly and retry —
                // breaking out of the loop here is what the previous
                // `return` did, and it left the daemon with no inspect
                // endpoint for the rest of its lifetime.
                const auto err = GetLastError();
                util::Logger::warn("InspectServer: CreateNamedPipe failed ({}); retrying", err);
                for (int i = 0; i < 100 && running_.load(std::memory_order_acquire); ++i) {
                    Sleep(10);
                }
                continue;
            }
            const BOOL connected =
                ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
            if (!running_.load(std::memory_order_acquire)) {
                CloseHandle(pipe);
                return;
            }
            if (connected) {
                serve_one_connection(pipe, providers_copy);
            }
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    });

    util::Logger::info("Inspect IPC listening at {}", endpoint_);
    return {};
}

void InspectServer::stop() {
    std::lock_guard lock(mutex_);
    if (!running_.exchange(false)) {
        return;
    }
    // Unblock any pending ConnectNamedPipe in the pump thread.
    HANDLE wake = CreateFileA(endpoint_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (wake != INVALID_HANDLE_VALUE) {
        CloseHandle(wake);
    }
    if (pipe_thread_.joinable()) {
        pipe_thread_.join();
    }
    io_ctx_ = nullptr;
}

void InspectServer::do_accept() {}

#endif  // _WIN32

void InspectServer::handle_session(std::shared_ptr<InspectSession>) {}

// ===========================================================================
// JSON rendering (platform-independent)
// ===========================================================================

std::string InspectServer::render_status_json(const InspectProviders& providers) {
    std::string out;
    out.reserve(128);
    out += '{';
    bool first = true;
    if (providers.mode) {
        append_kv_string(out, "mode", providers.mode(), first);
    }
    if (providers.version) {
        append_kv_string(out, "version", providers.version(), first);
    }
    if (providers.friends_online) {
        append_kv_num(out, "friends_online", providers.friends_online(), first);
    }
    if (providers.snapshot) {
        const auto snap = providers.snapshot();
        append_kv_num(out, "tunnels_active", snap.tunnels.size(), first);
        append_kv_num(out, "bytes_in", snap.bytes_in, first);
        append_kv_num(out, "bytes_out", snap.bytes_out, first);
    }
    out += '}';
    return out;
}

std::string InspectServer::render_tunnels_json(const InspectProviders& providers) {
    std::string out;
    out.reserve(256);
    out += '{';
    bool first = true;
    if (providers.mode) {
        append_kv_string(out, "mode", providers.mode(), first);
    }
    if (providers.version) {
        append_kv_string(out, "version", providers.version(), first);
    }
    if (providers.friends_online) {
        append_kv_num(out, "friends_online", providers.friends_online(), first);
    }
    if (!first) {
        out += ',';
    }
    out += "\"tunnels\":[";

    if (providers.snapshot) {
        const auto snap = providers.snapshot();
        bool first_tunnel = true;
        for (const auto& t : snap.tunnels) {
            if (!first_tunnel) {
                out += ',';
            }
            first_tunnel = false;
            out += '{';
            bool tfirst = true;
            append_kv_num(out, "id", t.id, tfirst);
            if (providers.friend_pk_prefix) {
                const auto pk = providers.friend_pk_prefix(t.id);
                if (!pk.empty()) {
                    append_kv_string(out, "friend_pk_prefix", pk, tfirst);
                }
            }
            // target = "host:port" so the table renderer doesn't have to
            // re-stitch the pieces.
            std::string target = t.target_host;
            target += ':';
            target += std::to_string(t.target_port);
            append_kv_string(out, "target", target, tfirst);
            append_kv_string(out, "state", t.state, tfirst);
            append_kv_num(out, "bytes_in", t.bytes_in, tfirst);
            append_kv_num(out, "bytes_out", t.bytes_out, tfirst);
            // Only emit idle_seconds when we actually measured it — a value of
            // zero on a never-active tunnel is misleading otherwise.
            if (t.idle_seconds.count() > 0) {
                append_kv_num(out, "idle_seconds", static_cast<std::size_t>(t.idle_seconds.count()),
                              tfirst);
            }
            out += '}';
        }
    }
    out += "]}";
    return out;
}

std::string InspectServer::render_error_json(std::string_view message) {
    std::string out = "{\"error\":\"";
    out += json_escape(message);
    out += "\"}";
    return out;
}

}  // namespace toxtunnel::app
