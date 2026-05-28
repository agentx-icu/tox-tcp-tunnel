#include "toxtunnel/app/socks5_listener.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <utility>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::app {

// ---------------------------------------------------------------------------
// SOCKS5 parsers
// ---------------------------------------------------------------------------

Socks5GreetingResult parse_socks5_greeting(const uint8_t* data, std::size_t length) {
    Socks5GreetingResult out;
    if (length < 2) {
        return out;
    }
    if (data[0] != socks5::kVersion) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }
    const std::size_t nmethods = data[1];
    // RFC 1928: nmethods == 0 means the client offers no methods; treat as malformed
    // because no negotiation is possible.
    if (nmethods == 0) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }
    const std::size_t total = 2 + nmethods;
    if (length < total) {
        return out;
    }
    out.methods.assign(data + 2, data + 2 + nmethods);
    out.consumed = total;
    out.status = Socks5ParseStatus::Ok;
    return out;
}

Socks5RequestResult parse_socks5_request(const uint8_t* data, std::size_t length) {
    Socks5RequestResult out;
    if (length < 4) {
        return out;
    }
    if (data[0] != socks5::kVersion) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }
    out.cmd = data[1];
    if (data[2] != 0x00) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }
    out.atyp = data[3];

    if (out.cmd != socks5::kCmdConnect) {
        out.status = Socks5ParseStatus::Malformed;
        out.reply_code = socks5::kReplyCmdNotSupported;
        return out;
    }

    std::size_t addr_offset = 4;
    std::size_t addr_len = 0;
    std::string host;

    switch (out.atyp) {
        case socks5::kAtypIPv4: {
            if (length < 4 + 4 + 2) {
                return out;
            }
            host.reserve(15);
            host.append(std::to_string(data[4]));
            host.push_back('.');
            host.append(std::to_string(data[5]));
            host.push_back('.');
            host.append(std::to_string(data[6]));
            host.push_back('.');
            host.append(std::to_string(data[7]));
            addr_len = 4;
            break;
        }
        case socks5::kAtypDomain: {
            if (length < 5) {
                return out;
            }
            const std::size_t name_len = data[4];
            if (name_len == 0) {
                out.status = Socks5ParseStatus::Malformed;
                return out;
            }
            const std::size_t total = 4 + 1 + name_len + 2;
            if (length < total) {
                return out;
            }
            host.assign(reinterpret_cast<const char*>(data + 5), name_len);
            addr_offset = 5;
            addr_len = name_len;
            break;
        }
        case socks5::kAtypIPv6: {
            if (length < 4 + 16 + 2) {
                return out;
            }
            // Compose canonical-ish IPv6 string (uncompressed). asio's
            // make_address handles both compressed and uncompressed forms, so
            // a verbose hex:group form is sufficient for downstream resolve.
            char buf[40];
            std::snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x", (data[4] << 8) | data[5],
                          (data[6] << 8) | data[7], (data[8] << 8) | data[9],
                          (data[10] << 8) | data[11], (data[12] << 8) | data[13],
                          (data[14] << 8) | data[15], (data[16] << 8) | data[17],
                          (data[18] << 8) | data[19]);
            host.assign(buf);
            addr_len = 16;
            break;
        }
        default:
            out.status = Socks5ParseStatus::Malformed;
            out.reply_code = socks5::kReplyAtypNotSupported;
            return out;
    }

    const std::size_t port_offset = addr_offset + addr_len;
    if (length < port_offset + 2) {
        return out;
    }
    out.host = std::move(host);
    out.port = static_cast<uint16_t>((data[port_offset] << 8) | data[port_offset + 1]);
    out.consumed = port_offset + 2;
    out.status = Socks5ParseStatus::Ok;
    return out;
}

std::vector<uint8_t> encode_socks5_reply(uint8_t reply_code) {
    return {
        socks5::kVersion, reply_code, 0x00, socks5::kAtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

// ---------------------------------------------------------------------------
// HTTP CONNECT parser
// ---------------------------------------------------------------------------

HttpConnectResult parse_http_connect(const uint8_t* data, std::size_t length) {
    HttpConnectResult out;
    const std::string_view view(reinterpret_cast<const char*>(data), length);
    const auto header_end = view.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        // Cap waiting bytes to avoid an open-ended buffer for clients that
        // speak gibberish without ever terminating headers.
        if (length > 8192) {
            out.status = Socks5ParseStatus::Malformed;
        }
        return out;
    }

    const std::string_view headers = view.substr(0, header_end);
    const auto first_eol = headers.find("\r\n");
    const std::string_view request_line =
        first_eol == std::string_view::npos ? headers : headers.substr(0, first_eol);

    constexpr std::string_view kConnect = "CONNECT ";
    if (request_line.size() < kConnect.size() ||
        request_line.substr(0, kConnect.size()) != kConnect) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }

    const auto sp_after_uri = request_line.find(' ', kConnect.size());
    if (sp_after_uri == std::string_view::npos) {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }
    const std::string_view authority =
        request_line.substr(kConnect.size(), sp_after_uri - kConnect.size());
    const std::string_view http_version = request_line.substr(sp_after_uri + 1);
    if (http_version.size() < 5 || http_version.substr(0, 5) != "HTTP/") {
        out.status = Socks5ParseStatus::Malformed;
        return out;
    }

    // CONNECT target is "host:port" — bracketed IPv6 ("[::1]:443") is allowed
    // by RFC 7230 §5.3.3.
    if (!authority.empty() && authority.front() == '[') {
        const auto close_bracket = authority.find(']');
        if (close_bracket == std::string_view::npos || close_bracket + 1 >= authority.size() ||
            authority[close_bracket + 1] != ':') {
            out.status = Socks5ParseStatus::Malformed;
            return out;
        }
        out.host.assign(authority.substr(1, close_bracket - 1));
        const auto port_sv = authority.substr(close_bracket + 2);
        unsigned int parsed = 0;
        auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed);
        if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || parsed == 0 ||
            parsed > 65535) {
            out.status = Socks5ParseStatus::Malformed;
            return out;
        }
        out.port = static_cast<uint16_t>(parsed);
    } else {
        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 >= authority.size()) {
            out.status = Socks5ParseStatus::Malformed;
            return out;
        }
        out.host.assign(authority.substr(0, colon));
        const auto port_sv = authority.substr(colon + 1);
        unsigned int parsed = 0;
        auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed);
        if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || parsed == 0 ||
            parsed > 65535) {
            out.status = Socks5ParseStatus::Malformed;
            return out;
        }
        out.port = static_cast<uint16_t>(parsed);
    }

    out.consumed = header_end + 4;
    out.status = Socks5ParseStatus::Ok;
    return out;
}

// ---------------------------------------------------------------------------
// Listener — per-connection session state machine
// ---------------------------------------------------------------------------

namespace {

enum class Protocol : uint8_t { Unknown, Socks5, HttpConnect };

enum class Socks5Phase : uint8_t { Greeting, Request, Streaming };

// Per-accepted-connection state. Lives via shared_ptr captured in the
// async-read continuation; destroyed once the parser completes (success path
// hands the connection off to the tunnel and clears the on_data callback, and
// the on_disconnect callback releases the final reference on failure).
struct Socks5Session : std::enable_shared_from_this<Socks5Session> {
    std::shared_ptr<core::TcpConnection> conn;
    OpenTunnelFn open_tunnel;
    Protocol protocol = Protocol::Unknown;
    Socks5Phase socks5_phase = Socks5Phase::Greeting;
    std::vector<uint8_t> buffer;

    void send_reply(std::vector<uint8_t> bytes) {
        if (conn && !bytes.empty()) {
            (void)conn->write(bytes.data(), bytes.size());
        }
    }

    void send_http_reply(std::string_view status_line) {
        std::string reply;
        reply.append("HTTP/1.1 ");
        reply.append(status_line);
        reply.append("\r\n\r\n");
        if (conn) {
            (void)conn->write(reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
        }
    }

    void reject_and_close(uint8_t socks5_reply, std::string_view http_reply) {
        if (protocol == Protocol::Socks5) {
            send_reply(encode_socks5_reply(socks5_reply));
        } else if (protocol == Protocol::HttpConnect) {
            send_http_reply(http_reply);
        }
        if (conn) {
            conn->close();
        }
    }

    void handoff_to_tunnel(std::string host, uint16_t port) {
        // Detach our on_data hook before the tunnel layer attaches its own.
        // Any bytes we already read past the handshake live in `buffer` and
        // must be passed to the tunnel as initial payload — naive clients
        // (and HTTP CONNECT clients in particular) often pipeline the
        // request and the first stream bytes into one TCP segment.
        auto self_conn = conn;
        auto self = shared_from_this();
        conn->set_on_data(nullptr);
        conn->set_on_disconnect(nullptr);
        // Also detach the EOF hook the session installed at accept time. Left
        // wired, a client half-close after handoff would fire it and null
        // session->conn, so the open_tunnel completion below would see a null
        // conn and silently skip the SOCKS5 / HTTP CONNECT success reply,
        // stalling the handshake. The tunnel layer installs its own EOF hook.
        conn->set_on_read_eof(nullptr);

        const auto sniffed_protocol = protocol;
        std::vector<uint8_t> initial_payload = std::move(buffer);
        buffer.clear();

        open_tunnel(std::move(self_conn), std::move(host), port, std::move(initial_payload),
                    [self, sniffed_protocol](bool connected) {
                        // Reply with the protocol-appropriate success/failure
                        // line once the tunnel layer reports back. The session
                        // is otherwise inert at this point.
                        if (!self->conn) {
                            return;
                        }
                        if (sniffed_protocol == Protocol::Socks5) {
                            self->send_reply(encode_socks5_reply(
                                connected ? socks5::kReplySuccess : socks5::kReplyHostUnreachable));
                            if (!connected) {
                                self->conn->close();
                            }
                        } else if (sniffed_protocol == Protocol::HttpConnect) {
                            if (connected) {
                                self->send_http_reply("200 Connection Established");
                            } else {
                                self->send_http_reply("502 Bad Gateway");
                                self->conn->close();
                            }
                        }
                    });
    }
};

void try_advance(const std::shared_ptr<Socks5Session>& session) {
    while (true) {
        if (session->protocol == Protocol::Unknown) {
            if (session->buffer.empty()) {
                return;
            }
            session->protocol = session->buffer.front() == socks5::kVersion ? Protocol::Socks5
                                                                            : Protocol::HttpConnect;
        }

        if (session->protocol == Protocol::Socks5) {
            if (session->socks5_phase == Socks5Phase::Greeting) {
                auto r = parse_socks5_greeting(session->buffer.data(), session->buffer.size());
                if (r.status == Socks5ParseStatus::NeedMore) {
                    return;
                }
                if (r.status == Socks5ParseStatus::Malformed) {
                    session->reject_and_close(socks5::kReplyGeneralFailure, "400 Bad Request");
                    return;
                }
                const bool no_auth_offered = std::find(r.methods.begin(), r.methods.end(),
                                                       socks5::kAuthNone) != r.methods.end();
                session->buffer.erase(
                    session->buffer.begin(),
                    session->buffer.begin() + static_cast<std::ptrdiff_t>(r.consumed));
                if (!no_auth_offered) {
                    session->send_reply({socks5::kVersion, socks5::kAuthNoAcceptable});
                    if (session->conn) {
                        session->conn->close();
                    }
                    return;
                }
                session->send_reply({socks5::kVersion, socks5::kAuthNone});
                session->socks5_phase = Socks5Phase::Request;
                continue;
            }

            if (session->socks5_phase == Socks5Phase::Request) {
                auto r = parse_socks5_request(session->buffer.data(), session->buffer.size());
                if (r.status == Socks5ParseStatus::NeedMore) {
                    return;
                }
                if (r.status == Socks5ParseStatus::Malformed) {
                    session->send_reply(encode_socks5_reply(r.reply_code));
                    if (session->conn) {
                        session->conn->close();
                    }
                    return;
                }
                session->buffer.erase(
                    session->buffer.begin(),
                    session->buffer.begin() + static_cast<std::ptrdiff_t>(r.consumed));
                session->socks5_phase = Socks5Phase::Streaming;
                session->handoff_to_tunnel(std::move(r.host), r.port);
                return;
            }

            return;
        }

        // HTTP CONNECT path
        auto r = parse_http_connect(session->buffer.data(), session->buffer.size());
        if (r.status == Socks5ParseStatus::NeedMore) {
            return;
        }
        if (r.status == Socks5ParseStatus::Malformed) {
            session->reject_and_close(socks5::kReplyGeneralFailure, "400 Bad Request");
            return;
        }
        session->buffer.erase(session->buffer.begin(),
                              session->buffer.begin() + static_cast<std::ptrdiff_t>(r.consumed));
        session->handoff_to_tunnel(std::move(r.host), r.port);
        return;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Socks5Listener
// ---------------------------------------------------------------------------

Socks5Listener::~Socks5Listener() {
    stop();
}

std::string Socks5Listener::start(asio::io_context& io_ctx, const std::string& host, uint16_t port,
                                  OpenTunnelFn open_tunnel) {
    if (running_) {
        return "Socks5Listener already running";
    }
    io_ctx_ = &io_ctx;
    open_tunnel_ = std::move(open_tunnel);

    asio::error_code ec;
    asio::ip::address addr = asio::ip::make_address(host, ec);
    if (ec) {
        // Permit hostnames via a resolver fallback. Listeners typically bind a
        // numeric IP (e.g. 127.0.0.1) but `localhost` is convenient.
        asio::ip::tcp::resolver resolver(io_ctx);
        auto results = resolver.resolve(host, std::to_string(port), ec);
        if (ec || results.empty()) {
            return "Invalid socks5.listen host '" + host + "': " + ec.message();
        }
        addr = results.begin()->endpoint().address();
        ec.clear();
    }

    // SOCKS5 v1 has no authentication, so a non-loopback bind would expose
    // an open proxy to anyone on the network. Config-level validation
    // (util::is_loopback_host) catches the YAML-supplied path, but the
    // listener's own contract is the right place to enforce this — any
    // caller that constructs Socks5Listener directly (tests, future code)
    // must hit the same guard (C-7 in the 2026-05-20 review).
    if (!addr.is_loopback()) {
        return "Socks5Listener: refused to bind non-loopback address " + addr.to_string() +
               " — SOCKS5 has no authentication";
    }

    asio::ip::tcp::endpoint endpoint(addr, port);
    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(io_ctx);
    acceptor_->open(endpoint.protocol(), ec);
    if (ec) {
        acceptor_.reset();
        return "acceptor.open: " + ec.message();
    }
    acceptor_->set_option(asio::socket_base::reuse_address(true), ec);
    acceptor_->bind(endpoint, ec);
    if (ec) {
        acceptor_.reset();
        return "acceptor.bind " + host + ":" + std::to_string(port) + ": " + ec.message();
    }
    acceptor_->listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        acceptor_.reset();
        return "acceptor.listen: " + ec.message();
    }

    bound_port_ = acceptor_->local_endpoint().port();
    running_ = true;
    do_accept();
    return {};
}

void Socks5Listener::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    if (acceptor_) {
        asio::error_code ec;
        acceptor_->cancel(ec);
        acceptor_->close(ec);
        acceptor_.reset();
    }
}

void Socks5Listener::do_accept() {
    if (!acceptor_ || !running_) {
        return;
    }
    // M-09: capture a weak_ptr, not `this`. If the listener is destroyed while
    // this accept is still queued on the io_context, the handler locks an empty
    // weak and returns instead of touching freed state.
    std::weak_ptr<Socks5Listener> weak = weak_from_this();
    acceptor_->async_accept([weak](const asio::error_code& ec, asio::ip::tcp::socket sock) {
        auto self = weak.lock();
        if (!self) {
            return;  // Listener destroyed before this accept completed.
        }
        if (ec) {
            if (self->running_) {
                util::Logger::debug("Socks5Listener accept error: {}", ec.message());
                self->do_accept();
            }
            return;
        }
        auto conn = std::make_shared<core::TcpConnection>(std::move(sock));
        auto session = std::make_shared<Socks5Session>();
        session->conn = conn;
        session->open_tunnel = self->open_tunnel_;

        // The connection's on_data callback keeps the session alive across
        // async-read callbacks; on_disconnect clears the cycle if the peer
        // hangs up before the handshake completes. handoff_to_tunnel clears
        // both callbacks once it takes over.
        conn->set_on_data([session](const uint8_t* data, std::size_t length) {
            session->buffer.insert(session->buffer.end(), data, data + length);
            try_advance(session);
        });
        conn->set_on_read_eof([session]() { session->conn.reset(); });
        conn->set_on_disconnect(
            [session](const std::error_code& /*ec*/) { session->conn.reset(); });
        conn->start_read();
        self->do_accept();
    });
}

}  // namespace toxtunnel::app
