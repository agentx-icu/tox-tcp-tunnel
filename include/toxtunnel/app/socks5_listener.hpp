#pragma once

#include <asio.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "toxtunnel/core/tcp_connection.hpp"

namespace toxtunnel::app {

// ---------------------------------------------------------------------------
// SOCKS5 wire constants (RFC 1928)
// ---------------------------------------------------------------------------

namespace socks5 {

constexpr uint8_t kVersion = 0x05;

constexpr uint8_t kAuthNone = 0x00;
constexpr uint8_t kAuthNoAcceptable = 0xFF;

constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdBind = 0x02;
constexpr uint8_t kCmdUdpAssociate = 0x03;

constexpr uint8_t kAtypIPv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIPv6 = 0x04;

constexpr uint8_t kReplySuccess = 0x00;
constexpr uint8_t kReplyGeneralFailure = 0x01;
constexpr uint8_t kReplyConnNotAllowed = 0x02;
constexpr uint8_t kReplyHostUnreachable = 0x04;
constexpr uint8_t kReplyConnRefused = 0x05;
constexpr uint8_t kReplyCmdNotSupported = 0x07;
constexpr uint8_t kReplyAtypNotSupported = 0x08;

}  // namespace socks5

// ---------------------------------------------------------------------------
// Parse helpers (pure, no I/O) — exposed in the header so unit tests can
// drive the protocol state machine without spinning a real TCP socket.
// ---------------------------------------------------------------------------

enum class Socks5ParseStatus : uint8_t {
    Ok,         ///< Parsed a complete message.
    NeedMore,   ///< Buffer prefix valid; need additional bytes.
    Malformed,  ///< Buffer is not a valid prefix of the expected message.
};

/// Result of parsing the SOCKS5 method-negotiation greeting
/// (`[ver=0x05][nmethods][methods...]`).
struct Socks5GreetingResult {
    Socks5ParseStatus status = Socks5ParseStatus::NeedMore;
    std::vector<uint8_t> methods;
    std::size_t consumed = 0;
};

/// Parse the SOCKS5 client greeting. The first byte MUST already be 0x05;
/// callers detect protocol via that sniff before invoking this.
[[nodiscard]] Socks5GreetingResult parse_socks5_greeting(const uint8_t* data, std::size_t length);

/// Result of parsing the SOCKS5 CONNECT request.
struct Socks5RequestResult {
    Socks5ParseStatus status = Socks5ParseStatus::NeedMore;
    uint8_t cmd = 0;    ///< Command byte (validated == kCmdConnect on success).
    uint8_t atyp = 0;   ///< Address type that was decoded.
    std::string host;   ///< Destination host (dotted IPv4, bracket-less IPv6 string, or DNS name).
    uint16_t port = 0;  ///< Destination port.
    std::size_t consumed = 0;
    /// Set when `status == Malformed` to indicate which SOCKS5 reply code the
    /// caller should send (e.g. `kReplyCmdNotSupported` for BIND).
    uint8_t reply_code = socks5::kReplyGeneralFailure;
};

/// Parse the SOCKS5 request: `[ver][cmd][rsv=0][atyp][addr][port:2]`.
/// Only CMD == CONNECT is supported; other commands return Malformed with
/// reply_code = kReplyCmdNotSupported so the caller can respond properly.
[[nodiscard]] Socks5RequestResult parse_socks5_request(const uint8_t* data, std::size_t length);

/// Encode a SOCKS5 reply frame `[ver=0x05][rep][rsv=0][atyp=0x01][bind=0.0.0.0][port=0]`.
/// We always emit an IPv4 bound address of 0.0.0.0:0 — RFC 1928 lets the client
/// treat the bound endpoint as opaque, and the destination has already been
/// chosen on the request side.
[[nodiscard]] std::vector<uint8_t> encode_socks5_reply(uint8_t reply_code);

/// Result of parsing an HTTP CONNECT request line + headers.
struct HttpConnectResult {
    Socks5ParseStatus status = Socks5ParseStatus::NeedMore;
    std::string host;
    uint16_t port = 0;
    std::size_t consumed = 0;
};

/// Parse an HTTP CONNECT request of the form
/// `CONNECT host:port HTTP/1.1\r\n... \r\n\r\n`.
/// Returns `NeedMore` until the terminating `\r\n\r\n` is seen, then `Ok` on
/// a valid request or `Malformed` if the request line is wrong. Headers other
/// than the request line and Host: are ignored — proxy-auth is intentionally
/// not implemented in v1.
[[nodiscard]] HttpConnectResult parse_http_connect(const uint8_t* data, std::size_t length);

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// Callback invoked when the listener has fully parsed a destination and is
/// ready to hand off the TCP socket to the tunnel layer.
///
/// The implementor must:
///   - Open an outbound tunnel to (host, port) through whichever transport
///     it manages.
///   - Wire the supplied `conn` to that tunnel (start_read on connect, route
///     bytes, etc.).
///   - Forward any `initial_payload` bytes upstream as the first tunnel write
///     once the tunnel reaches Connected. These are bytes that already arrived
///     on `conn` (pipelined past the handshake) and were buffered by the
///     listener. Naive clients that send e.g. a TLS ClientHello immediately
///     after `CONNECT host:port` without waiting for `200 OK` land here.
///   - Invoke `on_tunnel_state` exactly once: `TunnelOpenOutcome::Connected`
///     once the tunnel reaches Connected (so the listener can write the
///     protocol-specific success reply), or the matching failure outcome on
///     any pre-connected error.
///
/// Encapsulating the wiring behind a callback keeps Socks5Listener free of
/// TunnelClient dependencies and trivially testable.

/// Why the tunnel open ended, carried back so the listener can answer with the
/// right SOCKS5 reply code instead of a blanket failure. A server-side rules
/// denial in particular must surface as SOCKS5 0x02 ("connection not allowed
/// by ruleset") — that is the code operators are told to look for when
/// `rules.yaml` is the thing rejecting a destination.
enum class TunnelOpenOutcome : std::uint8_t {
    Connected,    ///< tunnel reached Connected
    Denied,       ///< server POLICY rejected the open (TUNNEL_ERROR code 1)
    Unreachable,  ///< general non-policy open failure (code 2)
    Refused,      ///< the target actively refused the TCP connect (code 3)
    Failed,       ///< anything else (client offline, no tunnel ids, unknown error)
};

/// Classify a peer's `TUNNEL_ERROR` into an open outcome.
///
/// WIRE CONTRACT (v0.4.12+). The three codes are disjoint *categories*, so a
/// client can act on the number alone:
///
///   1 — policy-denied open: rules denial, rate limit, concurrent-tunnel cap.
///   2 — general non-policy open failure: DNS failure, any connect failure that
///       is not a refusal, "Tunnel ID in use", target lost before the tunnel was
///       established. Deliberately NOT "cannot reach target" — it is the whole
///       non-policy bucket, and new members belong here unless they fit 1 or 3.
///   3 — the target actively refused the connection, and nothing else.
///
/// Before v0.4.12 code 3 conflated policy denials, connect failures and
/// teardowns, which is why a rate-limited open reached a SOCKS5 client as 0x04
/// "host unreachable" — indistinguishable from a dead target.
///
/// Pure by design: the whole old/new compatibility matrix is then testable
/// without a live tunnel, and the classification has exactly one definition.
[[nodiscard]] inline TunnelOpenOutcome tunnel_open_outcome_for(std::uint8_t error_code,
                                                               std::string_view description) {
    switch (error_code) {
        case 1:
            return TunnelOpenOutcome::Denied;
        case 2:
            return TunnelOpenOutcome::Unreachable;
        case 3:
            // COMPATIBILITY SHIM for servers <= v0.4.11, where code 3 was the
            // grab-bag. Safe to delete once no such server is in service.
            //
            // Exact matches only, against the two literals those releases
            // actually shipped for policy denials. Description matching is
            // unsuitable as the primary protocol contract — which is the whole
            // point of the numeric scheme above — but matching a known released
            // string is exactly what backward compatibility requires.
            if (description == "Rate limit exceeded" || description == "Tunnel limit exceeded") {
                return TunnelOpenOutcome::Denied;
            }
            // Old servers put the platform's connect message here, so a genuine
            // refusal still has to be recognised by substring. New servers emit
            // the fixed lowercase literal "TCP connection refused: " precisely so
            // that this keeps matching. Note this cannot be promoted to an
            // unconditional "code 3 means refused": an OLD server also sends 3
            // for a connect *timeout*, which must stay Unreachable.
            if (description.find("refused") != std::string_view::npos) {
                return TunnelOpenOutcome::Refused;
            }
            return TunnelOpenOutcome::Unreachable;
        default:
            // Includes 0 ("no TUNNEL_ERROR seen"), so a tunnel that failed
            // without one is a generic failure rather than a fabricated reason.
            return TunnelOpenOutcome::Failed;
    }
}

using OpenTunnelFn = std::function<void(std::shared_ptr<core::TcpConnection> conn, std::string host,
                                        uint16_t port, std::vector<uint8_t> initial_payload,
                                        std::function<void(TunnelOpenOutcome)> on_tunnel_state)>;

/// Map an open outcome onto the SOCKS5 reply byte (RFC 1928 §6).
[[nodiscard]] constexpr uint8_t socks5_reply_for(TunnelOpenOutcome outcome) noexcept {
    switch (outcome) {
        case TunnelOpenOutcome::Connected:
            return socks5::kReplySuccess;
        case TunnelOpenOutcome::Denied:
            return socks5::kReplyConnNotAllowed;
        case TunnelOpenOutcome::Unreachable:
            return socks5::kReplyHostUnreachable;
        case TunnelOpenOutcome::Refused:
            return socks5::kReplyConnRefused;
        case TunnelOpenOutcome::Failed:
            break;
    }
    return socks5::kReplyGeneralFailure;
}

/// Map an open outcome onto the HTTP CONNECT status line.
[[nodiscard]] constexpr const char* http_status_for(TunnelOpenOutcome outcome) noexcept {
    switch (outcome) {
        case TunnelOpenOutcome::Connected:
            return "200 Connection Established";
        case TunnelOpenOutcome::Denied:
            return "403 Forbidden";
        case TunnelOpenOutcome::Unreachable:
        case TunnelOpenOutcome::Refused:
        case TunnelOpenOutcome::Failed:
            break;
    }
    return "502 Bad Gateway";
}

/// Listener that accepts SOCKS5 or HTTP CONNECT requests and forwards each
/// accepted connection to the TunnelClient via the supplied OpenTunnelFn.
///
/// Protocol detection sniffs the first byte: 0x05 -> SOCKS5, anything else
/// is tried as HTTP CONNECT. Both flows converge on the same OpenTunnelFn.
///
/// Must be owned via shared_ptr (M-09): the accept loop captures a weak_ptr to
/// itself, so a callback already dispatched onto the io_context when the
/// listener is destroyed gracefully no-ops instead of dereferencing freed
/// state. `start()` therefore requires the object already be held by a
/// shared_ptr.
class Socks5Listener : public std::enable_shared_from_this<Socks5Listener> {
   public:
    Socks5Listener() = default;
    ~Socks5Listener();

    Socks5Listener(const Socks5Listener&) = delete;
    Socks5Listener& operator=(const Socks5Listener&) = delete;
    Socks5Listener(Socks5Listener&&) = delete;
    Socks5Listener& operator=(Socks5Listener&&) = delete;

    /// Start the listener. Returns an empty string on success, or an error
    /// description if the acceptor can't be opened/bound.
    [[nodiscard]] std::string start(asio::io_context& io_ctx, const std::string& host,
                                    uint16_t port, OpenTunnelFn open_tunnel);

    /// Stop accepting and tear down the acceptor. In-flight per-connection
    /// state may still drain via the io_context; callers should stop the
    /// io_context shortly after.
    void stop();

    [[nodiscard]] bool is_running() const noexcept { return running_; }
    [[nodiscard]] uint16_t bound_port() const noexcept { return bound_port_; }

   private:
    void do_accept();

    asio::io_context* io_ctx_ = nullptr;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    OpenTunnelFn open_tunnel_;
    uint16_t bound_port_ = 0;
    bool running_ = false;
};

}  // namespace toxtunnel::app
