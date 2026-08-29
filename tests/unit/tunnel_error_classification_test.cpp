// TUNNEL_ERROR classification: the wire contract between the two ends.
//
// THE BUG THIS FILE EXISTS FOR. A rate-limited TUNNEL_OPEN used to reach a
// SOCKS5 client as 0x04 "host unreachable" — indistinguishable from a dead
// target. The server sent code 3 for the rate limit, and code 3 was a grab-bag
// covering policy denials, connect failures and teardowns alike, so no
// client-side logic could separate them. The client papered over it by
// grepping the description for "refused", which is itself unportable: C++ only
// requires error_code::message() to describe the error, and on Windows asio
// gets that text from FormatMessage, whose language follows the machine locale.
//
// From v0.4.12 the three codes are disjoint categories:
//   1 = policy-denied open, 2 = general non-policy failure, 3 = actually refused.
//
// Because a released v0.4.11 server is still allowed to talk to a v0.4.12
// client, correctness here is a MATRIX, not a single mapping — every case below
// is labelled with which side is old and which is new.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

#include "toxtunnel/app/socks5_listener.hpp"
#include "toxtunnel/app/tunnel_server.hpp"

namespace toxtunnel::app {
namespace {

/// The full client-side chain in one call: what a peer put on the wire ->
/// classification -> the byte a SOCKS5 caller actually receives. Asserting on
/// the reply byte rather than the enum is the point; the enum is an internal
/// detail, the byte is the contract with curl and the browser.
[[nodiscard]] std::uint8_t socks5_reply_for_wire_error(std::uint8_t code,
                                                       std::string_view description) {
    return socks5_reply_for(tunnel_open_outcome_for(code, description));
}

[[nodiscard]] std::string http_status_for_wire_error(std::uint8_t code,
                                                     std::string_view description) {
    return http_status_for(tunnel_open_outcome_for(code, description));
}

// ---------------------------------------------------------------------------
// NEW client x NEW server (v0.4.12+ on both ends)
// ---------------------------------------------------------------------------

TEST(TunnelErrorClassificationTest, PolicyDenialIsDeniedRegardlessOfWhichPolicyRefused) {
    // All three policy rejections share code 1, so the client needs no
    // knowledge of which one fired — that is the whole point of the category.
    for (const auto* reason : {"Access denied", "Rate limit exceeded", "Tunnel limit exceeded"}) {
        EXPECT_EQ(tunnel_open_outcome_for(1, reason), TunnelOpenOutcome::Denied) << reason;
        EXPECT_EQ(socks5_reply_for_wire_error(1, reason), socks5::kReplyConnNotAllowed) << reason;
        EXPECT_EQ(http_status_for_wire_error(1, reason), "403 Forbidden") << reason;
    }
}

TEST(TunnelErrorClassificationTest, RateLimitedOpenNoLongerLooksLikeADeadTarget) {
    // THE ORIGINAL BUG, stated as an assertion. Before v0.4.12 this produced
    // kReplyHostUnreachable and an operator chasing a target that was fine.
    EXPECT_EQ(socks5_reply_for_wire_error(1, "Rate limit exceeded"), socks5::kReplyConnNotAllowed);
    EXPECT_NE(socks5_reply_for_wire_error(1, "Rate limit exceeded"), socks5::kReplyHostUnreachable);
}

TEST(TunnelErrorClassificationTest, GeneralFailuresAreUnreachableWhateverTheirText) {
    // Code 2 is the whole non-policy bucket, so the description must not
    // matter — including for text that contains the word this classifier used
    // to key on. A code 2 is never a refusal, even if it says "refused".
    for (const auto* description :
         {"DNS resolution failed: Host not found", "TCP connect failed: Operation timed out",
          "Tunnel ID in use", "Tunnel not found",
          "target connection lost before tunnel was established", "half-close linger timeout",
          "connection refused"}) {
        EXPECT_EQ(tunnel_open_outcome_for(2, description), TunnelOpenOutcome::Unreachable)
            << description;
        EXPECT_EQ(socks5_reply_for_wire_error(2, description), socks5::kReplyHostUnreachable)
            << description;
    }
}

TEST(TunnelErrorClassificationTest, RefusedConnectIsRefused) {
    EXPECT_EQ(tunnel_open_outcome_for(3, "TCP connection refused: Connection refused"),
              TunnelOpenOutcome::Refused);
    EXPECT_EQ(socks5_reply_for_wire_error(3, "TCP connection refused: Connection refused"),
              socks5::kReplyConnRefused);
}

TEST(TunnelErrorClassificationTest, UnknownAndAbsentCodesAreGenericFailures) {
    // 0 means "the tunnel failed without a TUNNEL_ERROR". Reporting a specific
    // reason there would be inventing one.
    EXPECT_EQ(tunnel_open_outcome_for(0, ""), TunnelOpenOutcome::Failed);
    EXPECT_EQ(socks5_reply_for_wire_error(0, ""), socks5::kReplyGeneralFailure);
    // A code from a FUTURE server this build has never heard of must degrade to
    // a generic failure, not be forced into the nearest known category.
    for (std::uint8_t code : {std::uint8_t{4}, std::uint8_t{9}, std::uint8_t{255}}) {
        EXPECT_EQ(tunnel_open_outcome_for(code, "something new"), TunnelOpenOutcome::Failed)
            << static_cast<int>(code);
    }
}

// ---------------------------------------------------------------------------
// NEW client x OLD server (<= v0.4.11, where code 3 was the grab-bag)
// ---------------------------------------------------------------------------

TEST(TunnelErrorLegacyCompatTest, OldServersPolicyDenialsAreStillRecognisedAsDenials) {
    // The compat shim: exact matches on the two literals v0.4.11 shipped. This
    // is what stops an old server's rate limit still reading as a dead target.
    EXPECT_EQ(tunnel_open_outcome_for(3, "Rate limit exceeded"), TunnelOpenOutcome::Denied);
    EXPECT_EQ(tunnel_open_outcome_for(3, "Tunnel limit exceeded"), TunnelOpenOutcome::Denied);
    EXPECT_EQ(socks5_reply_for_wire_error(3, "Rate limit exceeded"), socks5::kReplyConnNotAllowed);
    EXPECT_EQ(socks5_reply_for_wire_error(3, "Tunnel limit exceeded"),
              socks5::kReplyConnNotAllowed);
}

TEST(TunnelErrorLegacyCompatTest, ShimMatchesExactlyAndDoesNotSwallowNeighbouringText) {
    // Exact, not substring: a *new* server never sends these under code 3, and
    // a loose match would let unrelated text be reported as a policy denial.
    EXPECT_NE(tunnel_open_outcome_for(3, "Rate limit exceeded for friend ABC"),
              TunnelOpenOutcome::Denied);
    EXPECT_NE(tunnel_open_outcome_for(3, "rate limit exceeded"), TunnelOpenOutcome::Denied);
    EXPECT_NE(tunnel_open_outcome_for(3, " Rate limit exceeded"), TunnelOpenOutcome::Denied);
}

TEST(TunnelErrorLegacyCompatTest, OldServersGenuineRefusalStillReadsAsRefused) {
    // v0.4.11 sent code 3 with the bare platform message.
    EXPECT_EQ(tunnel_open_outcome_for(3, "TCP connect failed: Connection refused"),
              TunnelOpenOutcome::Refused);
    EXPECT_EQ(socks5_reply_for_wire_error(3, "TCP connect failed: Connection refused"),
              socks5::kReplyConnRefused);
}

TEST(TunnelErrorLegacyCompatTest, OldServersNonRefusalCodeThreeStaysUnreachable) {
    // Why code 3 cannot simply be redefined as "refused" on the client: an old
    // server sends 3 for a connect TIMEOUT too, and calling that a refusal
    // would trade one wrong answer for another.
    for (const auto* description :
         {"TCP connect failed: Operation timed out", "TCP connect failed: No route to host",
          "tunnel was torn down immediately after it was opened", "half-close linger timeout"}) {
        EXPECT_EQ(tunnel_open_outcome_for(3, description), TunnelOpenOutcome::Unreachable)
            << description;
        EXPECT_EQ(socks5_reply_for_wire_error(3, description), socks5::kReplyHostUnreachable)
            << description;
    }
}

// ---------------------------------------------------------------------------
// OLD client x NEW server — verified by construction, since an old client's
// logic is fixed and known. These assert the property the coordinator asked to
// preserve: mixed versions must be BETTER than today, never worse.
// ---------------------------------------------------------------------------

/// The v0.4.11 client's classifier, reproduced verbatim so the new server's
/// output can be checked against a peer that will never be updated.
[[nodiscard]] TunnelOpenOutcome v0_4_11_client_classify(std::uint8_t code,
                                                        std::string_view description) {
    switch (code) {
        case 1:
            return TunnelOpenOutcome::Denied;
        case 2:
            return TunnelOpenOutcome::Unreachable;
        case 3:
            return description.find("refused") != std::string_view::npos
                       ? TunnelOpenOutcome::Refused
                       : TunnelOpenOutcome::Unreachable;
        default:
            return TunnelOpenOutcome::Failed;
    }
}

TEST(TunnelErrorOldClientTest, NewServersPolicyDenialsImproveOnOldClientsToo) {
    // The headline win is not confined to updated clients: because the server
    // now sends code 1, even an un-upgraded v0.4.11 client answers 0x02.
    EXPECT_EQ(v0_4_11_client_classify(1, "Rate limit exceeded"), TunnelOpenOutcome::Denied);
    EXPECT_EQ(v0_4_11_client_classify(1, "Tunnel limit exceeded"), TunnelOpenOutcome::Denied);
    EXPECT_EQ(socks5_reply_for(v0_4_11_client_classify(1, "Rate limit exceeded")),
              socks5::kReplyConnNotAllowed);
}

TEST(TunnelErrorOldClientTest, NewServersRefusalLiteralStillMatchesTheOldSubstringCheck) {
    // Requirement 2, stated as a test: the fixed lowercase "refused" in the new
    // server's literal is what keeps already-deployed clients correct. Dropping
    // it in favour of the bare platform message would break exactly those peers
    // on non-English hosts.
    const auto reason = detail::open_failure_for_connect_error(
        asio::error::make_error_code(asio::error::connection_refused));
    EXPECT_EQ(v0_4_11_client_classify(reason.code, reason.description), TunnelOpenOutcome::Refused);
}

TEST(TunnelErrorOldClientTest, ConnectTimeoutMovingFromThreeToTwoStillReadsAsUnreachable) {
    // A non-refusal connect failure changes code (3 -> 2) but must not change
    // what an old client reports.
    const auto reason = detail::open_failure_for_connect_error(
        asio::error::make_error_code(asio::error::timed_out));
    EXPECT_EQ(reason.code, 2);
    EXPECT_EQ(v0_4_11_client_classify(reason.code, reason.description),
              TunnelOpenOutcome::Unreachable);
    EXPECT_EQ(tunnel_open_outcome_for(reason.code, reason.description),
              TunnelOpenOutcome::Unreachable);
}

// ---------------------------------------------------------------------------
// Server-side classification of a real connect failure
// ---------------------------------------------------------------------------

TEST(ConnectFailureClassificationTest, RefusalIsDetectedNumericallyNotByMessageText) {
    const auto reason = detail::open_failure_for_connect_error(
        asio::error::make_error_code(asio::error::connection_refused));
    EXPECT_EQ(reason.code, 3);
    // The stable literal, independent of the platform message that follows it.
    EXPECT_EQ(reason.description.rfind("TCP connection refused: ", 0), 0u) << reason.description;
}

TEST(ConnectFailureClassificationTest, NonRefusalsAreTheGeneralCategory) {
    for (auto err : {asio::error::timed_out, asio::error::host_unreachable,
                     asio::error::network_unreachable, asio::error::connection_aborted}) {
        const auto ec = asio::error::make_error_code(err);
        const auto reason = detail::open_failure_for_connect_error(ec);
        EXPECT_EQ(reason.code, 2) << ec.message();
        EXPECT_EQ(reason.description.rfind("TCP connect failed: ", 0), 0u) << reason.description;
    }
}

// A REAL refused connect, not a synthesised error_code. This is the test that
// would catch a platform where asio's connect error does not compare equal to
// asio::error::connection_refused — which is precisely the class of assumption
// the old string match got wrong on Windows.
TEST(ConnectFailureClassificationTest, ARealRefusedLoopbackConnectClassifiesAsRefused) {
    asio::io_context io_ctx;

    // Bind a port, learn its number, then close it, so the port is known-dead
    // and a connect to it is refused rather than timing out or being filtered.
    asio::ip::tcp::endpoint endpoint;
    {
        asio::ip::tcp::acceptor probe(
            io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
        endpoint = probe.local_endpoint();
        probe.close();
    }

    asio::ip::tcp::socket sock(io_ctx);
    std::error_code connect_ec;
    sock.connect(endpoint, connect_ec);

    ASSERT_TRUE(connect_ec) << "connect to a closed loopback port must fail";
    ASSERT_EQ(connect_ec, asio::error::connection_refused)
        << "expected a refusal on this platform, got: " << connect_ec.message();

    const auto reason = detail::open_failure_for_connect_error(connect_ec);
    EXPECT_EQ(reason.code, 3);
    EXPECT_EQ(reason.description.rfind("TCP connection refused: ", 0), 0u) << reason.description;

    // End to end: a real refusal must reach a SOCKS5 caller as 0x05, on both a
    // current and a v0.4.11 client.
    EXPECT_EQ(socks5_reply_for_wire_error(reason.code, reason.description),
              socks5::kReplyConnRefused);
    EXPECT_EQ(socks5_reply_for(v0_4_11_client_classify(reason.code, reason.description)),
              socks5::kReplyConnRefused);
}

}  // namespace
}  // namespace toxtunnel::app
