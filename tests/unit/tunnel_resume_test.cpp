// Tunnel-resume protocol unit tests.
//
// 1. ProtocolFrame round-trips for TUNNEL_RESUME_REQUEST and
//    TUNNEL_RESUME_ACK serialize -> deserialize bit-identically.
// 2. Status codes outside the known range decode to `Unknown`.
// 3. The feature flag (default false) does not affect any v0.3.0 wire path:
//    factory methods that don't involve the new opcodes still produce
//    bit-identical bytes.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "toxtunnel/app/tunnel_client.hpp"
#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace toxtunnel::test {
namespace {

using tunnel::FrameType;
using tunnel::ProtocolFrame;
using tunnel::TunnelResumeAckPayload;
using tunnel::TunnelResumeRequestPayload;
using tunnel::TunnelResumeStatus;

// H-07 offset reconciliation (pure decision used by the server's
// handle_resume_request). Argument order: local_send, peer_recv, local_recv,
// peer_send.
TEST(ResumeOffsetTest, NoGapWhenOffsetsMatch) {
    // Everything the server sent the client received, and vice versa.
    EXPECT_FALSE(app::resume_offsets_have_gap(/*local_send=*/1000, /*peer_recv=*/1000,
                                              /*local_recv=*/2000, /*peer_send=*/2000));
}

TEST(ResumeOffsetTest, GapWhenPeerMissedOurBytes) {
    // We sent 1000 but the peer only received 900 — 100-byte hole.
    EXPECT_TRUE(app::resume_offsets_have_gap(/*local_send=*/1000, /*peer_recv=*/900,
                                             /*local_recv=*/2000, /*peer_send=*/2000));
}

TEST(ResumeOffsetTest, GapWhenWeMissedPeerBytes) {
    // The peer sent 2000 but we only received 1500.
    EXPECT_TRUE(app::resume_offsets_have_gap(/*local_send=*/1000, /*peer_recv=*/1000,
                                             /*local_recv=*/1500, /*peer_send=*/2000));
}

TEST(ResumeOffsetTest, NoGapAtZeroOffsets) {
    EXPECT_FALSE(app::resume_offsets_have_gap(0, 0, 0, 0));
}

// ---------------------------------------------------------------------------
// Unpaired friend-`connected` events (resume-destroying race).
//
// toxcore can report a friend `connected` without ever having reported the
// preceding `disconnected`. setup_tunnel_manager() used to assign a fresh
// manager into managers_ unconditionally, destroying the live manager's tunnels
// and their target TCP connections; the peer's follow-up RESUME_REQUEST was then
// answered "no held tunnel; declined". classify_connected_event() is the guard.
// ---------------------------------------------------------------------------

using app::detail::classify_connected_event;
using app::detail::ConnectedManagerAction;

TEST(ConnectedEventTest, LiveManagerIsNeverReplaced) {
    // The regression itself: `connected` arrives with a live manager already
    // installed and nothing held. Must keep the live one, not build a fresh one.
    EXPECT_EQ(classify_connected_event(/*live=*/true, /*held=*/false, /*resume_enabled=*/true),
              ConnectedManagerAction::KeepExisting);
    // Same answer with resume off: the live manager's tunnels are just as real.
    EXPECT_EQ(classify_connected_event(/*live=*/true, /*held=*/false, /*resume_enabled=*/false),
              ConnectedManagerAction::KeepExisting);
}

TEST(ConnectedEventTest, LiveManagerWinsOverAHeldOne) {
    // Should not be reachable (teardown erases from managers_ before it holds),
    // but if both maps somehow carry this friend, the live manager is the one the
    // peer is actually talking to.
    EXPECT_EQ(classify_connected_event(/*live=*/true, /*held=*/true, /*resume_enabled=*/true),
              ConnectedManagerAction::KeepExisting);
}

TEST(ConnectedEventTest, HeldManagerIsResurrectedWhenResumeEnabled) {
    EXPECT_EQ(classify_connected_event(/*live=*/false, /*held=*/true, /*resume_enabled=*/true),
              ConnectedManagerAction::Resurrect);
}

TEST(ConnectedEventTest, HeldManagerIsIgnoredWhenResumeDisabled) {
    // resume.enabled is non-reloadable, so a hold cannot outlive the flag in
    // practice; assert the disabled path still never resurrects.
    EXPECT_EQ(classify_connected_event(/*live=*/false, /*held=*/true, /*resume_enabled=*/false),
              ConnectedManagerAction::CreateFresh);
}

TEST(ConnectedEventTest, FreshManagerForAnUnknownFriend) {
    EXPECT_EQ(classify_connected_event(/*live=*/false, /*held=*/false, /*resume_enabled=*/true),
              ConnectedManagerAction::CreateFresh);
    EXPECT_EQ(classify_connected_event(/*live=*/false, /*held=*/false, /*resume_enabled=*/false),
              ConnectedManagerAction::CreateFresh);
}

TEST(TunnelResumeProtocolTest, RoundTripRequest) {
    TunnelResumeRequestPayload p;
    p.prior_tunnel_id = 17;
    p.last_local_recv_offset = 1234567890;
    p.last_local_send_offset = 987654321;
    p.host = "internal.example.com";
    p.target_port = 22;

    auto built = ProtocolFrame::make_tunnel_resume_request(p);
    EXPECT_EQ(built.type(), FrameType::TUNNEL_RESUME_REQUEST);
    EXPECT_EQ(built.tunnel_id(), 17);

    auto wire = built.serialize();
    auto parsed = ProtocolFrame::deserialize(wire);
    ASSERT_TRUE(parsed) << parsed.error().message();

    auto extracted = parsed.value().as_tunnel_resume_request();
    ASSERT_TRUE(extracted);
    EXPECT_EQ(extracted->prior_tunnel_id, p.prior_tunnel_id);
    EXPECT_EQ(extracted->last_local_recv_offset, p.last_local_recv_offset);
    EXPECT_EQ(extracted->last_local_send_offset, p.last_local_send_offset);
    EXPECT_EQ(extracted->host, p.host);
    EXPECT_EQ(extracted->target_port, p.target_port);
}

TEST(TunnelResumeProtocolTest, RoundTripAck) {
    TunnelResumeAckPayload p;
    p.new_tunnel_id = 99;
    p.server_recv_offset = 555;
    p.server_send_offset = 444;
    p.status = TunnelResumeStatus::Ok;

    auto built = ProtocolFrame::make_tunnel_resume_ack(p);
    auto wire = built.serialize();
    auto parsed = ProtocolFrame::deserialize(wire);
    ASSERT_TRUE(parsed);

    auto extracted = parsed.value().as_tunnel_resume_ack();
    ASSERT_TRUE(extracted);
    EXPECT_EQ(extracted->new_tunnel_id, 99);
    EXPECT_EQ(extracted->server_recv_offset, 555u);
    EXPECT_EQ(extracted->server_send_offset, 444u);
    EXPECT_EQ(extracted->status, TunnelResumeStatus::Ok);
}

TEST(TunnelResumeProtocolTest, AckRejectsKnownFailureCodes) {
    for (auto s : {TunnelResumeStatus::TargetUnreachable, TunnelResumeStatus::RulesDenied,
                   TunnelResumeStatus::TooOld}) {
        TunnelResumeAckPayload p;
        p.new_tunnel_id = 1;
        p.status = s;
        auto wire = ProtocolFrame::make_tunnel_resume_ack(p).serialize();
        auto parsed = ProtocolFrame::deserialize(wire);
        ASSERT_TRUE(parsed);
        EXPECT_EQ(parsed.value().as_tunnel_resume_ack()->status, s);
    }
}

TEST(TunnelResumeProtocolTest, OldOpcodesUnchanged) {
    // Sanity check: TUNNEL_OPEN serialise/deserialise produces the same
    // bytes regardless of whether the new opcodes are part of the
    // protocol. A v0.3.0 peer expects exactly these bytes.
    auto built = ProtocolFrame::make_tunnel_open(42, "host.example.com", 8080);
    auto wire = built.serialize();
    // 5-byte header + 1 host_len + 16 chars host + 2 port = 24
    EXPECT_EQ(wire.size(), 24u);
    EXPECT_EQ(wire[0], static_cast<std::uint8_t>(FrameType::TUNNEL_OPEN));
}

}  // namespace
}  // namespace toxtunnel::test

// ===========================================================================
// Issue #31: resume-abort / stale-ACK / deadline regressions against the real
// TunnelClient resume machinery, driven through a friend test-access seam so no
// live toxcore link is needed. The RESUME_REQUEST send is captured via the
// installed sender seam; the resume handlers are invoked directly (their asio
// deadline-timer arming is a no-op without an io_context, which the default-
// constructed client has none of, so only the handler LOGIC runs).
// ===========================================================================

namespace toxtunnel::app {

class TunnelResumeTestAccess {
   public:
    static std::shared_ptr<tunnel::TunnelManager>& tunnel_mgr(TunnelClient& c) {
        return c.tunnel_mgr_;
    }
    static Config& config(TunnelClient& c) { return c.config_; }
    static std::vector<ClientServerEndpoint>& endpoints(TunnelClient& c) { return c.endpoints_; }
    static std::size_t& active_index(TunnelClient& c) { return c.active_index_; }
    static std::uint64_t& generation(TunnelClient& c) { return c.resume_session_generation_; }
    static std::function<void(std::uint32_t, const std::vector<std::uint8_t>&)>& resume_sender(
        TunnelClient& c) {
        return c.resume_request_sender_;
    }
    static void send_resume_requests(TunnelClient& c) { c.send_resume_requests(); }
    static void handle_resume_ack(TunnelClient& c, const tunnel::TunnelResumeAckPayload& ack,
                                  std::uint64_t captured_generation) {
        c.handle_resume_ack(ack, captured_generation);
    }
    static void on_resume_deadline(TunnelClient& c) { c.on_resume_deadline(); }
    static void put_token(TunnelClient& c, std::uint16_t id, std::uint64_t gen,
                          std::weak_ptr<tunnel::TunnelImpl> tunnel,
                          std::chrono::steady_clock::time_point deadline) {
        std::lock_guard<std::mutex> lock(c.resume_tokens_mutex_);
        c.resume_tokens_[id] = TunnelClient::ResumeToken{gen, std::move(tunnel), deadline};
    }
    static bool has_token(TunnelClient& c, std::uint16_t id) {
        std::lock_guard<std::mutex> lock(c.resume_tokens_mutex_);
        return c.resume_tokens_.count(id) != 0;
    }
    static std::size_t token_count(TunnelClient& c) {
        std::lock_guard<std::mutex> lock(c.resume_tokens_mutex_);
        return c.resume_tokens_.size();
    }
};

class TunnelServerResumeTestAccess {
   public:
    static Config& config(TunnelServer& s) { return s.config_; }
    static std::unordered_map<std::uint32_t, std::shared_ptr<tunnel::TunnelManager>>& managers(
        TunnelServer& s) {
        return s.managers_;
    }
    static std::function<void(std::uint32_t, const std::vector<std::uint8_t>&)>& resume_ack_sender(
        TunnelServer& s) {
        return s.resume_ack_sender_;
    }
    static void handle_resume_request(TunnelServer& s, std::uint32_t friend_number,
                                      const tunnel::ProtocolFrame& frame) {
        s.handle_resume_request(friend_number, frame);
    }
};

}  // namespace toxtunnel::app

namespace toxtunnel::test {
namespace {

using tunnel::Tunnel;
using tunnel::TunnelImpl;
using tunnel::TunnelManager;
using Access = toxtunnel::app::TunnelResumeTestAccess;

// A Connected TunnelImpl wired into a manager, with a no-op accepting send so
// close()/force_close() resolve synchronously.
std::shared_ptr<TunnelImpl> make_connected_tunnel(asio::io_context& io_ctx,
                                                  const std::shared_ptr<TunnelManager>& mgr,
                                                  std::uint16_t id) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, id, /*friend_number=*/0);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) { return tunnel::SendOutcome::Sent; });
    tunnel->set_state(Tunnel::State::Connecting);
    tunnel->set_state(Tunnel::State::Connected);
    mgr->add_tunnel(id, tunnel);
    return tunnel;
}

// Build a default client with resume enabled, one active endpoint (friend 0), a
// manager, and a capturing resume sender.
struct ResumeClientFixture {
    asio::io_context io_ctx;
    app::TunnelClient client;
    std::shared_ptr<TunnelManager> mgr;
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> sent;

    ResumeClientFixture() {
        Access::config(client).tunnel.resume.enabled = true;
        mgr = std::make_shared<TunnelManager>(io_ctx);
        Access::tunnel_mgr(client) = mgr;
        app::ClientServerEndpoint ep;
        ep.friend_number = 0;
        ep.tox_id_hex = std::string(76, 'A');
        ep.online = true;
        Access::endpoints(client).push_back(ep);
        Access::active_index(client) = 0;
        Access::resume_sender(client) = [this](std::uint32_t fn,
                                               const std::vector<std::uint8_t>& packet) {
            sent.emplace_back(fn, packet);
        };
    }
};

// #31 client-aborted: send_resume_requests must SKIP an outbound-aborted (but
// still Connected) tunnel and force-settle it, never sending a RESUME_REQUEST
// or recording a token for it.
TEST(ResumeAbortTest, ClientSkipsAndSettlesAbortedTunnel) {
    ResumeClientFixture f;
    auto tunnel = make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/5);
    // Seal the outbound side WITHOUT leaving Connected (close_outbound_gate
    // publishes the Abort seal; it does not transition state), giving the
    // Connected+sealed transient state the skip guards against.
    tunnel->close_outbound_gate();
    ASSERT_TRUE(tunnel->outbound_aborted());
    ASSERT_EQ(tunnel->state(), Tunnel::State::Connected);

    Access::send_resume_requests(f.client);

    EXPECT_TRUE(f.sent.empty()) << "a RESUME_REQUEST was sent for an aborted tunnel";
    EXPECT_FALSE(Access::has_token(f.client, 5)) << "a token was recorded for an aborted tunnel";
    EXPECT_NE(tunnel->state(), Tunnel::State::Connected) << "the aborted tunnel was not settled";
}

// #31 client happy path: a live tunnel gets a request + token.
TEST(ResumeAbortTest, ClientSendsRequestAndRecordsTokenForLiveTunnel) {
    ResumeClientFixture f;
    make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/6);

    Access::send_resume_requests(f.client);

    ASSERT_EQ(f.sent.size(), 1u) << "no RESUME_REQUEST sent for a live tunnel";
    EXPECT_EQ(f.sent[0].first, 0u);
    EXPECT_TRUE(Access::has_token(f.client, 6));
}

// #31 stale-generation: a RESUME_ACK captured at an older generation (a switch
// or reconnect bumped it) is dropped and does not act on the tunnel.
TEST(ResumeAbortTest, StaleGenerationAckIsDropped) {
    ResumeClientFixture f;
    auto tunnel = make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/7);
    Access::send_resume_requests(f.client);  // records token at generation 0
    ASSERT_TRUE(Access::has_token(f.client, 7));

    // A switch/reconnect bumps the generation after the ACK was captured.
    Access::generation(f.client) = 1;

    tunnel::TunnelResumeAckPayload ack;
    ack.new_tunnel_id = 7;
    ack.status = tunnel::TunnelResumeStatus::Ok;
    Access::handle_resume_ack(f.client, ack, /*captured_generation=*/0);

    EXPECT_EQ(tunnel->state(), Tunnel::State::Connected)
        << "a stale-generation ACK acted on the tunnel";
    EXPECT_TRUE(Access::has_token(f.client, 7))
        << "the generation gate must drop before consuming the token";
}

// #31 object-identity: a RESUME_ACK whose token resolves to a DIFFERENT tunnel
// object than the one it names (a same-generation id reuse) is dropped.
TEST(ResumeAbortTest, ObjectMismatchAckIsDropped) {
    ResumeClientFixture f;
    auto live = make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/8);
    // A separate impl the token points at, NOT the one in the manager at id 8.
    auto other = std::make_shared<TunnelImpl>(f.io_ctx, 8, 0);
    Access::put_token(f.client, 8, /*gen=*/0, other,
                      std::chrono::steady_clock::now() + std::chrono::seconds(30));

    tunnel::TunnelResumeAckPayload ack;
    ack.new_tunnel_id = 8;
    ack.status = tunnel::TunnelResumeStatus::Ok;
    Access::handle_resume_ack(f.client, ack, /*captured_generation=*/0);

    EXPECT_EQ(live->state(), Tunnel::State::Connected)
        << "an object-mismatched ACK acted on the recycled-id tunnel";
    EXPECT_FALSE(Access::has_token(f.client, 8)) << "the token must be consumed on mismatch";
}

// #31 seal-during-resume: an Abort that raced the request/ACK exchange leaves
// the tunnel Connected-but-sealed; the Ok-path recheck force-settles it instead
// of reporting a successful resume.
TEST(ResumeAbortTest, SealDuringResumeForcesSettleOnOkAck) {
    ResumeClientFixture f;
    auto tunnel = make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/11);
    Access::send_resume_requests(f.client);
    ASSERT_TRUE(Access::has_token(f.client, 11));

    // The tunnel is aborted while the ACK is in flight.
    tunnel->close_outbound_gate();
    ASSERT_TRUE(tunnel->outbound_aborted());
    ASSERT_EQ(tunnel->state(), Tunnel::State::Connected);

    tunnel::TunnelResumeAckPayload ack;
    ack.new_tunnel_id = 11;
    ack.status = tunnel::TunnelResumeStatus::Ok;
    Access::handle_resume_ack(f.client, ack, /*captured_generation=*/0);

    EXPECT_NE(tunnel->state(), Tunnel::State::Connected)
        << "an Ok ACK for a tunnel aborted mid-exchange was not force-settled";
    EXPECT_FALSE(Access::has_token(f.client, 11));
}

// #31 response deadline: a token whose deadline has passed force-settles its
// tunnel and is removed.
TEST(ResumeAbortTest, DeadlineForceSettlesUnansweredResume) {
    ResumeClientFixture f;
    auto tunnel = make_connected_tunnel(f.io_ctx, f.mgr, /*id=*/9);
    Access::put_token(f.client, 9, /*gen=*/0, tunnel,
                      std::chrono::steady_clock::now() - std::chrono::seconds(1));

    Access::on_resume_deadline(f.client);

    EXPECT_NE(tunnel->state(), Tunnel::State::Connected)
        << "an unanswered resume past its deadline was not force-settled";
    EXPECT_FALSE(Access::has_token(f.client, 9)) << "the expired token was not removed";
}

// #31 server-aborted: handle_resume_request must DECLINE (TooOld) and remove a
// held tunnel whose outbound side is Abort-sealed, rather than reattaching a
// tunnel that can never send back.
TEST(ResumeAbortTest, ServerDeclinesAndRemovesAbortedHeldTunnel) {
    using ServerAccess = toxtunnel::app::TunnelServerResumeTestAccess;
    asio::io_context io_ctx;
    app::TunnelServer server;
    ServerAccess::config(server).tunnel.resume.enabled = true;

    constexpr std::uint32_t kFriend = 3;
    constexpr std::uint16_t kTunnelId = 4;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    auto tunnel = make_connected_tunnel(io_ctx, mgr, kTunnelId);
    // Aborted-but-Connected held tunnel (see the client abort test).
    tunnel->close_outbound_gate();
    ASSERT_TRUE(tunnel->outbound_aborted());
    ServerAccess::managers(server)[kFriend] = mgr;

    std::vector<tunnel::TunnelResumeAckPayload> acks;
    ServerAccess::resume_ack_sender(server) = [&acks](std::uint32_t,
                                                      const std::vector<std::uint8_t>& packet) {
        // Strip the lossless prefix byte and decode the ACK. No ASSERT_ in this
        // non-test lambda; the test body validates what was captured.
        if (packet.size() < 2) {
            return;
        }
        auto frame = ProtocolFrame::deserialize(
            std::span<const std::uint8_t>(packet.data() + 1, packet.size() - 1));
        if (!frame) {
            return;
        }
        if (auto ack = frame.value().as_tunnel_resume_ack()) {
            acks.push_back(*ack);
        }
    };

    tunnel::TunnelResumeRequestPayload req;
    req.prior_tunnel_id = kTunnelId;
    req.host = "h";
    req.target_port = 80;
    auto frame = ProtocolFrame::make_tunnel_resume_request(req);

    ServerAccess::handle_resume_request(server, kFriend, frame);

    ASSERT_EQ(acks.size(), 1u) << "the server did not reply to the resume request";
    EXPECT_EQ(acks[0].status, tunnel::TunnelResumeStatus::TooOld)
        << "an aborted held tunnel must be declined, not reattached";
    EXPECT_EQ(mgr->get_tunnel(kTunnelId), nullptr)
        << "the aborted held tunnel must be removed from the manager";
}

}  // namespace
}  // namespace toxtunnel::test
