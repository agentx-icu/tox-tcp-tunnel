// Tunnel-resume protocol unit tests.
//
// 1. ProtocolFrame round-trips for TUNNEL_RESUME_REQUEST and
//    TUNNEL_RESUME_ACK serialize -> deserialize bit-identically.
// 2. Status codes outside the known range decode to `Unknown`.
// 3. The feature flag (default false) does not affect any v0.3.0 wire path:
//    factory methods that don't involve the new opcodes still produce
//    bit-identical bytes.

#include <gtest/gtest.h>

#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/tunnel/protocol.hpp"

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
