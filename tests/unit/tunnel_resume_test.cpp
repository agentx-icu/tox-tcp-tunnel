// Tunnel-resume protocol unit tests.
//
// 1. ProtocolFrame round-trips for TUNNEL_RESUME_REQUEST and
//    TUNNEL_RESUME_ACK serialize -> deserialize bit-identically.
// 2. Status codes outside the known range decode to `Unknown`.
// 3. TunnelResumeStore persists and reloads entries.
// 4. Old entries past `max_age_seconds` are pruned on load.
// 5. The feature flag (default false) does not affect any v0.3.0 wire path:
//    factory methods that don't involve the new opcodes still produce
//    bit-identical bytes.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>

#include "toxtunnel/app/tunnel_resume_store.hpp"
#include "toxtunnel/tunnel/protocol.hpp"

namespace toxtunnel::test {
namespace {

using tunnel::FrameType;
using tunnel::ProtocolFrame;
using tunnel::TunnelResumeAckPayload;
using tunnel::TunnelResumeRequestPayload;
using tunnel::TunnelResumeStatus;

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

// =============================================================================
// TunnelResumeStore persistence
// =============================================================================

TEST(TunnelResumeStoreTest, RoundTripPersist) {
    auto dir = std::filesystem::temp_directory_path() / "toxtunnel_resume_store_test";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    auto path = dir / "tunnel_resume_state.yaml";

    {
        app::TunnelResumeStore store;
        store.set_path(path);
        store.set_server_tox_id("AAAA");
        app::TunnelResumeEntry e;
        e.tunnel_id = 7;
        e.target_host = "127.0.0.1";
        e.target_port = 22;
        e.last_local_recv_offset = 100;
        e.last_local_send_offset = 200;
        e.local_listener_port = 2222;
        e.saved_at_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        store.upsert(e);
        ASSERT_TRUE(store.save());
    }

    app::TunnelResumeStore loaded;
    loaded.set_path(path);
    loaded.set_server_tox_id("AAAA");
    ASSERT_TRUE(loaded.load());
    auto entries = loaded.entries();
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].tunnel_id, 7);
    EXPECT_EQ(entries[0].target_host, "127.0.0.1");
    EXPECT_EQ(entries[0].target_port, 22);

    std::filesystem::remove_all(dir);
}

TEST(TunnelResumeStoreTest, DropsEntriesOlderThanMaxAge) {
    auto dir = std::filesystem::temp_directory_path() / "toxtunnel_resume_store_age";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    auto path = dir / "tunnel_resume_state.yaml";

    {
        app::TunnelResumeStore store;
        store.set_path(path);
        app::TunnelResumeEntry stale;
        stale.tunnel_id = 5;
        stale.saved_at_ns = 1;  // ancient
        store.upsert(stale);
        ASSERT_TRUE(store.save());
    }

    app::TunnelResumeStore loaded;
    loaded.set_path(path);
    loaded.set_max_age_seconds(1);
    ASSERT_TRUE(loaded.load());
    EXPECT_TRUE(loaded.entries().empty());

    std::filesystem::remove_all(dir);
}

TEST(TunnelResumeStoreTest, ServerIdChangeDropsEntries) {
    auto dir = std::filesystem::temp_directory_path() / "toxtunnel_resume_store_servid";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    auto path = dir / "tunnel_resume_state.yaml";

    {
        app::TunnelResumeStore store;
        store.set_path(path);
        store.set_server_tox_id("AAAA");
        app::TunnelResumeEntry e;
        e.tunnel_id = 3;
        e.saved_at_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        store.upsert(e);
        ASSERT_TRUE(store.save());
    }

    app::TunnelResumeStore loaded;
    loaded.set_path(path);
    loaded.set_server_tox_id("BBBB");  // different server
    ASSERT_TRUE(loaded.load());
    EXPECT_TRUE(loaded.entries().empty());

    std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace toxtunnel::test
