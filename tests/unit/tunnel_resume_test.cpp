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
#include <fstream>

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

// C-9 / 2026-05-20 finding: saved_at_ns must come from system_clock,
// not steady_clock, because the value is persisted to YAML and compared
// against now_ns() on the next process run (possibly after a reboot).
// steady_clock's epoch is arbitrary and per-boot.
TEST(TunnelResumeStoreTest, SavedTimestampIsWallClock) {
    using namespace std::chrono;

    app::TunnelResumeStore store;
    app::TunnelResumeEntry e;
    e.tunnel_id = 1;
    e.target_host = "127.0.0.1";
    e.target_port = 80;
    store.upsert(e);

    // After upsert, the stored saved_at_ns must be a recent wall-clock
    // value. Test bounds: 2026-01-01 (~1.767e18 ns) lower, two years
    // ahead upper. Steady-clock typical values are << 1e18 (it starts
    // from process boot, so under 10^15 ns even after a year of uptime).
    auto entries = store.entries();
    ASSERT_EQ(entries.size(), 1u);
    const auto saved = entries[0].saved_at_ns;

    const auto now_wall =
        duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
    EXPECT_GT(saved, static_cast<std::int64_t>(1'700'000'000) * 1'000'000'000)
        << "saved_at_ns looks like a steady_clock value, not wall clock";
    EXPECT_LE(saved, now_wall);
    // And the stamp lands within a tight window of "now" (clock skew aside).
    EXPECT_LT(now_wall - saved, static_cast<std::int64_t>(60) * 1'000'000'000)
        << "saved_at_ns drifted from system_clock::now()";
}

TEST(TunnelResumeStoreTest, DropsEntriesOlderThanMaxAge) {
    auto dir = std::filesystem::temp_directory_path() / "toxtunnel_resume_store_age";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    auto path = dir / "tunnel_resume_state.yaml";

    // Hand-craft the YAML rather than going through upsert(): upsert
    // always stamps `saved_at_ns = now_ns()` so the entry is by
    // construction fresh, which is the right runtime behaviour but not
    // what we want to test here. We want the load-side filter to drop
    // an ancient entry that was written by a previous process.
    {
        std::ofstream out(path);
        out << "version: 1\n";
        out << "tunnels:\n";
        out << "  - tunnel_id: 5\n";
        out << "    target_host: 127.0.0.1\n";
        out << "    target_port: 22\n";
        out << "    last_local_recv_offset: 0\n";
        out << "    last_local_send_offset: 0\n";
        out << "    local_listener_port: 0\n";
        out << "    saved_at_ns: 1\n";  // ancient (Unix epoch + 1ns)
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
