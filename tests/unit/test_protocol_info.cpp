#include <gtest/gtest.h>

#include <span>
#include <string>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/system_info.hpp"

using namespace toxtunnel;
using namespace toxtunnel::tunnel;
using namespace toxtunnel::util;

// ---------------------------------------------------------------------------
// INFO_REQUEST framing
// ---------------------------------------------------------------------------

TEST(ProtocolInfoFrame, MakeInfoRequestEmptyPayloadTunnelZero) {
    auto frame = ProtocolFrame::make_info_request();
    EXPECT_EQ(frame.type(), FrameType::INFO_REQUEST);
    EXPECT_EQ(frame.tunnel_id(), 0);
    EXPECT_TRUE(frame.payload().empty());

    auto wire = frame.serialize();
    ASSERT_EQ(wire.size(), kFrameHeaderSize);
    EXPECT_EQ(wire[0], 0x06);
    EXPECT_EQ(wire[1], 0);
    EXPECT_EQ(wire[2], 0);
    EXPECT_EQ(wire[3], 0);
    EXPECT_EQ(wire[4], 0);
}

TEST(ProtocolInfoFrame, RoundTripInfoRequest) {
    auto frame = ProtocolFrame::make_info_request();
    auto wire = frame.serialize();
    auto parsed = ProtocolFrame::deserialize(std::span<const uint8_t>(wire));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value().type(), FrameType::INFO_REQUEST);
    EXPECT_EQ(parsed.value().tunnel_id(), 0);
}

// ---------------------------------------------------------------------------
// INFO_REPLY framing
// ---------------------------------------------------------------------------

TEST(ProtocolInfoFrame, MakeInfoReplyCarriesYamlPayload) {
    const std::string yaml = "hostname: nas-01\nos: Linux\n";
    auto frame = ProtocolFrame::make_info_reply(yaml);
    EXPECT_EQ(frame.type(), FrameType::INFO_REPLY);
    EXPECT_EQ(frame.tunnel_id(), 0);
    ASSERT_EQ(frame.payload().size(), yaml.size());
    EXPECT_EQ(frame.as_info_reply_yaml(), yaml);
}

TEST(ProtocolInfoFrame, MakeInfoReplyEmptyPayloadIsValid) {
    auto frame = ProtocolFrame::make_info_reply("");
    EXPECT_EQ(frame.type(), FrameType::INFO_REPLY);
    EXPECT_TRUE(frame.payload().empty());
    EXPECT_EQ(frame.as_info_reply_yaml(), "");
}

TEST(ProtocolInfoFrame, RoundTripInfoReply) {
    const std::string yaml =
        "hostname: nas-01\nos: Linux\nos_version: \"6.6.0\"\narch: aarch64\nuptime_seconds: "
        "84221\n";
    auto frame = ProtocolFrame::make_info_reply(yaml);
    auto wire = frame.serialize();
    auto parsed = ProtocolFrame::deserialize(std::span<const uint8_t>(wire));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value().type(), FrameType::INFO_REPLY);
    EXPECT_EQ(parsed.value().as_info_reply_yaml(), yaml);
}

TEST(ProtocolInfoFrame, AsInfoReplyYamlReturnsEmptyForOtherFrames) {
    auto ping = ProtocolFrame::make_ping();
    EXPECT_EQ(ping.as_info_reply_yaml(), "");
}

// ---------------------------------------------------------------------------
// SystemInfo gathering (gated by ServerInfoDisclose policy)
// ---------------------------------------------------------------------------

TEST(SystemInfoGather, EmptyPolicyReturnsAllNullopt) {
    ServerInfoDisclose policy;
    auto snap = gather_system_info(policy);
    EXPECT_FALSE(snap.hostname.has_value());
    EXPECT_FALSE(snap.os.has_value());
    EXPECT_FALSE(snap.os_version.has_value());
    EXPECT_FALSE(snap.arch.has_value());
    EXPECT_FALSE(snap.uptime_seconds.has_value());
    EXPECT_FALSE(snap.toxtunnel_version.has_value());
}

TEST(SystemInfoGather, HostnamePolicyOnlyFillsHostname) {
    ServerInfoDisclose policy;
    policy.hostname = true;
    auto snap = gather_system_info(policy);
    // hostname should be present on every supported platform.
    EXPECT_TRUE(snap.hostname.has_value());
    EXPECT_FALSE(snap.os.has_value());
    EXPECT_FALSE(snap.arch.has_value());
}

TEST(SystemInfoGather, ToxTunnelVersionPolicyFillsVersion) {
    ServerInfoDisclose policy;
    policy.toxtunnel_version = true;
    auto snap = gather_system_info(policy);
    ASSERT_TRUE(snap.toxtunnel_version.has_value());
    EXPECT_FALSE(snap.toxtunnel_version->empty());
}

TEST(SystemInfoGather, AllPolicyFillsAllProbedFields) {
    ServerInfoDisclose policy;
    policy.hostname = true;
    policy.os = true;
    policy.os_version = true;
    policy.arch = true;
    policy.toxtunnel_version = true;
    // Note: uptime is platform-specific and may legitimately fail; keep it off
    // here so the assertion below is reliable on all CI runners.
    auto snap = gather_system_info(policy);
    EXPECT_TRUE(snap.hostname.has_value());
    EXPECT_TRUE(snap.os.has_value());
    EXPECT_TRUE(snap.os_version.has_value());
    EXPECT_TRUE(snap.arch.has_value());
    EXPECT_TRUE(snap.toxtunnel_version.has_value());
}

// ---------------------------------------------------------------------------
// SystemInfo YAML round-trip (the wire format inside INFO_REPLY)
// ---------------------------------------------------------------------------

TEST(SystemInfoYaml, RoundTripPreservesAllFields) {
    SystemInfoSnapshot original;
    original.hostname = "nas-01";
    original.os = "Linux";
    original.os_version = "6.6.0-arm64";
    original.arch = "aarch64";
    original.uptime_seconds = 84221;
    original.toxtunnel_version = "0.1.11";

    const auto yaml = snapshot_to_yaml(original);
    EXPECT_NE(yaml.find("hostname: nas-01"), std::string::npos);
    EXPECT_NE(yaml.find("uptime_seconds: 84221"), std::string::npos);

    const auto parsed = snapshot_from_yaml(yaml);
    EXPECT_EQ(parsed.hostname, original.hostname);
    EXPECT_EQ(parsed.os, original.os);
    EXPECT_EQ(parsed.os_version, original.os_version);
    EXPECT_EQ(parsed.arch, original.arch);
    EXPECT_EQ(parsed.uptime_seconds, original.uptime_seconds);
    EXPECT_EQ(parsed.toxtunnel_version, original.toxtunnel_version);
}

TEST(SystemInfoYaml, EmptySnapshotYieldsEmptyMapAndParsesBack) {
    SystemInfoSnapshot empty;
    const auto yaml = snapshot_to_yaml(empty);
    const auto parsed = snapshot_from_yaml(yaml);
    EXPECT_FALSE(parsed.hostname.has_value());
    EXPECT_FALSE(parsed.os.has_value());
}

TEST(SystemInfoYaml, MalformedYamlReturnsEmptySnapshot) {
    const auto parsed = snapshot_from_yaml("this: is: not: valid:\n  - yaml\n: oops");
    EXPECT_FALSE(parsed.hostname.has_value());
    EXPECT_FALSE(parsed.os.has_value());
    EXPECT_FALSE(parsed.arch.has_value());
}
