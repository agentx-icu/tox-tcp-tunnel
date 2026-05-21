// Outbound zero-copy (Wave B) tests.
//
// These tests pin the contract introduced by the outbound zero-copy work:
//
//   1. OwnedFrameBuffer carries one allocation big enough for the reserved
//      header prefix plus the payload region; mutations advance `payload_used`
//      and never reallocate.
//
//   2. `ProtocolFrame::serialize_tunnel_data_in_place` writes the 0xA0
//      lossless prefix byte plus the 5-byte tunnel frame header into the
//      reserved prefix of the supplied buffer; the resulting wire bytes are
//      *bit-identical* to what `ProtocolFrame::serialize()` produces minus
//      the lossless prefix byte.
//
//   3. `TunnelImpl::send_data_to_tox` routes a TUNNEL_DATA frame through the
//      zero-copy callback when it is set, and falls back to the span callback
//      when it is not. The owned buffer arrives at the callback intact and
//      its wire bytes round-trip through `ProtocolFrame::deserialize` to the
//      original payload.
//
//   4. The outbound metrics (`outbound_buffer_allocs_total`) tick once per
//      emitted TUNNEL_DATA frame.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/tunnel/owned_frame_buffer.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::test {
namespace {

using tunnel::kFrameHeaderReserved;
using tunnel::OwnedFrameBuffer;
using tunnel::ProtocolFrame;

std::vector<std::uint8_t> make_pattern(std::size_t size, std::uint8_t seed = 0) {
    std::vector<std::uint8_t> v(size);
    for (std::size_t i = 0; i < size; ++i) {
        v[i] = static_cast<std::uint8_t>((i + seed) & 0xFF);
    }
    return v;
}

// =============================================================================
// 1. OwnedFrameBuffer basic semantics.
// =============================================================================

TEST(OwnedFrameBufferTest, AllocateProducesEmptyPayloadWithReservedPrefix) {
    auto buf = OwnedFrameBuffer::allocate(/*payload_capacity=*/1024);
    ASSERT_FALSE(buf.empty());
    EXPECT_EQ(buf.payload_capacity(), 1024u);
    EXPECT_EQ(buf.payload_used(), 0u);
    EXPECT_EQ(buf.payload_remaining(), 1024u);
    ASSERT_NE(buf.header_data(), nullptr);
    // Header pointer + reserved offset == payload start.
    EXPECT_EQ(buf.header_data() + kFrameHeaderReserved, buf.payload_data());
}

TEST(OwnedFrameBufferTest, AppendPayloadAdvancesUsedAndClampsAtCapacity) {
    auto buf = OwnedFrameBuffer::allocate(8);
    auto first = make_pattern(4, 0x10);
    EXPECT_EQ(buf.append_payload(std::span<const std::uint8_t>(first)), 4u);
    EXPECT_EQ(buf.payload_used(), 4u);

    auto second = make_pattern(8, 0x20);  // overflow attempt
    EXPECT_EQ(buf.append_payload(std::span<const std::uint8_t>(second)), 4u);
    EXPECT_EQ(buf.payload_used(), 8u);
    EXPECT_EQ(buf.payload_remaining(), 0u);

    // Further appends are no-ops.
    EXPECT_EQ(buf.append_payload(std::span<const std::uint8_t>(second)), 0u);
}

TEST(OwnedFrameBufferTest, WithPayloadCopiesIntoPayloadRegion) {
    auto src = make_pattern(123, 0x77);
    auto buf = OwnedFrameBuffer::with_payload(std::span<const std::uint8_t>(src));
    EXPECT_EQ(buf.payload_used(), src.size());
    EXPECT_EQ(buf.payload_capacity(), src.size());
    auto seen = buf.payload();
    ASSERT_EQ(seen.size(), src.size());
    EXPECT_TRUE(std::equal(seen.begin(), seen.end(), src.begin()));
}

TEST(OwnedFrameBufferTest, SharedStorageSurvivesCopy) {
    auto src = make_pattern(64, 0xAA);
    auto buf = OwnedFrameBuffer::with_payload(std::span<const std::uint8_t>(src));
    const auto* original_storage = buf.storage().get();
    OwnedFrameBuffer copy = buf;
    EXPECT_EQ(buf.storage().get(), original_storage);
    EXPECT_EQ(copy.storage().get(), original_storage);
    // Use-count == 2 because the wrapper holds one ref and the copy a second.
    EXPECT_EQ(buf.storage().use_count(), 2);
}

// =============================================================================
// 2. serialize_tunnel_data_in_place produces the same wire bytes as serialize().
// =============================================================================

TEST(OutboundZeroCopyProtocol, InPlaceSerializeMatchesLegacySerialize) {
    const std::uint16_t tunnel_id = 42;
    const auto payload = make_pattern(512, 0x33);

    // Legacy path: build, serialize.
    auto legacy =
        ProtocolFrame::make_tunnel_data(tunnel_id, std::span<const std::uint8_t>(payload));
    const auto legacy_wire = legacy.serialize();
    ASSERT_EQ(legacy_wire.size(), tunnel::kFrameHeaderSize + payload.size());

    // Zero-copy path: with_payload + serialize_in_place.
    auto buf = OwnedFrameBuffer::with_payload(std::span<const std::uint8_t>(payload));
    ProtocolFrame::serialize_tunnel_data_in_place(buf, tunnel_id);
    const auto zc_wire = buf.wire_view();

    // Wave B wire view starts with the 0xA0 lossless prefix byte; the legacy
    // serialize() omits it (the on_send_to_tox callback prepends it). Strip
    // the first byte of zc_wire and the rest must match legacy_wire.
    ASSERT_GE(zc_wire.size(), legacy_wire.size() + 1);
    EXPECT_EQ(zc_wire[0], 0xA0);
    EXPECT_TRUE(std::equal(zc_wire.begin() + 1, zc_wire.end(), legacy_wire.begin()));
}

TEST(OutboundZeroCopyProtocol, RoundTripThroughDeserialize) {
    const std::uint16_t tunnel_id = 99;
    const auto payload = make_pattern(1300, 0x55);

    auto buf = OwnedFrameBuffer::with_payload(std::span<const std::uint8_t>(payload));
    ProtocolFrame::serialize_tunnel_data_in_place(buf, tunnel_id);
    const auto zc_wire = buf.wire_view();

    // Skip the 0xA0 prefix byte and feed the rest to ProtocolFrame::deserialize.
    auto parsed = ProtocolFrame::deserialize(
        std::span<const std::uint8_t>(zc_wire.data() + 1, zc_wire.size() - 1));
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed.value().type(), tunnel::FrameType::TUNNEL_DATA);
    EXPECT_EQ(parsed.value().tunnel_id(), tunnel_id);
    auto seen = parsed.value().as_tunnel_data();
    ASSERT_EQ(seen.size(), payload.size());
    EXPECT_TRUE(std::equal(seen.begin(), seen.end(), payload.begin()));
}

// =============================================================================
// 3. TunnelImpl routes through the owned callback when it is set; falls back
//    to the span callback otherwise.
// =============================================================================

class OutboundZeroCopyTunnelTest : public ::testing::Test {
   protected:
    void SetUp() override {
        io_ = std::make_unique<core::IoContext>(1);
        io_->run();
        util::MetricsRegistry::instance().reset();
    }
    void TearDown() override { io_->stop(); }
    asio::io_context& io_ctx() { return io_->get_io_context(); }
    std::unique_ptr<core::IoContext> io_;
};

TEST_F(OutboundZeroCopyTunnelTest, SendDataPrefersOwnedCallback) {
    tunnel::TunnelImpl tunnel(io_ctx(), /*tunnel_id=*/7, /*friend_number=*/0);
    tunnel.configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);  // bypass timer
    tunnel.set_state(tunnel::Tunnel::State::Connected);

    std::vector<OwnedFrameBuffer> owned_calls;
    std::atomic<int> span_calls{0};
    tunnel.set_on_send_to_tox_owned([&owned_calls](OwnedFrameBuffer buf) -> bool {
        owned_calls.push_back(std::move(buf));
        return true;
    });
    tunnel.set_on_send_to_tox([&span_calls](std::span<const std::uint8_t>) -> bool {
        span_calls.fetch_add(1, std::memory_order_relaxed);
        return true;
    });

    const auto payload = make_pattern(800, 0x42);
    ASSERT_TRUE(tunnel.send_data_to_tox(std::span<const std::uint8_t>(payload)));

    ASSERT_EQ(owned_calls.size(), 1u);
    EXPECT_EQ(span_calls.load(), 0);

    // Wire payload after the 6-byte prefix must equal the original bytes.
    const auto& buf = owned_calls.front();
    auto seen = buf.payload();
    ASSERT_EQ(seen.size(), payload.size());
    EXPECT_TRUE(std::equal(seen.begin(), seen.end(), payload.begin()));

    // Header byte at offset 0 is the 0xA0 lossless prefix; offset 1 is the
    // TUNNEL_DATA frame type.
    auto wire = buf.wire_view();
    ASSERT_GE(wire.size(), 6u);
    EXPECT_EQ(wire[0], 0xA0);
    EXPECT_EQ(wire[1], static_cast<std::uint8_t>(tunnel::FrameType::TUNNEL_DATA));

    // Metric ticked once for the single emitted frame.
    EXPECT_EQ(util::MetricsRegistry::instance().outbound_buffer_allocs(), 1u);
}

TEST_F(OutboundZeroCopyTunnelTest, FallsBackToSpanCallbackWhenOwnedAbsent) {
    tunnel::TunnelImpl tunnel(io_ctx(), /*tunnel_id=*/13, /*friend_number=*/1);
    tunnel.configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);
    tunnel.set_state(tunnel::Tunnel::State::Connected);

    std::vector<std::vector<std::uint8_t>> span_calls;
    tunnel.set_on_send_to_tox([&span_calls](std::span<const std::uint8_t> data) -> bool {
        span_calls.emplace_back(data.begin(), data.end());
        return true;
    });

    const auto payload = make_pattern(64, 0xAB);
    ASSERT_TRUE(tunnel.send_data_to_tox(std::span<const std::uint8_t>(payload)));

    ASSERT_EQ(span_calls.size(), 1u);
    // No outbound owned-buffer allocations.
    EXPECT_EQ(util::MetricsRegistry::instance().outbound_buffer_allocs(), 0u);
}

// =============================================================================
// 4. Large writes (> MTU) fragment into multiple owned frames, each with its
//    own allocation accounted in the metric.
// =============================================================================

TEST_F(OutboundZeroCopyTunnelTest, LargeWriteFragmentsIntoMultipleOwnedFrames) {
    tunnel::TunnelImpl tunnel(io_ctx(), /*tunnel_id=*/77, /*friend_number=*/2);
    tunnel.configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);
    tunnel.set_state(tunnel::Tunnel::State::Connected);

    std::vector<OwnedFrameBuffer> owned_calls;
    tunnel.set_on_send_to_tox_owned([&owned_calls](OwnedFrameBuffer buf) -> bool {
        owned_calls.push_back(std::move(buf));
        return true;
    });

    // 4000 bytes > 1367-byte Tox MTU → ceil(4000/1367) = 3 frames.
    const auto payload = make_pattern(4000, 0x05);
    ASSERT_TRUE(tunnel.send_data_to_tox(std::span<const std::uint8_t>(payload)));

    EXPECT_GE(owned_calls.size(), 3u);
    EXPECT_EQ(util::MetricsRegistry::instance().outbound_buffer_allocs(), owned_calls.size());

    // Re-assemble the payload bytes from the fragments and confirm they
    // match exactly what we sent.
    std::vector<std::uint8_t> reassembled;
    reassembled.reserve(payload.size());
    for (const auto& buf : owned_calls) {
        auto p = buf.payload();
        reassembled.insert(reassembled.end(), p.begin(), p.end());
    }
    ASSERT_EQ(reassembled.size(), payload.size());
    EXPECT_TRUE(std::equal(reassembled.begin(), reassembled.end(), payload.begin()));
}

// =============================================================================
// 5. Buffer survives async hand-off via shared_ptr refcount: clone the
//    OwnedFrameBuffer in the callback, drop the original, confirm the clone
//    still resolves the original wire bytes.
// =============================================================================

TEST_F(OutboundZeroCopyTunnelTest, OwnedFrameBufferSurvivesHandoff) {
    tunnel::TunnelImpl tunnel(io_ctx(), /*tunnel_id=*/8, /*friend_number=*/3);
    tunnel.configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);
    tunnel.set_state(tunnel::Tunnel::State::Connected);

    std::shared_ptr<OwnedFrameBuffer> escaped;
    tunnel.set_on_send_to_tox_owned([&escaped](OwnedFrameBuffer buf) -> bool {
        escaped = std::make_shared<OwnedFrameBuffer>(std::move(buf));
        return true;
    });

    {
        const auto payload = make_pattern(256, 0x9A);
        ASSERT_TRUE(tunnel.send_data_to_tox(std::span<const std::uint8_t>(payload)));
        // `payload` goes out of scope here. The escaped buffer must still
        // be valid because its allocation is shared-owned.
    }

    ASSERT_TRUE(escaped);
    EXPECT_EQ(escaped->payload_used(), 256u);
    auto wire = escaped->wire_view();
    ASSERT_GE(wire.size(), 6u);
    EXPECT_EQ(wire[0], 0xA0);
}

}  // namespace
}  // namespace toxtunnel::test
