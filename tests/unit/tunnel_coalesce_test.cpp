#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <numeric>
#include <span>
#include <thread>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"

using namespace toxtunnel::tunnel;
using namespace std::chrono_literals;

namespace {

// Captures every TUNNEL_DATA payload emitted by a Tunnel's on_send_to_tox
// hook so tests can assert exact frame boundaries and ordering. Non-DATA
// frames (TUNNEL_CLOSE, ACK, etc.) are recorded separately so close-flush
// tests can distinguish "data flushed" from "close emitted".
struct CapturedFrames {
    std::vector<std::vector<uint8_t>> data_payloads;
    std::vector<FrameType> all_frame_types;

    void record(std::span<const uint8_t> wire) {
        auto frame = ProtocolFrame::deserialize(wire);
        ASSERT_TRUE(frame.has_value());
        const auto& f = frame.value();
        all_frame_types.push_back(f.type());
        if (f.type() == FrameType::TUNNEL_DATA) {
            auto payload = f.as_tunnel_data();
            data_payloads.emplace_back(payload.begin(), payload.end());
        }
    }

    std::vector<uint8_t> concatenated_data() const {
        std::vector<uint8_t> out;
        for (const auto& p : data_payloads) {
            out.insert(out.end(), p.begin(), p.end());
        }
        return out;
    }
};

class TunnelCoalesceTest : public ::testing::Test {
   protected:
    void SetUp() override {
        // shared_ptr (not unique_ptr): Tunnel inherits enable_shared_from_this
        // so its timer handlers can capture weak_from_this(). Constructing
        // via make_unique would leave weak_from_this returning an expired
        // weak_ptr and the timer callbacks would silently no-op.
        tunnel_ = std::make_shared<TunnelImpl>(io_ctx_, 1, 0);
        tunnel_->set_on_send_to_tox(
            [this](std::span<const uint8_t> wire) { captured_.record(wire); });
        tunnel_->set_state(Tunnel::State::Connecting);
        tunnel_->set_state(Tunnel::State::Connected);
    }

    // Advance the io_context past the coalesce timer so the delayed flush runs.
    void run_for(std::chrono::microseconds dur) {
        io_ctx_.restart();
        io_ctx_.run_for(dur);
    }

    asio::io_context io_ctx_;
    std::shared_ptr<TunnelImpl> tunnel_;
    CapturedFrames captured_;
};

}  // namespace

// ---------------------------------------------------------------------------
// 1. Many small writes collapse into one frame on delay flush
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CoalescesManyOneByteWritesIntoSingleFrame) {
    tunnel_->configure_coalesce(/*max_delay_us=*/500, /*max_bytes=*/1362);

    for (uint8_t i = 0; i < 32; ++i) {
        ASSERT_TRUE(tunnel_->send_data_to_tox(std::vector<uint8_t>{i}));
    }

    // Nothing should have been emitted yet — the delay timer hasn't fired.
    EXPECT_TRUE(captured_.data_payloads.empty());

    run_for(20ms);

    ASSERT_EQ(captured_.data_payloads.size(), 1u);
    ASSERT_EQ(captured_.data_payloads[0].size(), 32u);
    for (uint8_t i = 0; i < 32; ++i) {
        EXPECT_EQ(captured_.data_payloads[0][i], i);
    }
}

// ---------------------------------------------------------------------------
// 2. Exact-MTU write emits immediately, no remainder
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ExactMtuWriteEmitsImmediatelyNoRemainder) {
    constexpr std::size_t kMtu = 1362;
    tunnel_->configure_coalesce(500, kMtu);

    std::vector<uint8_t> payload(kMtu);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Should have emitted exactly one frame synchronously.
    ASSERT_EQ(captured_.data_payloads.size(), 1u);
    EXPECT_EQ(captured_.data_payloads[0].size(), kMtu);

    // Advancing time must NOT add a spurious empty/extra frame.
    run_for(20ms);
    EXPECT_EQ(captured_.data_payloads.size(), 1u);
}

// ---------------------------------------------------------------------------
// 3. Oversized writes split into full frames plus leftover
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, OversizedWriteSplitsIntoFullFramesPlusLeftover) {
    constexpr std::size_t kMtu = 100;
    tunnel_->configure_coalesce(500, kMtu);

    std::vector<uint8_t> payload(255);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Two full kMtu frames should already be on the wire; the 55-byte
    // remainder is parked waiting for the timer.
    ASSERT_EQ(captured_.data_payloads.size(), 2u);
    EXPECT_EQ(captured_.data_payloads[0].size(), kMtu);
    EXPECT_EQ(captured_.data_payloads[1].size(), kMtu);

    run_for(20ms);

    ASSERT_EQ(captured_.data_payloads.size(), 3u);
    EXPECT_EQ(captured_.data_payloads[2].size(), 55u);
    EXPECT_EQ(captured_.concatenated_data(), payload);
}

// ---------------------------------------------------------------------------
// 4. Zero delay disables coalescing entirely
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ZeroDelayEmitsEveryWriteImmediately) {
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    for (uint8_t i = 0; i < 5; ++i) {
        ASSERT_TRUE(tunnel_->send_data_to_tox(std::vector<uint8_t>{i}));
    }

    ASSERT_EQ(captured_.data_payloads.size(), 5u);
    for (uint8_t i = 0; i < 5; ++i) {
        ASSERT_EQ(captured_.data_payloads[i].size(), 1u);
        EXPECT_EQ(captured_.data_payloads[i][0], i);
    }
}

// ---------------------------------------------------------------------------
// 5. Order is preserved across many interleaved writes of varied sizes
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, OrderPreservedAcrossInterleavedWrites) {
    constexpr std::size_t kMtu = 64;
    tunnel_->configure_coalesce(500, kMtu);

    std::vector<uint8_t> expected;
    expected.reserve(1024);

    // Mix tiny writes with mid-sized writes and one oversized write that
    // forces an inline split. The full output stream must equal `expected`
    // regardless of how the coalescer chunks it.
    auto append = [&](std::initializer_list<uint8_t> bytes) {
        std::vector<uint8_t> v(bytes);
        expected.insert(expected.end(), v.begin(), v.end());
        ASSERT_TRUE(tunnel_->send_data_to_tox(v));
    };

    for (uint8_t i = 0; i < 200; ++i) {
        if (i % 7 == 0) {
            std::vector<uint8_t> chunk(20, i);
            expected.insert(expected.end(), chunk.begin(), chunk.end());
            ASSERT_TRUE(tunnel_->send_data_to_tox(chunk));
        } else if (i % 13 == 0) {
            std::vector<uint8_t> chunk(100, i);
            expected.insert(expected.end(), chunk.begin(), chunk.end());
            ASSERT_TRUE(tunnel_->send_data_to_tox(chunk));
        } else {
            append({i});
        }
    }

    run_for(20ms);

    EXPECT_EQ(captured_.concatenated_data(), expected);
    // Every frame except possibly the last must be exactly MTU-sized.
    for (std::size_t i = 0; i + 1 < captured_.data_payloads.size(); ++i) {
        EXPECT_EQ(captured_.data_payloads[i].size(), kMtu) << "frame " << i;
    }
}

// ---------------------------------------------------------------------------
// 6. close() flushes whatever is parked in the coalesce buffer
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CloseFlushesPendingAccumulator) {
    tunnel_->configure_coalesce(/*max_delay_us=*/60'000'000, /*max_bytes=*/1362);

    std::vector<uint8_t> chunk = {1, 2, 3, 4, 5, 6, 7, 8};
    ASSERT_TRUE(tunnel_->send_data_to_tox(chunk));

    // Nothing emitted yet — the timer is set for a minute.
    EXPECT_TRUE(captured_.data_payloads.empty());

    tunnel_->close();

    // close() must drain pending bytes, then emit TUNNEL_CLOSE — in that
    // order, so the receiver sees every byte before the EOF signal.
    ASSERT_EQ(captured_.data_payloads.size(), 1u);
    EXPECT_EQ(captured_.data_payloads[0], chunk);

    ASSERT_GE(captured_.all_frame_types.size(), 2u);
    EXPECT_EQ(captured_.all_frame_types.front(), FrameType::TUNNEL_DATA);
    EXPECT_EQ(captured_.all_frame_types.back(), FrameType::TUNNEL_CLOSE);
}

// ---------------------------------------------------------------------------
// 7. flush_pending_writes() works mid-stream and is idempotent
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ExplicitFlushIsIdempotent) {
    tunnel_->configure_coalesce(500, 1362);

    ASSERT_TRUE(tunnel_->send_data_to_tox(std::vector<uint8_t>{42, 43, 44}));
    tunnel_->flush_pending_writes();
    ASSERT_EQ(captured_.data_payloads.size(), 1u);

    tunnel_->flush_pending_writes();  // No-op: buffer already drained.
    EXPECT_EQ(captured_.data_payloads.size(), 1u);
}
