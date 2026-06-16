#include <gtest/gtest.h>

#include <algorithm>
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
        tunnel_->set_on_send_to_tox([this](std::span<const uint8_t> wire) -> bool {
            captured_.record(wire);
            return true;
        });
        tunnel_->set_state(Tunnel::State::Connecting);
        tunnel_->set_state(Tunnel::State::Connected);
    }

    // Advance the io_context past the coalesce timer so the delayed flush runs.
    //
    // On asio's Windows IOCP backend, run_for() can return without dispatching
    // an expired steady_timer in this single-threaded test shape. Polling ready
    // handlers between small sleeps keeps the test deterministic across backends.
    void run_for(std::chrono::microseconds dur) {
        const auto deadline = std::chrono::steady_clock::now() + dur;
        while (std::chrono::steady_clock::now() < deadline) {
            io_ctx_.poll_one();
            io_ctx_.restart();
            std::this_thread::sleep_for(1ms);
        }
        while (io_ctx_.poll_one() > 0) {
            io_ctx_.restart();
        }
        io_ctx_.restart();
    }

    template <typename Predicate>
    bool wait_until(Predicate predicate,
                    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (predicate()) {
                return true;
            }
            io_ctx_.poll_one();
            io_ctx_.restart();
            std::this_thread::sleep_for(1ms);
        }
        while (io_ctx_.poll_one() > 0) {
            io_ctx_.restart();
        }
        io_ctx_.restart();
        return predicate();
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

// ---------------------------------------------------------------------------
// 8. Tox SENDQ backpressure must NOT drop bytes (close-before-drain fix).
//    A failing send retains the bytes for retry; once the queue drains, every
//    byte is delivered, in order. Regression for the ~85-90 KiB truncation
//    where coalesce_emit_front_locked erased the bytes on a full Tox queue.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, BackpressuredSendRetainsBytesUntilDrained) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> bool {
        if (!allow_send) {
            return false;  // toxcore lossless SENDQ full: nothing transmitted
        }
        captured_.record(wire);
        return true;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/1000, /*max_bytes=*/1362);

    // 3 full MTUs + a sub-MTU remainder.
    std::vector<uint8_t> payload(3 * 1362 + 100);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Backpressured: nothing transmitted, but nothing dropped either — the
    // bytes are parked in the coalesce buffer and the retry timer is armed.
    run_for(20ms);
    EXPECT_TRUE(captured_.data_payloads.empty());

    // Release backpressure; the retry timer must now drain everything, in
    // order, with zero loss.
    allow_send = true;
    ASSERT_TRUE(wait_until([&] { return captured_.concatenated_data() == payload; }))
        << "backpressured data did not drain after Tox queue became writable";

    EXPECT_EQ(captured_.concatenated_data(), payload);
}

// ---------------------------------------------------------------------------
// 8b. Regression (/ship adversarial review): on the immediate-emit path
//     (zero-delay / bypass), a write that arrives while a prior backpressured
//     remainder is still buffered must queue BEHIND it. Emitting it directly —
//     which succeeds once Tox un-backpressures — would put the newer bytes on
//     the wire ahead of the older buffered ones (drained later by the retry
//     timer), silently reordering a lossless stream.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ImmediatePathPreservesOrderAcrossBackpressure) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> bool {
        if (!allow_send) {
            return false;  // SENDQ full
        }
        captured_.record(wire);
        return true;
    });
    // Zero delay selects the immediate-emit path.
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    // First write backpressures and parks in the coalesce buffer (timer armed).
    std::vector<uint8_t> first(100, 0xAA);
    ASSERT_TRUE(tunnel_->send_data_to_tox(first));
    EXPECT_TRUE(captured_.data_payloads.empty());

    // Release backpressure, THEN issue the second write. Without the FIFO
    // guard the second write would emit directly here and reach the wire before
    // the still-buffered first.
    allow_send = true;
    std::vector<uint8_t> second(100, 0xBB);
    ASSERT_TRUE(tunnel_->send_data_to_tox(second));

    // Drain the retry timer and assert strict first-then-second ordering.
    run_for(20ms);

    std::vector<uint8_t> expected;
    expected.insert(expected.end(), first.begin(), first.end());
    expected.insert(expected.end(), second.begin(), second.end());
    EXPECT_EQ(captured_.concatenated_data(), expected);
}

// ---------------------------------------------------------------------------
// 9. close() during backpressure defers TUNNEL_CLOSE until the buffer drains,
//    so CLOSE never overtakes the still-buffered DATA (the peer would drop the
//    trailing frames as "unknown tunnel"). Regression for the 0-byte / partial
//    transfers observed under a slow link.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CloseDeferredUntilBackpressureDrains) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> bool {
        if (!allow_send) {
            return false;
        }
        captured_.record(wire);
        return true;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/1000, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(2 * 1362 + 50);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Close while the queue is backpressured: CLOSE must be withheld.
    tunnel_->close();
    run_for(20ms);
    EXPECT_TRUE(captured_.all_frame_types.empty());

    // Release: the timer drains all DATA first, then emits the deferred CLOSE.
    allow_send = true;
    ASSERT_TRUE(wait_until([&] {
        return captured_.concatenated_data() == payload && !captured_.all_frame_types.empty() &&
               captured_.all_frame_types.back() == FrameType::TUNNEL_CLOSE;
    })) << "deferred close did not wait for backpressured data to drain";

    EXPECT_EQ(captured_.concatenated_data(), payload);
    ASSERT_FALSE(captured_.all_frame_types.empty());
    EXPECT_EQ(captured_.all_frame_types.front(), FrameType::TUNNEL_DATA);
    EXPECT_EQ(captured_.all_frame_types.back(), FrameType::TUNNEL_CLOSE);
}

// ---------------------------------------------------------------------------
// 10. A peer TUNNEL_CLOSE must not discard outbound bytes we already accepted.
//     SSH is full-duplex: the client side can close while the server side still
//     has stdout buffered behind Tox SENDQ backpressure. Even in this
//     manager-only fixture with no local TcpConnection to half-close, the tunnel
//     must retry those DATA frames and only notify close after they drain.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, RemoteCloseWaitsForBackpressuredOutboundDrain) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> bool {
        if (!allow_send) {
            return false;
        }
        captured_.record(wire);
        return true;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/1000, /*max_bytes=*/1362);

    std::atomic<bool> close_notified{false};
    tunnel_->set_on_close([&]() { close_notified.store(true, std::memory_order_release); });

    std::vector<uint8_t> payload(2 * 1362 + 99);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Simulate the peer closing while our outbound side is still stuck behind
    // a full Tox SENDQ. The close callback must be deferred, not fired now.
    tunnel_->handle_frame(ProtocolFrame::make_tunnel_close(tunnel_->tunnel_id()));
    run_for(20ms);

    EXPECT_FALSE(close_notified.load(std::memory_order_acquire));
    EXPECT_TRUE(captured_.all_frame_types.empty());

    // Once Tox accepts packets again, DATA drains before the tunnel notifies
    // final close. With no local TcpConnection in this fixture, there is no
    // later TCP EOF to wait for.
    allow_send = true;
    ASSERT_TRUE(wait_until([&] {
        return captured_.concatenated_data() == payload &&
               close_notified.load(std::memory_order_acquire) &&
               tunnel_->state() == Tunnel::State::Closed;
    })) << "remote close notification fired before outbound data drained";

    EXPECT_EQ(captured_.concatenated_data(), payload);
    EXPECT_TRUE(close_notified.load(std::memory_order_acquire));
    ASSERT_FALSE(captured_.all_frame_types.empty());
    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_CLOSE),
              0);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Closed);
}

TEST_F(TunnelCoalesceTest, LocalHalfCloseStillAcceptsPeerDataUntilPeerCloses) {
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    std::vector<uint8_t> received;
    tunnel_->set_on_data_for_tcp([&](std::span<const uint8_t> data) {
        received.insert(received.end(), data.begin(), data.end());
        return true;
    });

    tunnel_->on_tcp_read_eof();
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Disconnecting);

    const std::vector<uint8_t> payload = {0x10, 0x20, 0x30};
    tunnel_->handle_frame(ProtocolFrame::make_tunnel_data(tunnel_->tunnel_id(), payload));

    EXPECT_EQ(received, payload);
    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_CLOSE),
              1);

    tunnel_->handle_frame(ProtocolFrame::make_tunnel_close(tunnel_->tunnel_id()));
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Closed);
}
