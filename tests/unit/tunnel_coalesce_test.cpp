#include <gtest/gtest.h>

#include <algorithm>
#include <asio.hpp>
#include <chrono>
#include <functional>
#include <numeric>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"

using namespace toxtunnel::tunnel;
using namespace std::chrono_literals;

// Shared io_context pump helpers. Defined once in test_tunnel_manager.cpp,
// which links into the same unit_tests binary; declared here rather than in a
// new header because tests/CMakeLists.txt lists its sources explicitly and
// adding files to it is out of scope for this change.
namespace toxtunnel::test_support {

bool PumpUntil(asio::io_context& io_ctx, const std::function<bool()>& pred,
               std::chrono::milliseconds deadline);
void PumpFor(asio::io_context& io_ctx, std::chrono::milliseconds duration);

}  // namespace toxtunnel::test_support

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
        tunnel_->set_on_send_to_tox([this](std::span<const uint8_t> wire) -> SendOutcome {
            captured_.record(wire);
            return SendOutcome::Sent;
        });
        tunnel_->set_state(Tunnel::State::Connecting);
        tunnel_->set_state(Tunnel::State::Connected);
    }

    // Pump the io_context until `predicate` holds, or the deadline passes.
    //
    // The loop itself lives once, in test_tunnel_manager.cpp (same unit_tests
    // binary) — this file used to carry a second copy of it. See that file for
    // why the loop must never sleep and must use poll() rather than run_for().
    template <typename Predicate>
    bool pump_until(Predicate predicate,
                    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        return toxtunnel::test_support::PumpUntil(
            io_ctx_, std::function<bool()>(std::move(predicate)), timeout);
    }

    // Pump for a fixed wall-clock budget without waiting on a condition. Used
    // only by the negative assertions ("advancing time must NOT emit an extra
    // frame"), where there is nothing to wait *for*.
    void pump_for(std::chrono::milliseconds budget) {
        toxtunnel::test_support::PumpFor(io_ctx_, budget);
    }

    template <typename Predicate>
    bool wait_until(Predicate predicate,
                    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        return pump_until(std::move(predicate), timeout);
    }

    asio::io_context io_ctx_;
    std::shared_ptr<TunnelImpl> tunnel_;
    CapturedFrames captured_;
};

}  // namespace

namespace {

/// A coalesce delay that is actually honoured on every platform.
///
/// Windows cannot deliver a sub-tick timer, so the production code treats a
/// sub-floor delay as "do not hold" (see kMinHonouredCoalesceDelayUs). Tests
/// that assert *batching* must therefore ask for a delay the platform can keep,
/// or they would be asserting behaviour the operator explicitly does not get
/// there. Tests that assert the immediate path keep using 0.
constexpr std::uint32_t kBatchingDelayUs =
    toxtunnel::tunnel::kMinHonouredCoalesceDelayUs > 500
        ? toxtunnel::tunnel::kMinHonouredCoalesceDelayUs + 400
        : 500;

}  // namespace

// ---------------------------------------------------------------------------
// 1. Many small writes collapse into one frame on delay flush
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CoalescesManyOneByteWritesIntoSingleFrame) {
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    for (uint8_t i = 0; i < 32; ++i) {
        ASSERT_TRUE(tunnel_->send_data_to_tox(std::vector<uint8_t>{i}));
    }

    // Nothing should have been emitted yet — the delay timer hasn't fired.
    EXPECT_TRUE(captured_.data_payloads.empty());

    ASSERT_TRUE(pump_until([&] { return !captured_.data_payloads.empty(); }))
        << "coalesce timer never flushed the buffered writes";

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
    tunnel_->configure_coalesce(kBatchingDelayUs, kMtu);

    std::vector<uint8_t> payload(kMtu);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Should have emitted exactly one frame synchronously.
    ASSERT_EQ(captured_.data_payloads.size(), 1u);
    EXPECT_EQ(captured_.data_payloads[0].size(), kMtu);

    // Advancing time must NOT add a spurious empty/extra frame.
    pump_for(20ms);
    EXPECT_EQ(captured_.data_payloads.size(), 1u);
}

// ---------------------------------------------------------------------------
// 3. Oversized writes split into full frames plus leftover
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, OversizedWriteSplitsIntoFullFramesPlusLeftover) {
    constexpr std::size_t kMtu = 100;
    tunnel_->configure_coalesce(kBatchingDelayUs, kMtu);

    std::vector<uint8_t> payload(255);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Two full kMtu frames should already be on the wire; the 55-byte
    // remainder is parked waiting for the timer.
    ASSERT_EQ(captured_.data_payloads.size(), 2u);
    EXPECT_EQ(captured_.data_payloads[0].size(), kMtu);
    EXPECT_EQ(captured_.data_payloads[1].size(), kMtu);

    ASSERT_TRUE(pump_until([&] { return captured_.data_payloads.size() >= 3u; }))
        << "coalesce timer never flushed the sub-MTU remainder";

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
    tunnel_->configure_coalesce(kBatchingDelayUs, kMtu);

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

    ASSERT_TRUE(pump_until([&] { return captured_.concatenated_data() == expected; }))
        << "coalescer did not deliver every byte in order";

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
    tunnel_->configure_coalesce(kBatchingDelayUs, 1362);

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
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;  // toxcore lossless SENDQ full: nothing transmitted
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    // 3 full MTUs + a sub-MTU remainder.
    std::vector<uint8_t> payload(3 * 1362 + 100);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Backpressured: nothing transmitted, but nothing dropped either — the
    // bytes are parked in the coalesce buffer and the retry timer is armed.
    pump_for(20ms);
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
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;  // SENDQ full
        }
        captured_.record(wire);
        return SendOutcome::Sent;
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
    // Wait on the *bytes*, not the frame count: both writes are sub-MTU and the
    // drain legitimately merges them into a single frame.
    std::vector<uint8_t> expected;
    expected.insert(expected.end(), first.begin(), first.end());
    expected.insert(expected.end(), second.begin(), second.end());

    ASSERT_TRUE(pump_until([&] { return captured_.concatenated_data() == expected; }))
        << "FIFO drain never emitted both parked writes in order; got "
        << captured_.concatenated_data().size() << " of " << expected.size() << " bytes";

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
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(2 * 1362 + 50);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Close while the queue is backpressured: CLOSE must be withheld.
    tunnel_->close();
    pump_for(20ms);
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
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::atomic<bool> close_notified{false};
    tunnel_->set_on_close([&]() { close_notified.store(true, std::memory_order_release); });

    std::vector<uint8_t> payload(2 * 1362 + 99);
    std::iota(payload.begin(), payload.end(), uint8_t{0});
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Simulate the peer closing while our outbound side is still stuck behind
    // a full Tox SENDQ. The close callback must be deferred, not fired now.
    tunnel_->handle_frame(ProtocolFrame::make_tunnel_close(tunnel_->tunnel_id()));
    pump_for(20ms);

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

// ===========================================================================
// Outbound emission driver (slice 2, issue #24)
// ===========================================================================

// ---------------------------------------------------------------------------
// 11. Cohort caps are never merged. Bytes buffered under the batch cap and a
//     bypass write parked behind them each keep the cap they were admitted
//     under, across backpressure and retry. A merged cap would either break
//     the buffered framing contract (frame larger than coalesce_max_bytes)
//     or slice the bypass write below the wire ceiling for no reason.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CohortsKeepTheirAdmissionCapAcrossBackpressure) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    // Batch cap of 100 so the caps are visibly different from the 1367-byte
    // bypass ceiling.
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/100);

    // 250 bytes admitted under the batch cap, all retained by backpressure.
    std::vector<uint8_t> batched(250, 0xAA);
    ASSERT_TRUE(tunnel_->send_data_to_tox(batched));
    EXPECT_TRUE(captured_.data_payloads.empty());

    // 150 bytes admitted as a bypass write. Must queue BEHIND the batched
    // cohort (FIFO) but keep its own one-frame-per-write framing.
    tunnel_->set_coalesce_mode(CoalesceMode::Bypass);
    std::vector<uint8_t> bypass(150, 0xBB);
    ASSERT_TRUE(tunnel_->send_data_to_tox(bypass));
    EXPECT_TRUE(captured_.data_payloads.empty());

    allow_send = true;
    std::vector<uint8_t> expected;
    expected.insert(expected.end(), batched.begin(), batched.end());
    expected.insert(expected.end(), bypass.begin(), bypass.end());
    ASSERT_TRUE(wait_until([&] { return captured_.concatenated_data() == expected; }))
        << "backpressured cohorts did not drain in order";

    // Frame boundaries: the batched cohort drains under ITS cap (100, 100,
    // 50), the bypass cohort under the wire ceiling (one 150-byte frame).
    // Never a frame mixing bytes admitted under different caps.
    ASSERT_EQ(captured_.data_payloads.size(), 4u);
    EXPECT_EQ(captured_.data_payloads[0].size(), 100u);
    EXPECT_EQ(captured_.data_payloads[1].size(), 100u);
    EXPECT_EQ(captured_.data_payloads[2].size(), 50u);
    EXPECT_EQ(captured_.data_payloads[3].size(), 150u);
}

// ---------------------------------------------------------------------------
// 12. A send_data_to_tox() re-entered from INSIDE the send callback (the
//     synchronous ACK round-trip shape) queues behind the in-flight write's
//     remainder. The rejected-draft failure mode was A1, C, A2: the reentrant
//     write jumping the not-yet-emitted second half of the write that
//     triggered it. Under the old in-lock emission this call would have
//     deadlocked on coalesce_mutex_ instead.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ReentrantSendQueuesBehindTheInFlightWritesRemainder) {
    std::vector<uint8_t> first(2000, 0xAA);  // emits as 1367 + 633
    std::vector<uint8_t> reentrant(100, 0xBB);

    bool injected = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        captured_.record(wire);
        if (!injected) {
            injected = true;
            // Same thread, from inside the first frame's callback.
            EXPECT_TRUE(tunnel_->send_data_to_tox(reentrant));
        }
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    ASSERT_TRUE(tunnel_->send_data_to_tox(first));

    // Byte order is the assertion that catches the A1, C, A2 reorder: a
    // jumped queue concatenates to A1 + C + A2, which != A + C. Frame count is
    // deliberately NOT pinned to one-frame-per-write: both writes were
    // admitted under the same bypass cap, and "one frame per bypass write" is
    // a property of the unobstructed path only — under a backlog the FIFO
    // legitimately merges same-cap cohorts (633 + 100 emit as one frame).
    std::vector<uint8_t> expected;
    expected.insert(expected.end(), first.begin(), first.end());
    expected.insert(expected.end(), reentrant.begin(), reentrant.end());
    ASSERT_TRUE(wait_until([&] { return captured_.concatenated_data() == expected; }))
        << "reentrant write was lost or reordered";

    ASSERT_EQ(captured_.data_payloads.size(), 2u);
    EXPECT_EQ(captured_.data_payloads[0].size(), 1367u);
    EXPECT_EQ(captured_.data_payloads[1].size(), 733u);
}

// ---------------------------------------------------------------------------
// 12b. flush_pending_writes() during backpressure must not cancel the retry
//      timer — that timer is the ONLY wakeup for the retained bytes, and
//      cancelling it on a drain that did NOT complete is the same
//      "deferred/backpressured means drained" conflation the driver design
//      exists to kill. (Slice-2 review finding.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, FlushDuringBackpressureLeavesTheRetryTimerArmed) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(500, 0xEE);
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // The flush attempt backpressures; the bytes stay retained and the retry
    // timer must survive the flush.
    tunnel_->flush_pending_writes();
    EXPECT_TRUE(captured_.data_payloads.empty());

    allow_send = true;
    ASSERT_TRUE(wait_until([&] { return captured_.concatenated_data() == payload; }))
        << "flush_pending_writes() cancelled the only wakeup for the retained bytes";
}

// ---------------------------------------------------------------------------
// 13. close() while an emitter is mid-drain treats "deferred" as deferred,
//     never as drained: the TUNNEL_CLOSE is emitted by the driver AFTER the
//     remaining DATA, not in between. This is the first rejected draft of the
//     driver design (a boolean that conflated the two let CLOSE overtake
//     in-flight DATA).
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, CloseFromInsideTheSendCallbackWaitsForTheDrain) {
    std::vector<uint8_t> payload(2000, 0xCC);  // emits as 1367 + 633

    bool closed = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        captured_.record(wire);
        if (!closed) {
            closed = true;
            // The driver is active (this very callback): close() must defer.
            tunnel_->close();
        }
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    ASSERT_TRUE(wait_until([&] {
        return std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                          FrameType::TUNNEL_CLOSE) == 1;
    })) << "deferred close never fired after the drain";

    EXPECT_EQ(captured_.concatenated_data(), payload) << "close truncated in-flight data";
    // CLOSE is the LAST frame — after both DATA frames, never between them.
    ASSERT_FALSE(captured_.all_frame_types.empty());
    EXPECT_EQ(captured_.all_frame_types.back(), FrameType::TUNNEL_CLOSE);
    EXPECT_EQ(captured_.all_frame_types.size(), 3u);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Disconnecting);
}

// ---------------------------------------------------------------------------
// 14. Local half-close AND remote close both deferred behind the same
//     backpressured drain settle exactly once. The drain-complete bookkeeping
//     must consume BOTH flags in one pass: leaving `remote_close_pending_`
//     set let a later empty-FIFO driver run (the flush timer fires
//     regardless) finalize the remote close a second time, double-counting
//     the remote-close metric. (Slice-2 review finding.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, DeferredLocalAndRemoteCloseSettleExactlyOnce) {
    const auto remote_closed_before = toxtunnel::util::MetricsRegistry::instance().tunnels_closed(
        toxtunnel::util::MetricsRegistry::CloseReason::Remote);

    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(300, 0xDD);
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    // Local EOF defers behind the retained bytes...
    tunnel_->on_tcp_read_eof();
    // ...and the peer's CLOSE arrives while they are still retained.
    tunnel_->handle_frame(ProtocolFrame::make_tunnel_close(tunnel_->tunnel_id()));
    EXPECT_TRUE(captured_.data_payloads.empty());

    allow_send = true;
    ASSERT_TRUE(wait_until([&] { return tunnel_->state() == Tunnel::State::Closed; }))
        << "deferred local+remote close never settled after the drain";
    EXPECT_EQ(captured_.concatenated_data(), payload);

    // Force further empty-FIFO driver runs; they must find nothing to settle.
    tunnel_->flush_pending_writes();
    pump_for(20ms);

    const auto remote_closed_after = toxtunnel::util::MetricsRegistry::instance().tunnels_closed(
        toxtunnel::util::MetricsRegistry::CloseReason::Remote);
    EXPECT_EQ(remote_closed_after - remote_closed_before, 1u)
        << "the remote close was finalized more than once";
}

// ===========================================================================
// Terminal Abort ordering (slice 3, issue #24)
// ===========================================================================

// ---------------------------------------------------------------------------
// 15. send_error() seals admission and abandons retained DATA atomically, so
//     no TUNNEL_DATA can reach the wire after the terminal TUNNEL_ERROR —
//     previously the retained cohorts kept riding the retry timer and emitted
//     against a tunnel the peer had already torn down. Also: one tunnel, one
//     terminal ERROR; the second call is a suppressed duplicate.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, SendErrorAbandonsRetainedDataAndClaimsTheOneTerminalError) {
    bool allow_send = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        if (!allow_send) {
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    // Retained under backpressure.
    std::vector<uint8_t> payload(400, 0xAB);
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));

    allow_send = true;
    tunnel_->send_error(2, "target went away");
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error);

    // Admission is sealed: nothing new gets in.
    EXPECT_FALSE(tunnel_->send_data_to_tox(payload))
        << "admission accepted bytes after the terminal Abort seal";

    // A duplicate terminal error is suppressed entirely.
    tunnel_->send_error(3, "duplicate");

    // Give the (now pointless) retry timer every chance to misbehave.
    pump_for(30ms);

    const auto errors = std::count(captured_.all_frame_types.begin(),
                                   captured_.all_frame_types.end(), FrameType::TUNNEL_ERROR);
    const auto data_frames = std::count(captured_.all_frame_types.begin(),
                                        captured_.all_frame_types.end(), FrameType::TUNNEL_DATA);
    EXPECT_EQ(errors, 1) << "either the duplicate was not suppressed or the ERROR never went out";
    EXPECT_EQ(data_frames, 0) << "abandoned DATA reached the wire after the terminal ERROR";
}

// ---------------------------------------------------------------------------
// 15b. A CLOSE deferred behind backpressure records an Owed obligation that
//      pins the tunnel id. send_error()'s abandonment removes the drain that
//      would have discharged it, so it must give the obligation up itself —
//      after the ERROR attempt and the terminal transition — or an owner
//      whose on_id_releasable hook is already installed waits forever and
//      the id is pinned for the life of the object.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, SendErrorReleasesAnOwedCloseObligation) {
    tunnel_->set_on_send_to_tox(
        [&](std::span<const uint8_t>) -> SendOutcome { return SendOutcome::SendqFull; });
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(200, 0x77);
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));
    tunnel_->close();  // defers behind the retained bytes; CLOSE now Owed
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Connected) << "close was not deferred";

    bool releasable = false;
    tunnel_->set_on_id_releasable([&] { releasable = true; });
    EXPECT_FALSE(releasable) << "id released while a CLOSE was still owed";

    tunnel_->send_error(2, "target died mid-close");
    EXPECT_TRUE(releasable)
        << "the owed CLOSE was abandoned silently and the id stayed pinned forever";
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error);
}

// ---------------------------------------------------------------------------
// 16. send_error() from INSIDE the driver's send callback: the abandonment
//     runs while a DATA frame is in flight. The commit step must tolerate the
//     emptied FIFO (nothing to consume), the remainder must never follow the
//     ERROR onto the wire, and nothing crashes.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, SendErrorFromInsideTheSendCallbackAbandonsTheRemainder) {
    std::vector<uint8_t> payload(2000, 0xCD);  // would emit as 1367 + 633

    bool errored = false;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        captured_.record(wire);
        if (!errored) {
            errored = true;
            // Same thread, mid-frame: the driver is active and its first
            // frame is being accepted right now.
            tunnel_->send_error(2, "mid-flight failure");
        }
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));
    pump_for(30ms);

    // Wire order: the first DATA frame (in flight when the error struck),
    // then the ERROR, then silence — the 633-byte remainder was abandoned.
    ASSERT_GE(captured_.all_frame_types.size(), 2u);
    EXPECT_EQ(captured_.all_frame_types[0], FrameType::TUNNEL_DATA);
    EXPECT_EQ(captured_.all_frame_types[1], FrameType::TUNNEL_ERROR);
    EXPECT_EQ(captured_.all_frame_types.size(), 2u)
        << "abandoned remainder (or a duplicate frame) reached the wire after the ERROR";
    EXPECT_EQ(captured_.data_payloads.size(), 1u);
    EXPECT_EQ(captured_.data_payloads[0].size(), 1367u);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error);
}

// ---------------------------------------------------------------------------
// 16b. close() re-entered from the terminal ERROR's own transport callback:
//      the state still reads Connected there (the Error transition happens
//      after the send), so only the Abort seal stands between the re-entrant
//      close and a TUNNEL_CLOSE emitted AFTER the terminal ERROR —
//      downgrading Abort to graceful on the wire. (Slice-3 review finding.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ReentrantCloseDuringTheTerminalErrorEmitsNoClose) {
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        captured_.record(wire);
        auto frame = ProtocolFrame::deserialize(wire);
        if (frame.has_value() && frame.value().type() == FrameType::TUNNEL_ERROR) {
            tunnel_->close();  // state still reads Connected here
        }
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    tunnel_->send_error(2, "boom");
    pump_for(20ms);

    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_CLOSE),
              0)
        << "a graceful CLOSE followed the terminal ERROR onto the wire";
    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_ERROR),
              1);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error);
}

// ---------------------------------------------------------------------------
// 16b2. force_close() re-entered from the terminal ERROR's transport
//       callback: it claims Connected -> Closed and asks to announce a CLOSE
//       before send_error() has fenced the close machinery. Only the Abort
//       seal consulted at the EMISSION boundary (emit_close_frame_once)
//       stops that CLOSE from following the ERROR onto the wire; the
//       terminal Closed claim must also survive (send_error's transition is
//       conditional, not a blind Error store). (Slice-3 follow-up P1.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ReentrantForceCloseDuringTheTerminalErrorEmitsNoClose) {
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        captured_.record(wire);
        auto frame = ProtocolFrame::deserialize(wire);
        if (frame.has_value() && frame.value().type() == FrameType::TUNNEL_ERROR) {
            tunnel_->force_close();  // claims Connected -> Closed re-entrantly
        }
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    tunnel_->send_error(2, "boom");
    pump_for(20ms);

    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_CLOSE),
              0)
        << "force_close's CLOSE announcement followed the terminal ERROR onto the wire";
    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_ERROR),
              1);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Closed)
        << "send_error's transition clobbered the terminal state force_close claimed";
}

// ---------------------------------------------------------------------------
// 16c. send_error() from inside an in-flight CLOSE's transport callback,
//      where the CLOSE comes back SendqFull: the terminal fence must stop
//      the SendqFull verdict from restoring Owed and re-arming a CLOSE retry
//      that would land after the ERROR. Also: the CLOSE emit path must not
//      clobber the terminal Error state with its Disconnecting transition.
//      (Slice-3 review finding.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, TerminalErrorFencesAnInFlightCloseRetry) {
    int close_attempts = 0;
    tunnel_->set_on_send_to_tox([&](std::span<const uint8_t> wire) -> SendOutcome {
        auto frame = ProtocolFrame::deserialize(wire);
        if (frame.has_value() && frame.value().type() == FrameType::TUNNEL_CLOSE) {
            ++close_attempts;
            // Same thread, mid-CLOSE: the target died while the close was
            // inside the transport.
            tunnel_->send_error(2, "died during close");
            return SendOutcome::SendqFull;
        }
        captured_.record(wire);
        return SendOutcome::Sent;
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    tunnel_->close();  // empty FIFO: the CLOSE emits synchronously
    pump_for(100ms);   // a wrongly re-armed retry would fire well within this

    EXPECT_EQ(close_attempts, 1) << "the CLOSE retried after the terminal ERROR";
    EXPECT_EQ(std::count(captured_.all_frame_types.begin(), captured_.all_frame_types.end(),
                         FrameType::TUNNEL_ERROR),
              1);
    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error)
        << "the CLOSE path's Disconnecting transition clobbered the terminal state";
}

// ---------------------------------------------------------------------------
// 16d. force_close() with retained outbound DATA and an accepting transport:
//      the best-effort flush must reach the wire BEFORE the CLOSE
//      announcement — the peer drops post-close frames as "unknown tunnel",
//      so CLOSE-then-DATA is the recorded truncation mistake. (Slice-3
//      review finding: the old order announced first.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ForceCloseFlushesRetainedDataBeforeItsClose) {
    tunnel_->configure_coalesce(/*max_delay_us=*/kBatchingDelayUs, /*max_bytes=*/1362);

    std::vector<uint8_t> payload(300, 0x5A);
    ASSERT_TRUE(tunnel_->send_data_to_tox(payload));  // held for the flush timer

    tunnel_->force_close();

    EXPECT_EQ(captured_.concatenated_data(), payload) << "force_close dropped deliverable bytes";
    ASSERT_GE(captured_.all_frame_types.size(), 2u);
    EXPECT_EQ(captured_.all_frame_types[0], FrameType::TUNNEL_DATA);
    EXPECT_EQ(captured_.all_frame_types[1], FrameType::TUNNEL_CLOSE)
        << "the CLOSE announcement overtook the flushed DATA";
}

// ---------------------------------------------------------------------------
// 16e. A transport callback that THROWS during the terminal ERROR must not
//      strand the tunnel: the claim is irrevocable (later send_error calls
//      are suppressed duplicates), so the terminal transition and the close
//      notification must still run. (Slice-3 review finding; mirrors the
//      ClaimGuard in emit_close_frame_once.)
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, ThrowingTransportDoesNotStrandTheTerminalError) {
    tunnel_->set_on_send_to_tox([](std::span<const uint8_t>) -> SendOutcome {
        throw std::runtime_error("transport exploded");
    });
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    bool close_notified = false;
    tunnel_->set_on_close([&] { close_notified = true; });

    tunnel_->send_error(2, "boom");

    EXPECT_EQ(tunnel_->state(), Tunnel::State::Error)
        << "the throwing transport skipped the terminal transition";
    EXPECT_TRUE(close_notified) << "the throwing transport skipped the close notification";
}

// ---------------------------------------------------------------------------
// 17. close_outbound_gate() publishes the Abort seal in the same critical
//     section that closes the gate: one authority. Afterwards ordinary
//     admission is refused outright instead of feeding bytes to fake-success
//     gated sends.
// ---------------------------------------------------------------------------

TEST_F(TunnelCoalesceTest, GateCloseSealsAdmissionInTheSameStep) {
    tunnel_->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    tunnel_->close_outbound_gate();
    EXPECT_TRUE(tunnel_->outbound_gate_closed());

    std::vector<uint8_t> payload(64, 0x11);
    EXPECT_FALSE(tunnel_->send_data_to_tox(payload))
        << "admission stayed open after the gate closed — gate and seal split authority";
    EXPECT_TRUE(captured_.data_payloads.empty());
}
