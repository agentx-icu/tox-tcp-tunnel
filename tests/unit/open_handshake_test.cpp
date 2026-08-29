// Tests for the open-handshake send seam: TUNNEL_OPEN driver ownership on the
// client side and the OPEN_ACK causal barrier on the server side.
//
// No test here sleeps or uses a wall-clock deadline. The suite runs on a
// Windows ARM64 VM whose timer granularity is ~15.6 ms, so any assertion
// phrased as "within N milliseconds" is a coin flip there. Timing is
// instead asserted structurally: `poll()` runs only handlers that are already
// ready (so a positive retry delay means "nothing runs"), and `run()` returns
// when the io_context has no work left (so a test that must reach a resolution
// simply runs to completion rather than waiting a guessed interval).
//
// Most tests here are also DETERMINISTIC — they inject at the exact point the
// property lives, and fail reliably against the defect they describe. A few are
// not: where a window sits between two statements with no callback to hook,
// they race it instead. Those are labelled GUARD in place, and a guard is not
// evidence — it may pass against broken code. Do not cite one as coverage.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/app/tunnel_senders.hpp"
#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/sendq_retry.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/metrics.hpp"

// Google style disallows `using namespace`; name what is actually used.
namespace app = toxtunnel::app;
namespace core = toxtunnel::core;
namespace tunnel = toxtunnel::tunnel;
namespace tox = toxtunnel::tox;
namespace util = toxtunnel::util;
using toxtunnel::tunnel::FrameType;
using toxtunnel::tunnel::ProtocolFrame;
using toxtunnel::tunnel::SendOutcome;
using toxtunnel::tunnel::Tunnel;
using toxtunnel::tunnel::TunnelImpl;
using toxtunnel::tunnel::TunnelManager;

namespace {

constexpr std::uint16_t kTunnelId = 42;
constexpr std::uint32_t kFriendNumber = 1;

/// Windows' default timer resolution.
///
/// An asio timer with a shorter nominal delay routinely takes about this long
/// there — the same platform behaviour that forced
/// `tunnel::kMinHonouredCoalesceDelayUs`. Any wait for a timer has to be sized
/// against THIS, not against the timer's nominal delay.
constexpr auto kTimerGranularity = std::chrono::milliseconds(16);

/// Safety bound for any wait that depends on a SENDQ retry timer firing.
///
/// DERIVED from the retry cadence rather than hardcoded, so the budget and the
/// thing it waits for cannot drift apart. Sized for Windows: the base retry
/// delay is 2 ms, but there that is one ~15.6 ms tick, and a wait spanning
/// several backoff steps needs the sum of those ticks, not the sum of the
/// nominal delays.
///
/// Deliberately generous. Every wait below returns as soon as its predicate
/// holds, so this is only ever reached when something is actually broken — at
/// which point the caller's assertion fails loudly, which is the point.
constexpr auto kRetryWaitBudget =
    std::chrono::duration_cast<std::chrono::milliseconds>(tunnel::kSendqRetryMaxDelay) * 100 +
    kTimerGranularity * 100;

/// Drive @p io_ctx until @p done holds, bounded by a wall-clock deadline.
///
/// ONE mechanism for every asynchronous wait in this file. Two Windows-only CI
/// failures came from hand-rolled waits here: first a spin bounded by an
/// iteration count, then the same thing after a partial sweep missed a loop
/// whose predicate sat in the body rather than the condition. An iteration count
/// is a proxy for time and the proxy breaks under contention — 2000 non-blocking
/// `poll()` calls complete in about a millisecond, so they expire before a 2 ms
/// timer can even fire.
///
/// Uses `run_for`, not `poll()`: it BLOCKS until there is work, so waiting for a
/// timer costs no CPU and cannot outrun the timer it is waiting for.
///
/// NOT for every `poll()` in this file. A bare `poll()` followed by an assertion
/// that nothing happened is an ANTI-wait: it runs only already-ready handlers to
/// prove no timer was armed (the retry-spin checks). Giving those a deadline
/// would invert their meaning — they must not wait. Leave them alone.
template <typename Predicate>
void pump_io_until(asio::io_context& io_ctx, Predicate done,
                   std::chrono::milliseconds timeout = kRetryWaitBudget) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return;
        }
        const auto slice = std::min<std::chrono::milliseconds>(
            kTimerGranularity,
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now) +
                std::chrono::milliseconds(1));
        io_ctx.restart();
        io_ctx.run_for(slice);
    }
    // POST-CONDITION: leave the context runnable. `run_for()` stops the
    // io_context when its slice expires, and a stopped one makes a later
    // `run()` return immediately without servicing anything — which silently
    // broke a test whose worker thread calls run() after connecting.
    io_ctx.restart();
}

/// Frame type of an unprefixed wire buffer (offset 0; see ProtocolFrame).
[[nodiscard]] FrameType type_of(std::span<const std::uint8_t> wire) {
    return static_cast<FrameType>(wire[0]);
}

/// Records every frame type a tunnel actually managed to put on the wire, and
/// lets a test steer the transport verdict per attempt.
struct FakeTransport {
    std::vector<FrameType> delivered;  ///< Frames the peer would have seen.
    std::vector<FrameType> attempted;  ///< Every attempt, delivered or not.
    SendOutcome verdict{SendOutcome::Sent};
    /// After this many attempts the verdict flips to `after_verdict`. Keeps a
    /// "permanently backpressured" test from looping forever.
    unsigned flip_after{0};
    SendOutcome after_verdict{SendOutcome::Sent};

    TunnelImpl::SendToToxCallback callback() {
        return [this](std::span<const std::uint8_t> wire) -> SendOutcome {
            attempted.push_back(type_of(wire));
            const SendOutcome outcome =
                (flip_after > 0 && attempted.size() > flip_after) ? after_verdict : verdict;
            if (outcome == SendOutcome::Sent) {
                delivered.push_back(type_of(wire));
            }
            return outcome;
        };
    }

    [[nodiscard]] std::size_t count(FrameType type) const {
        std::size_t n = 0;
        for (const auto t : delivered) {
            if (t == type) {
                ++n;
            }
        }
        return n;
    }
};

}  // namespace

// ===========================================================================
// 1. Retry cadence — the property that keeps every driver spin-free
// ===========================================================================

TEST(SendqRetryCadenceTest, DelayIsAlwaysPositiveMonotoneAndCapped) {
    // The whole reason this schedule exists rather than reusing
    // tunnel.coalesce_max_delay_us: that value is legally 0 (the effective
    // Windows default, since sub-tick delays are clamped there), and a
    // zero-delay timer that re-arms from its own handler never lets the
    // io_context go idle.
    auto previous = tunnel::sendq_retry_delay(0);
    EXPECT_GT(previous.count(), 0);
    for (unsigned attempt = 1; attempt < 64; ++attempt) {
        const auto delay = tunnel::sendq_retry_delay(attempt);
        EXPECT_GT(delay.count(), 0) << "attempt " << attempt;
        EXPECT_GE(delay, previous) << "attempt " << attempt;
        EXPECT_LE(delay, tunnel::kSendqRetryMaxDelay) << "attempt " << attempt;
        previous = delay;
    }
    EXPECT_EQ(tunnel::sendq_retry_delay(63), tunnel::kSendqRetryMaxDelay);
}

// ===========================================================================
// 2. TUNNEL_OPEN is driver-owned
// ===========================================================================

class OpenDriverTest : public ::testing::Test {
   protected:
    std::shared_ptr<TunnelImpl> MakeTunnel() {
        // shared_ptr, not a stack object: the retry timer captures
        // weak_from_this() and refuses to arm without an owner.
        return std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    }

    asio::io_context io_ctx;
    FakeTransport transport;
};

TEST_F(OpenDriverTest, BackpressuredOpenStaysConnectingAndIsNotReportedSent) {
    transport.verdict = SendOutcome::SendqFull;
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    EXPECT_TRUE(tunnel->open("example.com", 443)) << "SendqFull is not an open failure";
    EXPECT_EQ(tunnel->state(), Tunnel::State::Connecting);
    EXPECT_FALSE(tunnel->open_sent()) << "a parked OPEN has not reached the peer";
    EXPECT_TRUE(transport.delivered.empty());

    // Nothing may be torn down merely because the transport backpressured.
    tunnel->close();
}

TEST_F(OpenDriverTest, BackpressuredThenSentDeliversExactlyOneOpen) {
    transport.verdict = SendOutcome::SendqFull;
    transport.flip_after = 1;  // First attempt refused, every later one accepted.
    transport.after_verdict = SendOutcome::Sent;

    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    ASSERT_TRUE(tunnel->open("example.com", 443));
    ASSERT_FALSE(tunnel->open_sent());
    ASSERT_EQ(tunnel->open_attempts(), 1u);

    // run() (not run_for) — the retry resolves and then there is no work left,
    // so this terminates on its own rather than on a guessed deadline.
    io_ctx.run();

    EXPECT_TRUE(tunnel->open_sent());
    EXPECT_EQ(tunnel->state(), Tunnel::State::Connecting) << "still awaiting the peer's ACK";
    EXPECT_EQ(transport.count(FrameType::TUNNEL_OPEN), 1u) << "the OPEN must not be duplicated";
    EXPECT_EQ(tunnel->open_attempts(), 2u);
}

TEST_F(OpenDriverTest, LocalCloseBeforeOpenIsSentEmitsNoTunnelClose) {
    // THE INVARIANT: the peer has never heard of this tunnel id, so a
    // TUNNEL_CLOSE names nothing — and once the id is released and recycled it
    // would name somebody else's tunnel.
    transport.verdict = SendOutcome::SendqFull;
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    unsigned close_notifications = 0;
    tunnel->set_on_close([&close_notifications]() { ++close_notifications; });

    ASSERT_TRUE(tunnel->open("example.com", 443));
    ASSERT_EQ(close_notifications, 0u) << "SendqFull is not a resolution";

    tunnel->close();

    EXPECT_EQ(transport.count(FrameType::TUNNEL_CLOSE), 0u);
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed);
    EXPECT_EQ(close_notifications, 1u) << "the id is released exactly once, at resolution";

    // And the cancelled retry must not resurrect the OPEN afterwards.
    io_ctx.run();
    EXPECT_TRUE(transport.delivered.empty());
    EXPECT_EQ(tunnel->open_attempts(), 1u);
}

TEST_F(OpenDriverTest, LocalCloseAfterOpenIsSentDoesEmitTunnelClose) {
    // The mirror image: once the peer owns half a tunnel, the CLOSE is
    // mandatory. Without this the invariant above could be "satisfied" by never
    // sending CLOSE at all.
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    ASSERT_TRUE(tunnel->open("example.com", 443));
    ASSERT_TRUE(tunnel->open_sent());

    tunnel->close();

    EXPECT_EQ(transport.count(FrameType::TUNNEL_CLOSE), 1u);
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed);
}

TEST_F(OpenDriverTest, PermanentFailRollsBackToNone) {
    transport.verdict = SendOutcome::PermanentFail;
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    EXPECT_FALSE(tunnel->open("example.com", 443));
    EXPECT_EQ(tunnel->state(), Tunnel::State::None) << "the id is free for the caller to release";
    EXPECT_FALSE(tunnel->open_sent());
    EXPECT_EQ(tunnel->target_host(), "") << "target rolled back with the state";

    // Nothing armed: a permanent failure is not retried.
    EXPECT_EQ(io_ctx.poll(), 0u);
    EXPECT_EQ(tunnel->open_attempts(), 1u);
}

TEST_F(OpenDriverTest, ReleasedIdIsReusableAfterAPermanentFail) {
    transport.verdict = SendOutcome::PermanentFail;
    auto manager = std::make_shared<TunnelManager>(io_ctx);
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());
    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));

    ASSERT_FALSE(tunnel->open("example.com", 443));
    manager->remove_tunnel(kTunnelId);

    EXPECT_FALSE(manager->has_tunnel(kTunnelId));
    auto replacement = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    EXPECT_TRUE(manager->add_tunnel(kTunnelId, replacement)) << "the id must be free again";
}

TEST_F(OpenDriverTest, ReopenAfterPermanentFailActuallySendsAgain) {
    // A rollback puts the state machine back at None, so a second open() is
    // legitimate — and must really put a TUNNEL_OPEN on the wire. If the
    // resolved OpenPhase from the failed attempt survives the rollback, the
    // second open() sends nothing at all and still reports success: a tunnel
    // that believes it is Connecting for a frame that was never transmitted.
    transport.verdict = SendOutcome::PermanentFail;
    auto tunnel = MakeTunnel();
    tunnel->set_on_send_to_tox(transport.callback());

    ASSERT_FALSE(tunnel->open("example.com", 443));
    ASSERT_EQ(tunnel->state(), Tunnel::State::None);
    ASSERT_EQ(transport.attempted.size(), 1u);

    transport.verdict = SendOutcome::Sent;
    EXPECT_TRUE(tunnel->open("example.com", 443));
    EXPECT_EQ(transport.attempted.size(), 2u) << "the second open must actually attempt a send";
    EXPECT_TRUE(tunnel->open_sent());
    EXPECT_EQ(tunnel->state(), Tunnel::State::Connecting);
    EXPECT_EQ(transport.count(FrameType::TUNNEL_OPEN), 1u);
}

// ---------------------------------------------------------------------------
// A close that lands *while the OPEN send is in flight* owns the terminal
// state. These two reproduce that window deterministically and single-threaded
// by closing from inside the send callback — which is exactly the
// OpenPhase::Sending window, with no scheduling luck involved.
// ---------------------------------------------------------------------------

TEST_F(OpenDriverTest, CloseDuringTheInitialOpenSendIsNotRolledBackToNone) {
    auto tunnel = MakeTunnel();
    TunnelImpl* raw = tunnel.get();  // Not the shared_ptr: that would self-cycle.

    unsigned close_notifications = 0;
    tunnel->set_on_close([&close_notifications]() { ++close_notifications; });

    bool closed_from_send = false;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame_wire) -> SendOutcome {
        transport.attempted.push_back(type_of(frame_wire));
        if (type_of(frame_wire) == FrameType::TUNNEL_OPEN && !closed_from_send) {
            closed_from_send = true;
            raw->close();  // Resolves the tunnel to Closed, mid-send.
        }
        return SendOutcome::PermanentFail;
    });

    EXPECT_FALSE(tunnel->open("example.com", 443));

    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "the close resolved this tunnel; a failed open must not rewrite that to None";
    EXPECT_EQ(close_notifications, 1u);
}

TEST_F(OpenDriverTest, CloseDuringARetrySendIsNotOverwrittenByError) {
    auto tunnel = MakeTunnel();
    TunnelImpl* raw = tunnel.get();

    unsigned close_notifications = 0;
    tunnel->set_on_close([&close_notifications]() { ++close_notifications; });

    unsigned open_sends = 0;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame_wire) -> SendOutcome {
        transport.attempted.push_back(type_of(frame_wire));
        if (type_of(frame_wire) != FrameType::TUNNEL_OPEN) {
            return SendOutcome::Sent;
        }
        if (++open_sends == 1) {
            return SendOutcome::SendqFull;  // Park it; a retry gets armed.
        }
        raw->close();  // Resolves to Closed while the retry is mid-send.
        return SendOutcome::PermanentFail;
    });

    ASSERT_TRUE(tunnel->open("example.com", 443));
    io_ctx.run();

    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "a retry that fails after the close must not publish Error over Closed";
    EXPECT_EQ(close_notifications, 1u) << "exactly one terminal resolution";
}

TEST_F(OpenDriverTest, ZeroCoalesceDelayDoesNotProduceARetrySpin) {
    // Regression guard for the tempting shortcut of reusing the coalesce timer's
    // delay for the OPEN retry. At coalesce_max_delay_us == 0 that would arm a
    // zero-delay timer that re-arms itself, and poll() — which drains everything
    // already runnable — would burn through attempts without ever returning to
    // the caller with work outstanding.
    transport.verdict = SendOutcome::SendqFull;
    transport.flip_after = 200;  // Escape hatch so a spin terminates rather than hangs.
    transport.after_verdict = SendOutcome::PermanentFail;

    auto tunnel = MakeTunnel();
    tunnel->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);
    tunnel->set_on_send_to_tox(transport.callback());

    ASSERT_TRUE(tunnel->open("example.com", 443));
    ASSERT_EQ(tunnel->open_attempts(), 1u);

    io_ctx.poll();

    // A spin would have run straight to the 200-attempt escape hatch. A real
    // backoff leaves the timer unexpired, so poll() dispatches nothing; the
    // margin absorbs a descheduled test thread without admitting a spin.
    EXPECT_LE(tunnel->open_attempts(), 5u)
        << "OPEN retry is spinning; it must not use the coalesce delay";

    tunnel->close();  // Cancel the outstanding retry so the io_context can drain.
    io_ctx.run();
}

// ===========================================================================
// 3. SendqFull routing per frame type
// ===========================================================================

class SendqRoutingTest : public ::testing::Test {
   protected:
    void SetUp() override {
        manager = std::make_shared<TunnelManager>(io_ctx);
        manager->set_send_handler([this](const std::vector<std::uint8_t>& wire) {
            drained.push_back(type_of(wire));
            return SendOutcome::Sent;
        });
    }

    [[nodiscard]] SendOutcome route(const ProtocolFrame& frame) {
        const auto wire = frame.serialize();
        return tunnel::route_sendq_full(*manager, std::span<const std::uint8_t>(wire));
    }

    asio::io_context io_ctx;
    std::shared_ptr<TunnelManager> manager;
    std::vector<FrameType> drained;  ///< What the manager's retry queue re-sent.
};

TEST_F(SendqRoutingTest, HandshakeAndDataFramesAreReturnedToTheirDriver) {
    EXPECT_EQ(route(ProtocolFrame::make_tunnel_open(kTunnelId, "h", 80)), SendOutcome::SendqFull);
    EXPECT_EQ(route(ProtocolFrame::make_tunnel_ack(kTunnelId, 0)), SendOutcome::SendqFull);
    const std::array<std::uint8_t, 2> payload{1, 2};
    EXPECT_EQ(route(ProtocolFrame::make_tunnel_data(
                  kTunnelId, std::span<const std::uint8_t>(payload.data(), payload.size()))),
              SendOutcome::SendqFull);

    // None of them may have been parked — the whole point is that the caller
    // keeps the frame.
    io_ctx.run();
    EXPECT_TRUE(drained.empty());
}

TEST_F(SendqRoutingTest, OtherControlFramesStillParkAndStillReportSent) {
    // Deliberately unchanged by this slice: CLOSE / ERROR / PING and friends
    // keep the park-and-report-Sent behaviour (and with it the known
    // stale-frame-onto-a-recycled-id hazard) until they too move to driver
    // ownership.
    EXPECT_EQ(route(ProtocolFrame::make_tunnel_close(kTunnelId)), SendOutcome::Sent);
    EXPECT_EQ(route(ProtocolFrame::make_tunnel_error(kTunnelId, 3, "x")), SendOutcome::Sent);
    EXPECT_EQ(route(ProtocolFrame::make_ping()), SendOutcome::Sent);

    io_ctx.run();
    EXPECT_EQ(drained, (std::vector<FrameType>{FrameType::TUNNEL_CLOSE, FrameType::TUNNEL_ERROR,
                                               FrameType::PING}))
        << "parked frames must still be delivered by the drain timer, in order";
}

TEST_F(SendqRoutingTest, TypedSendCannotOvertakeAFrameThatIsMidDrain) {
    // The FIFO barrier has to cover the drain's in-flight entry, not just the
    // deque. drain_pending_outbound() pops its frame and only then calls the
    // transport with the mutex released; during that window the deque is empty,
    // so an unguarded send_frame_typed() sends immediately and its frame reaches
    // toxcore ahead of one that was queued first.
    unsigned close_sends = 0;
    std::optional<SendOutcome> typed_during_drain;
    manager->set_send_handler([&](const std::vector<std::uint8_t>& wire) -> SendOutcome {
        const FrameType type = type_of(wire);
        if (type == FrameType::TUNNEL_CLOSE && ++close_sends == 1) {
            return SendOutcome::SendqFull;  // Park it and arm the drain timer.
        }
        if (type == FrameType::TUNNEL_CLOSE) {
            // Second sighting: we are the drain, inside the transport call with
            // the frame already popped. A driver-owned frame issued right now
            // must be told to wait its turn.
            typed_during_drain =
                manager->send_frame_typed(ProtocolFrame::make_tunnel_ack(kTunnelId, 0));
        }
        drained.push_back(type);
        return SendOutcome::Sent;
    });

    ASSERT_TRUE(manager->send_frame(ProtocolFrame::make_tunnel_close(kTunnelId)));
    io_ctx.run();

    ASSERT_TRUE(typed_during_drain.has_value()) << "the drain never re-sent the parked frame";
    EXPECT_EQ(*typed_during_drain, SendOutcome::SendqFull)
        << "a driver-owned frame must not be sent past a frame that is mid-drain";
    EXPECT_EQ(drained, (std::vector<FrameType>{FrameType::TUNNEL_CLOSE}))
        << "the ACK must not have reached the transport at all";
}

// ===========================================================================
// 4. The OPEN_ACK causal barrier
// ===========================================================================

class OpenAckGateTest : public ::testing::Test {
   protected:
    /// Models what the peer observes, in order. "DATA" is emitted from the
    /// commit callback because that is exactly the causality under test: the
    /// server's target-socket read loop only starts there, so DATA can only
    /// exist downstream of the commit.
    std::vector<std::string> wire;
    bool ack_accepted{false};
    tunnel::SendOutcome ack_verdict{tunnel::SendOutcome::SendqFull};

    std::shared_ptr<app::detail::OpenAckGate> MakeGate() {
        return std::make_shared<app::detail::OpenAckGate>(
            io_ctx,
            [this]() -> tunnel::SendOutcome {
                if (!ack_accepted) {
                    return ack_verdict;
                }
                wire.emplace_back("ACK");
                return tunnel::SendOutcome::Sent;
            },
            [this]() {
                wire.emplace_back("START_READ");
                wire.emplace_back("DATA");
                return true;
            },
            [this]() { wire.emplace_back("ERROR"); },
            [this]() { wire.emplace_back("POST_COMMIT_CLOSE"); });
    }

    asio::io_context io_ctx;
};

TEST_F(OpenAckGateTest, DataCannotOvertakeABackpressuredOpenAck) {
    auto gate = MakeGate();
    gate->start();

    // Bug B: the old code published Connected, bumped the open metrics and
    // called start_read() right after handing the ACK to a bool send that
    // reports a parked frame as queued. DATA then went out on the per-tunnel
    // path, not the manager's retry queue, and could reach a peer that was
    // still in Connecting — which silently discards TUNNEL_DATA.
    EXPECT_TRUE(wire.empty()) << "nothing may be published while the ACK is backpressured";
    EXPECT_FALSE(gate->committed());

    io_ctx.poll();
    EXPECT_TRUE(wire.empty());

    ack_accepted = true;
    io_ctx.run();

    EXPECT_TRUE(gate->committed());
    EXPECT_EQ(wire, (std::vector<std::string>{"ACK", "START_READ", "DATA"}));
}

TEST_F(OpenAckGateTest, AcceptedAckCommitsImmediately) {
    ack_accepted = true;
    auto gate = MakeGate();
    gate->start();

    EXPECT_TRUE(gate->committed());
    EXPECT_EQ(wire, (std::vector<std::string>{"ACK", "START_READ", "DATA"}));
    EXPECT_EQ(gate->attempts(), 1u);
    EXPECT_EQ(io_ctx.poll(), 0u) << "no retry armed after a successful ACK";
}

// Unit-level shape of the abandon path. The end-to-end version — a real socket
// dying, detected by production code — is
// PeerCloseWatchTest.RealTargetDeathDuringABackpressuredAckYieldsError below;
// this one only pins the gate's own bookkeeping.
TEST_F(OpenAckGateTest, TargetDeathWhileAckIsBackpressuredYieldsErrorAndNoData) {
    auto gate = MakeGate();
    gate->start();
    ASSERT_TRUE(wire.empty());

    EXPECT_TRUE(gate->target_gone()) << "the gate owns this teardown; no ordinary close";
    EXPECT_EQ(wire, (std::vector<std::string>{"ERROR"}))
        << "a terminal TUNNEL_ERROR, not a CLOSE the peer cannot act on while Connecting";
    EXPECT_FALSE(gate->committed());

    // The cancelled retry must not resurrect the ACK, and DATA must never
    // appear: the tunnel was never published.
    ack_accepted = true;
    io_ctx.run();
    EXPECT_EQ(wire, (std::vector<std::string>{"ERROR"}));
}

TEST_F(OpenAckGateTest, PermanentAckFailureResolvesTheClientWithAnError) {
    ack_verdict = tunnel::SendOutcome::PermanentFail;
    auto gate = MakeGate();
    gate->start();

    EXPECT_EQ(wire, (std::vector<std::string>{"ERROR"}));
    EXPECT_FALSE(gate->committed());
    EXPECT_EQ(io_ctx.poll(), 0u) << "a permanent failure is not retried";
}

TEST_F(OpenAckGateTest, TargetDeathAfterCommitLeavesTheOrdinaryClosePath) {
    ack_accepted = true;
    auto gate = MakeGate();
    gate->start();
    ASSERT_TRUE(gate->committed());

    EXPECT_FALSE(gate->target_gone())
        << "a live tunnel's target death belongs to Tunnel::close(), not the gate";
    EXPECT_EQ(wire, (std::vector<std::string>{"ACK", "START_READ", "DATA"}))
        << "no ERROR may be appended once the tunnel is published";
}

TEST_F(OpenAckGateTest, ResolutionHappensExactlyOnce) {
    auto gate = MakeGate();
    gate->start();

    EXPECT_TRUE(gate->target_gone());
    EXPECT_TRUE(gate->target_gone()) << "still the gate's teardown, not the ordinary close";
    EXPECT_EQ(wire, (std::vector<std::string>{"ERROR"})) << "abandon must not run twice";
}

TEST_F(OpenAckGateTest, TargetDeathDuringTheAckSendNeverPutsTheErrorBeforeTheAck) {
    // The target dies while the ACK is inside the transport call. Resolving
    // there and then would emit TUNNEL_ERROR (and remove the tunnel) while an
    // OPEN_ACK for that same tunnel was still on its way out — the peer would
    // receive an ACK for a tunnel it had just been told had failed.
    std::shared_ptr<app::detail::OpenAckGate> gate;
    bool gone_absorbed = false;
    gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx,
        [&]() -> tunnel::SendOutcome {
            gone_absorbed = gate->target_gone();
            wire.emplace_back("ACK");  // The send completes regardless.
            return tunnel::SendOutcome::Sent;
        },
        [this]() {
            wire.emplace_back("START_READ");
            wire.emplace_back("DATA");
            return true;
        },
        [this]() { wire.emplace_back("ERROR"); },
        [this]() { wire.emplace_back("POST_COMMIT_CLOSE"); });

    gate->start();

    EXPECT_TRUE(gone_absorbed) << "the gate owns this teardown; no ordinary close";
    EXPECT_EQ(wire, (std::vector<std::string>{"ACK", "ERROR"}))
        << "the in-flight ACK must not be able to follow the ERROR onto the wire";
    EXPECT_FALSE(gate->committed()) << "an abandoned gate must never publish the tunnel";
}

TEST_F(OpenAckGateTest, TargetDeathDuringCommitIsDeferredUntilCommitHasRun) {
    // The only way production reaches target death after a successful ACK is
    // through the read loop that commit itself starts — so the disconnect can
    // land while commit is still running. Reporting "committed" there sends the
    // caller down the ordinary close path against a tunnel that is still None,
    // where Tunnel::close() is a no-op; commit then publishes Connected and
    // starts reading a socket that is already dead.
    ack_accepted = true;
    std::shared_ptr<app::detail::OpenAckGate> gate;
    bool observed_committed_mid_commit = true;
    bool gone_absorbed = false;
    gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx,
        [this]() -> tunnel::SendOutcome {
            wire.emplace_back("ACK");
            return tunnel::SendOutcome::Sent;
        },
        [&]() {
            wire.emplace_back("START_READ");
            observed_committed_mid_commit = gate->committed();
            gone_absorbed = gate->target_gone();
            wire.emplace_back("DATA");
            return true;
        },
        [this]() { wire.emplace_back("ERROR"); },
        [this]() { wire.emplace_back("POST_COMMIT_CLOSE"); });

    gate->start();

    EXPECT_FALSE(observed_committed_mid_commit)
        << "commit must not be observable as done until it has actually run";
    EXPECT_TRUE(gone_absorbed) << "the gate must not hand back a half-published tunnel";
    EXPECT_EQ(wire, (std::vector<std::string>{"ACK", "START_READ", "DATA", "POST_COMMIT_CLOSE"}))
        << "the deferred close must run, and only after commit finished";
    EXPECT_TRUE(gate->committed());
}

TEST_F(OpenAckGateTest, BackpressuredAckDoesNotSpin) {
    // Same guard as the OPEN retry: the ACK cadence must not be the coalesce
    // delay, which is legally zero.
    auto gate = MakeGate();
    gate->start();
    ASSERT_EQ(gate->attempts(), 1u);

    io_ctx.poll();
    EXPECT_LE(gate->attempts(), 5u) << "OPEN_ACK retry is spinning";

    gate->target_gone();  // Cancel the outstanding retry so the io_context drains.
    io_ctx.run();
}

// ===========================================================================
// 5. Target death detected on a REAL socket, by production code
// ===========================================================================
//
// The gate's abandon path is only worth having if something can actually reach
// it. Real TCP death is surfaced by a read completing — and the whole point of
// the barrier is that `start_read()` does not happen until the OPEN_ACK is on
// the wire. So during the backpressure window there is no outstanding read, and
// a target that dies there used to be invisible: nothing would tear the tunnel
// down and the client would sit in Connecting waiting for an ACK whose tunnel
// was already dead.
//
// `TcpConnection::watch_peer_close()` closes that hole, and this test drives it
// with a real loopback pair and a real FIN — no hook is called by hand. What it
// deliberately does NOT cover is `TunnelServer::wire_tcp_to_tunnel()` itself,
// which needs a live ToxAdapter; the wiring there (watch armed before
// `gate->start()`, stood down by `start_read()` inside commit) is mirrored here
// rather than executed.

class PeerCloseWatchTest : public ::testing::Test {
   protected:
    /// Run ready handlers until `done` or the bound is hit. A bounded spin, not
    /// a sleep: loopback FIN arrives in microseconds, and the bound only exists
    /// so a regression fails the assertion instead of hanging the suite.
    template <typename Predicate>
    /// See pump_io_until(): one mechanism for every asynchronous wait here.
    void pump_until(Predicate done, std::chrono::milliseconds timeout = kRetryWaitBudget) {
        pump_io_until(io_ctx, done, timeout);
    }

    asio::io_context io_ctx;
};

TEST_F(PeerCloseWatchTest, RealTargetDeathDuringABackpressuredAckYieldsError) {
    asio::ip::tcp::acceptor acceptor(
        io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto endpoint = acceptor.local_endpoint();

    asio::ip::tcp::socket target(io_ctx);
    bool accepted = false;
    acceptor.async_accept(target, [&accepted](const std::error_code& ec) { accepted = !ec; });

    auto conn = std::make_shared<core::TcpConnection>(io_ctx);
    bool connected = false;
    conn->async_connect(endpoint, [&connected](const std::error_code& ec) { connected = !ec; });

    pump_until([&] { return accepted && connected; });
    ASSERT_TRUE(accepted);
    ASSERT_TRUE(connected);

    // Mirror the production wiring: the ACK is backpressured, so the gate keeps
    // retrying and nothing is published.
    std::vector<std::string> wire;
    auto gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx, []() -> tunnel::SendOutcome { return tunnel::SendOutcome::SendqFull; },
        [&wire]() {
            wire.emplace_back("START_READ");
            wire.emplace_back("DATA");
            return true;
        },
        [&wire]() { wire.emplace_back("ERROR"); },
        [&wire]() { wire.emplace_back("POST_COMMIT_CLOSE"); });

    conn->set_on_disconnect([&wire, gate](const std::error_code&) {
        if (gate->target_gone()) {
            return;
        }
        wire.emplace_back("ORDINARY_CLOSE");
    });

    conn->watch_peer_close();
    gate->start();
    ASSERT_TRUE(wire.empty()) << "nothing may be published while the ACK is backpressured";

    // Kill the target for real. No hook is invoked by hand from here on.
    std::error_code ignored;
    target.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    target.close(ignored);

    pump_until([&] { return !wire.empty(); });

    // Snapshot before standing the gate down, so the teardown below cannot
    // retroactively satisfy the assertion it is meant to prove.
    const std::vector<std::string> observed = wire;
    EXPECT_EQ(observed, (std::vector<std::string>{"ERROR"}))
        << "a real FIN during the backpressure window must reach the gate's abandon path";
    EXPECT_FALSE(gate->committed());

    // Stand everything down explicitly. The ACK sender is permanently
    // backpressured, so a regression that never notices the FIN would leave the
    // gate retrying forever and a bare run() would hang the suite instead of
    // failing it. target_gone() is a no-op on an already-abandoned gate.
    gate->target_gone();
    conn->force_close();
    io_ctx.restart();
    io_ctx.run();

    EXPECT_EQ(std::count(wire.begin(), wire.end(), std::string("DATA")), 0)
        << "the tunnel was never published, so no data may ever have flowed";
}

TEST_F(PeerCloseWatchTest, WatchStandsDownWhenTheReadLoopTakesOver) {
    // start_read() must supersede the watch: the read loop reports EOF as a
    // *half*-close via on_read_eof_, and a stale watch also firing would turn
    // that into a hard close.
    asio::ip::tcp::acceptor acceptor(
        io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto endpoint = acceptor.local_endpoint();

    asio::ip::tcp::socket target(io_ctx);
    bool accepted = false;
    acceptor.async_accept(target, [&accepted](const std::error_code& ec) { accepted = !ec; });

    auto conn = std::make_shared<core::TcpConnection>(io_ctx);
    bool connected = false;
    conn->async_connect(endpoint, [&connected](const std::error_code& ec) { connected = !ec; });
    pump_until([&] { return accepted && connected; });
    ASSERT_TRUE(accepted);
    ASSERT_TRUE(connected);

    unsigned eofs = 0;
    unsigned disconnects = 0;
    conn->set_on_read_eof([&eofs]() { ++eofs; });
    conn->set_on_disconnect([&disconnects](const std::error_code&) { ++disconnects; });

    conn->watch_peer_close();
    conn->start_read();  // Implies cancel_peer_close_watch().

    std::error_code ignored;
    target.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);

    pump_until([&] { return eofs > 0; });

    EXPECT_EQ(eofs, 1u) << "the read loop owns EOF reporting once it is running";
    EXPECT_EQ(disconnects, 0u) << "a stale watch must not escalate a half-close to a hard close";

    target.close(ignored);
    conn->force_close();
    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 6. Terminal-state ownership under concurrency
// ===========================================================================
//
// `open()`, `retry_open_send()`, `close()` and `force_close()` can all be
// racing for the same tunnel, and the phase claim under `open_retry_mutex_`
// only excludes the two OPEN attempts from each other — the state transition
// itself happens later, outside that mutex, because firing a state callback
// under a tunnel lock is forbidden (H-01). The compare-exchange inside
// `transition_state_if()` is what closes the remaining gap.
//
// These are genuine races, so they are exercised by repetition rather than by a
// forced interleaving — but the assertions are invariants, not timings, so a
// run either proves nothing or proves a real violation. No sleeps.

namespace {

constexpr int kRaceIterations = 20000;

}  // namespace

class OpenTerminalOwnershipTest : public ::testing::Test {
   protected:
    asio::io_context io_ctx;
};

// Deterministic injection of the exact window finding 1 describes: the OPEN
// attempt has claimed ownership under open_retry_mutex_ and its send has
// returned, but the terminal transition has not run yet — and in that gap
// another resolver publishes a terminal state.
//
// `set_state()` stands in for that resolver rather than a real close() on a
// second thread, and it stands in faithfully: the precondition the transition
// must survive is "the tunnel already left Connecting, and it was not this
// attempt that took it out", which is exactly what this sets up. Using close()
// here would instead set open_abandon_requested_ and take the *other*,
// already-covered branch — which is why the round-2 tests do not catch this.
TEST_F(OpenTerminalOwnershipTest, InitialFailureDoesNotRollBackOverAResolutionItDoesNotOwn) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();

    tunnel->set_on_send_to_tox([raw](std::span<const std::uint8_t> wire) -> SendOutcome {
        if (type_of(wire) == FrameType::TUNNEL_OPEN) {
            raw->set_state(Tunnel::State::Closed);
        }
        return SendOutcome::PermanentFail;
    });

    EXPECT_FALSE(tunnel->open("example.com", 443));
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "a failed open must not roll a resolved tunnel back to None";
}

TEST_F(OpenTerminalOwnershipTest, RetryFailureDoesNotPublishErrorOverAResolutionItDoesNotOwn) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();

    unsigned open_sends = 0;
    unsigned close_notifications = 0;
    tunnel->set_on_close([&close_notifications]() { ++close_notifications; });
    tunnel->set_on_send_to_tox(
        [raw, &open_sends](std::span<const std::uint8_t> wire) -> SendOutcome {
            if (type_of(wire) != FrameType::TUNNEL_OPEN) {
                return SendOutcome::Sent;
            }
            if (++open_sends == 1) {
                return SendOutcome::SendqFull;  // Park it; a retry gets armed.
            }
            raw->set_state(Tunnel::State::Closed);
            return SendOutcome::PermanentFail;
        });

    ASSERT_TRUE(tunnel->open("example.com", 443));
    io_ctx.run();

    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "a failed retry must not publish Error over a state it does not own";
    EXPECT_EQ(close_notifications, 0u) << "and must not book a second terminal resolution for it";
}

TEST_F(OpenTerminalOwnershipTest, AFailedOpenNeverOverwritesAConcurrentCloseResolution) {
    for (int i = 0; i < kRaceIterations; ++i) {
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        TunnelImpl* raw = tunnel.get();

        std::atomic<unsigned> close_notifications{0};
        tunnel->set_on_close([&close_notifications]() { close_notifications.fetch_add(1); });

        // Signals the closer the moment the OPEN send is about to return, so the
        // close lands in the post-send / pre-transition window rather than
        // inside the send callback (which is a different, already-covered case).
        std::atomic<bool> send_returning{false};
        tunnel->set_on_send_to_tox([&send_returning](std::span<const std::uint8_t>) -> SendOutcome {
            send_returning.store(true, std::memory_order_release);
            return SendOutcome::PermanentFail;
        });

        std::thread closer([&]() {
            while (!send_returning.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            raw->close();
        });

        (void)tunnel->open("example.com", 443);
        closer.join();

        const auto state = tunnel->state();
        const unsigned closes = close_notifications.load();

        ASSERT_LE(closes, 1u) << "iteration " << i << ": the tunnel resolved twice";
        ASSERT_NE(state, Tunnel::State::Connecting) << "iteration " << i << ": left in Connecting";
        if (closes == 1) {
            ASSERT_EQ(state, Tunnel::State::Closed)
                << "iteration " << i << ": on_close fired, but the state was overwritten to "
                << to_string(state);
        } else {
            ASSERT_EQ(state, Tunnel::State::None)
                << "iteration " << i << ": the failed open must roll back to None";
        }
    }
}

TEST_F(OpenTerminalOwnershipTest, OpenCannotResurrectATunnelAForceCloseAlreadyResolved) {
    // force_close() does NOT short-circuit on None — it only ignores Closed — so
    // it can publish Closed between open()'s state check and open()'s own
    // transition, and nothing may bring such a tunnel back to Connecting.
    //
    // Unlike the two tests above, this window has no injectable hook: it sits
    // between two statements of open() with no callback in between. So it is
    // raced, with both threads released from a tight spin rendezvous so the two
    // sub-microsecond paths overlap. The assertion is an invariant, never a
    // timing, so a run either proves nothing or proves a real violation.
    for (int i = 0; i < kRaceIterations; ++i) {
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        TunnelImpl* raw = tunnel.get();

        std::atomic<unsigned> close_notifications{0};
        tunnel->set_on_close([&close_notifications]() { close_notifications.fetch_add(1); });
        tunnel->set_on_send_to_tox(
            [](std::span<const std::uint8_t>) -> SendOutcome { return SendOutcome::Sent; });

        std::atomic<bool> closer_ready{false};
        std::atomic<bool> go{false};
        std::thread closer([&]() {
            closer_ready.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            raw->force_close();
        });

        while (!closer_ready.load(std::memory_order_acquire)) {
        }
        go.store(true, std::memory_order_release);
        (void)tunnel->open("example.com", 443);
        closer.join();

        ASSERT_EQ(close_notifications.load(), 1u) << "iteration " << i;
        ASSERT_EQ(tunnel->state(), Tunnel::State::Closed)
            << "iteration " << i << ": force_close resolved this tunnel, but it ended up "
            << to_string(tunnel->state());
    }
}

// ===========================================================================
// 7. The FIFO barrier on the direct per-tunnel send path
// ===========================================================================

class TunnelSendersTest : public ::testing::Test {
   protected:
    void SetUp() override {
        manager = std::make_shared<TunnelManager>(io_ctx);
        // The manager's own handler: refuses the first frame (parking it), then
        // accepts everything and records what reached "toxcore".
        manager->set_send_handler([this](const std::vector<std::uint8_t>& wire) -> SendOutcome {
            if (refuse_next_manager_send) {
                refuse_next_manager_send = false;
                return SendOutcome::SendqFull;
            }
            on_wire.push_back(type_of(wire));
            return SendOutcome::Sent;
        });

        senders = app::detail::make_tunnel_senders(
            [this](std::uint32_t, const std::uint8_t* data, std::size_t length) {
                // The per-tunnel path prefixes the lossless byte, so the frame
                // type sits at offset 1 here.
                if (length > 1) {
                    on_wire.push_back(static_cast<FrameType>(data[1]));
                }
                return tox::ToxAdapter::LosslessSendOutcome::Sent;
            },
            manager, kFriendNumber);
    }

    [[nodiscard]] SendOutcome send_direct(const ProtocolFrame& frame) {
        const auto wire = frame.serialize();
        return senders.span(std::span<const std::uint8_t>(wire));
    }

    asio::io_context io_ctx;
    std::shared_ptr<TunnelManager> manager;
    app::detail::TunnelSenders senders;
    bool refuse_next_manager_send{false};
    std::vector<FrameType> on_wire;
};

TEST_F(TunnelSendersTest, HandshakeFrameDoesNotOvertakeAParkedFrameForARecycledId) {
    // The design's central failure, on the production path:
    //   CLOSE(id=7) parked and reported Sent -> tunnel resolves -> id 7 released
    //   -> id 7 recycled -> OPEN(id=7) sent DIRECTLY, accepted
    //   -> drain timer delivers the stale CLOSE(id=7) -> kills the NEW tunnel.
    // The per-tunnel callback bypasses send_frame_impl entirely, so consulting
    // the barrier only *after* a refusal does not prevent it.
    refuse_next_manager_send = true;
    ASSERT_TRUE(manager->send_frame(ProtocolFrame::make_tunnel_close(kTunnelId)));
    ASSERT_TRUE(on_wire.empty()) << "the CLOSE should be parked, not sent";

    // The recycled id's OPEN, issued while that CLOSE is still queued.
    EXPECT_EQ(send_direct(ProtocolFrame::make_tunnel_open(kTunnelId, "h", 80)),
              SendOutcome::SendqFull)
        << "an OPEN must wait behind a parked frame, not be sent past it";
    EXPECT_TRUE(on_wire.empty()) << "the OPEN must not have reached toxcore";

    // Once the queue drains, the OPEN goes out — after the CLOSE, which is the
    // order the peer needs.
    io_ctx.run();
    EXPECT_EQ(send_direct(ProtocolFrame::make_tunnel_open(kTunnelId, "h", 80)), SendOutcome::Sent);
    EXPECT_EQ(on_wire, (std::vector<FrameType>{FrameType::TUNNEL_CLOSE, FrameType::TUNNEL_OPEN}));
}

TEST_F(TunnelSendersTest, OpenAckAlsoWaitsBehindAParkedFrame) {
    refuse_next_manager_send = true;
    ASSERT_TRUE(manager->send_frame(ProtocolFrame::make_tunnel_close(kTunnelId)));

    EXPECT_EQ(send_direct(ProtocolFrame::make_tunnel_ack(kTunnelId, 0)), SendOutcome::SendqFull);
    EXPECT_TRUE(on_wire.empty());

    io_ctx.run();
    EXPECT_EQ(send_direct(ProtocolFrame::make_tunnel_ack(kTunnelId, 0)), SendOutcome::Sent);
    EXPECT_EQ(on_wire, (std::vector<FrameType>{FrameType::TUNNEL_CLOSE, FrameType::TUNNEL_ACK}));
}

TEST_F(TunnelSendersTest, DataIsNotHeldBehindAnUnrelatedParkedFrame) {
    // DATA deliberately skips the barrier: it can only flow on a Connected
    // tunnel, which required a barriered OPEN or OPEN_ACK, so it is already
    // ordered behind them. Stalling a live stream behind an unrelated parked
    // PING would be a pure regression.
    refuse_next_manager_send = true;
    ASSERT_TRUE(manager->send_frame(ProtocolFrame::make_ping()));

    const std::array<std::uint8_t, 2> payload{1, 2};
    EXPECT_EQ(send_direct(ProtocolFrame::make_tunnel_data(
                  kTunnelId, std::span<const std::uint8_t>(payload.data(), payload.size()))),
              SendOutcome::Sent);
    EXPECT_EQ(on_wire, (std::vector<FrameType>{FrameType::TUNNEL_DATA}));

    io_ctx.run();
}

// ===========================================================================
// 8. Flow-control ACK: PermanentFail drops the credit and does not re-arm
// ===========================================================================

TEST(FlowControlAckTest, PermanentFailDropsTheCreditWithoutRearmingTheRetry) {
    // SendqFull and PermanentFail are not interchangeable on the ACK path.
    // Restoring an unsendable credit leaves an accumulator that can never be
    // flushed: every later attempt re-reads it, fails again, restores again, and
    // every notify_tcp_writable() re-arms the retry timer for a peer that is
    // gone. (The matching terminal Abort belongs to a later slice; this slice
    // only guarantees the credit is dropped and nothing is re-armed.)
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_state(Tunnel::State::Connected);
    tunnel->set_ack_threshold(1);
    tunnel->set_on_data_for_tcp([](std::span<const std::uint8_t>) -> bool { return true; });

    unsigned ack_attempts = 0;
    tunnel->set_on_send_to_tox([&ack_attempts](std::span<const std::uint8_t> wire) -> SendOutcome {
        if (type_of(wire) == FrameType::TUNNEL_ACK) {
            ++ack_attempts;
            return SendOutcome::PermanentFail;
        }
        return SendOutcome::Sent;
    });

    const std::array<std::uint8_t, 4> payload{1, 2, 3, 4};
    tunnel->handle_frame(ProtocolFrame::make_tunnel_data(
        kTunnelId, std::span<const std::uint8_t>(payload.data(), payload.size())));

    EXPECT_EQ(ack_attempts, 1u);
    EXPECT_EQ(io_ctx.poll(), 0u) << "a permanently failed ACK must not arm a retry timer";

    // Nothing is left pending, so the socket's watermark is released rather than
    // kept armed forever.
    EXPECT_TRUE(tunnel->notify_tcp_writable());
    EXPECT_EQ(ack_attempts, 1u) << "the dropped credit must not be retried";
    EXPECT_EQ(io_ctx.poll(), 0u);
}

// ===========================================================================
// 9. The peer-close watch: data-then-close, and the takeover to the read loop
// ===========================================================================

namespace {

/// Bring up a real loopback pair and hand back both ends.
struct LoopbackPair {
    asio::ip::tcp::acceptor acceptor;
    asio::ip::tcp::socket target;
    std::shared_ptr<core::TcpConnection> conn;
};

}  // namespace

class PeerCloseHoldbackTest : public ::testing::Test {
   protected:
    template <typename Predicate>
    /// See pump_io_until(): one mechanism for every asynchronous wait here.
    void pump_until(Predicate done, std::chrono::milliseconds timeout = kRetryWaitBudget) {
        pump_io_until(io_ctx, done, timeout);
    }

    std::unique_ptr<LoopbackPair> Connect() {
        auto pair = std::unique_ptr<LoopbackPair>(new LoopbackPair{
            asio::ip::tcp::acceptor(
                io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)),
            asio::ip::tcp::socket(io_ctx), std::make_shared<core::TcpConnection>(io_ctx)});

        bool accepted = false;
        pair->acceptor.async_accept(pair->target,
                                    [&accepted](const std::error_code& ec) { accepted = !ec; });
        bool connected = false;
        pair->conn->async_connect(pair->acceptor.local_endpoint(),
                                  [&connected](const std::error_code& ec) { connected = !ec; });
        pump_until([&] { return accepted && connected; });
        EXPECT_TRUE(accepted);
        EXPECT_TRUE(connected);
        return pair;
    }

    asio::io_context io_ctx;
};

TEST_F(PeerCloseHoldbackTest, DataThenCloseDuringABackpressuredAckStillYieldsError) {
    // The case a bare "readable with zero bytes == FIN" probe misses entirely: a
    // target that writes a banner and *then* closes hides its FIN behind those
    // unread bytes, so the watch would stand down and the tunnel would sit in
    // Connecting for an ACK whose target is already dead.
    auto pair = Connect();

    std::vector<std::string> wire;
    auto gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx, []() -> tunnel::SendOutcome { return tunnel::SendOutcome::SendqFull; },
        [&wire]() {
            wire.emplace_back("START_READ");
            wire.emplace_back("DATA");
            return true;
        },
        [&wire]() { wire.emplace_back("ERROR"); },
        [&wire]() { wire.emplace_back("POST_COMMIT_CLOSE"); });

    pair->conn->set_on_disconnect([&wire, gate](const std::error_code&) {
        if (gate->target_gone()) {
            return;
        }
        wire.emplace_back("ORDINARY_CLOSE");
    });

    pair->conn->watch_peer_close();
    gate->start();
    ASSERT_TRUE(wire.empty());

    // Banner first, close second — no hook is invoked by hand.
    const std::string banner = "220 ready\r\n";
    std::error_code ignored;
    asio::write(pair->target, asio::buffer(banner), ignored);
    ASSERT_FALSE(ignored);
    pair->target.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    pair->target.close(ignored);

    pump_until([&] { return !wire.empty(); });

    const std::vector<std::string> observed = wire;
    EXPECT_EQ(observed, (std::vector<std::string>{"ERROR"}))
        << "a FIN behind unread data must still reach the gate's abandon path";
    EXPECT_FALSE(gate->committed());

    gate->target_gone();
    pair->conn->force_close();
    io_ctx.restart();
    io_ctx.run();
}

TEST_F(PeerCloseHoldbackTest, ReadAheadIsReplayedInOrderWhenTheReadLoopStarts) {
    // The watch reads ahead to see FIN, so those bytes must not be lost: they
    // belong to the stream and have to reach on_data_ before anything the read
    // loop pulls afterwards. The replay happens inside start_read()'s
    // strand-serialised takeover, which is also what stops it racing a watcher
    // that is still mid-callback.
    auto pair = Connect();

    std::string received;
    pair->conn->set_on_data([&received](const std::uint8_t* data, std::size_t length) {
        received.append(reinterpret_cast<const char*>(data), length);
    });

    pair->conn->watch_peer_close();

    std::error_code ignored;
    asio::write(pair->target, asio::buffer(std::string("first")), ignored);
    ASSERT_FALSE(ignored);

    // Let the watch bank those bytes. There is no predicate for "banked", so
    // this drives for a fixed SPAN OF TIME rather than a count of iterations —
    // a count means nothing on a contended runner. Several Windows timer ticks
    // is ample for a loopback read.
    {
        io_ctx.restart();
        io_ctx.run_for(kTimerGranularity * 4);
    }
    EXPECT_TRUE(received.empty()) << "nothing may be delivered before the read loop starts";

    pair->conn->start_read();
    asio::write(pair->target, asio::buffer(std::string("second")), ignored);
    ASSERT_FALSE(ignored);

    pump_until([&] { return received == "firstsecond"; });
    EXPECT_EQ(received, "firstsecond")
        << "read-ahead bytes must be replayed exactly once, ahead of live reads";

    pair->target.close(ignored);
    pair->conn->force_close();
    io_ctx.restart();
    io_ctx.run();
}

TEST_F(PeerCloseHoldbackTest, ForeignThreadStartReadDoesNotRaceAnArmedWatch) {
    // start_read() is called from the OPEN_ACK gate's commit, which can run on
    // any io_context worker — never necessarily the connection's strand. The
    // whole watch-to-read takeover therefore has to be dispatched onto the
    // strand; an atomic stand-down flag cannot stop a watcher already past its
    // own check. Exercised by running the io_context on one thread while a
    // foreign thread performs the takeover.
    for (int iteration = 0; iteration < 200; ++iteration) {
        auto pair = Connect();

        std::atomic<unsigned> eofs{0};
        // Disconnects are CLASSIFIED BY CAUSE rather than counted, because this
        // test closes the connection itself during teardown and a bare count
        // cannot tell that apart from the escalation under test. Counting is
        // what produced a CI false positive: the runner thread can still be
        // inside the on_read_eof_ handler when this thread runs `work.reset()`,
        // so the io_context's work count has not reached zero, it does not stop,
        // and the force_close handler posted next is executed rather than left
        // queued — incrementing the counter before it was read. Coverage
        // instrumentation fattens the handler epilogue and widens that window.
        //
        // The causes are distinguishable at the source: force_close() passes
        // asio::error::operation_aborted, while the watch's escalation passes
        // `ec ? ec : std::error_code{}` — an EMPTY code for the FIN case. So
        // anything that is not operation_aborted is an escalation, and unlike a
        // snapshot this stays valid for the whole life of the connection: an
        // escalation queued behind the EOF handler is still caught.
        std::atomic<unsigned> escalations{0};
        std::atomic<unsigned> teardown_closes{0};
        std::string received;
        std::mutex received_mutex;
        pair->conn->set_on_data([&](const std::uint8_t* data, std::size_t length) {
            std::lock_guard<std::mutex> lock(received_mutex);
            received.append(reinterpret_cast<const char*>(data), length);
        });
        pair->conn->set_on_read_eof([&eofs]() { eofs.fetch_add(1); });
        pair->conn->set_on_disconnect([&escalations, &teardown_closes](const std::error_code& ec) {
            if (ec == asio::error::operation_aborted) {
                teardown_closes.fetch_add(1);
            } else {
                escalations.fetch_add(1);
            }
        });

        pair->conn->watch_peer_close();
        std::error_code ignored;
        asio::write(pair->target, asio::buffer(std::string("payload")), ignored);

        auto work = asio::make_work_guard(io_ctx);
        std::thread runner([this]() { io_ctx.run(); });

        pair->conn->start_read();  // Foreign thread relative to the strand.
        pair->target.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);

        // WALL-CLOCK DEADLINE, not an iteration count. A count is a proxy for
        // time, and on a contended Windows runner the proxy expires before a
        // real cross-thread EOF arrives — this test failed exactly that way in a
        // --gtest_shuffle run. The deadline is generous and is only a safety
        // bound; the assertions below still fail loudly if it is reached.
        // The io_context is being run by `runner`, so this waits rather than
        // drives. Bounded by the same derived budget as every other wait here.
        const auto eof_deadline = std::chrono::steady_clock::now() + kRetryWaitBudget;
        while (eofs.load() == 0 && std::chrono::steady_clock::now() < eof_deadline) {
            std::this_thread::yield();
        }

        // A half-close must leave the connection Connected with only its read
        // half shut — our write side still usable — whereas an escalation drives
        // do_close() to Disconnected. Sampled here, before our own close makes
        // the state meaningless. This is a snapshot and only speaks for this
        // moment; the escalation classifier above is what covers all of time.
        const core::ConnectionState state_at_eof = pair->conn->state();

        // Close while the work guard is still held so the runner actually
        // executes it, then wait for it to land. Resetting the guard first can
        // leave this handler queued-but-unrun, and it would then fire during a
        // later iteration — against callbacks that capture this iteration's
        // now-dead locals by reference.
        pair->conn->force_close();
        const auto close_deadline = std::chrono::steady_clock::now() + kRetryWaitBudget;
        while (pair->conn->state() != core::ConnectionState::Disconnected &&
               std::chrono::steady_clock::now() < close_deadline) {
            std::this_thread::yield();
        }
        // RECORD, do not assert: `runner` is still joinable here, and a fatal
        // assertion would unwind through a joinable std::thread — that is
        // std::terminate, which would take the whole test binary down instead of
        // reporting a failure. Assert after the join below.
        const bool teardown_settled = pair->conn->state() == core::ConnectionState::Disconnected;

        work.reset();
        runner.join();
        io_ctx.restart();

        // Past the join the runner thread is gone, so every callback has run to
        // completion and the counters below are final rather than sampled.
        ASSERT_TRUE(teardown_settled) << "iteration " << iteration << ": teardown did not settle";
        ASSERT_EQ(eofs.load(), 1u) << "iteration " << iteration;
        ASSERT_EQ(escalations.load(), 0u)
            << "iteration " << iteration << ": the watch escalated a half-close into a hard close";
        ASSERT_EQ(teardown_closes.load(), 1u)
            << "iteration " << iteration << ": expected exactly one close, from the teardown";
        ASSERT_EQ(state_at_eof, core::ConnectionState::Connected)
            << "iteration " << iteration
            << ": a half-close must leave the write side usable, not close the connection";
        {
            std::lock_guard<std::mutex> lock(received_mutex);
            ASSERT_EQ(received, "payload") << "iteration " << iteration;
        }

        pair->target.close(ignored);
    }
}

// ===========================================================================
// 10. Teardown of an UNPUBLISHED server tunnel
// ===========================================================================
//
// The gate leaves a server tunnel in `None` until its OPEN_ACK is on the wire,
// and `Tunnel::close()` is a documented no-op in `None`. So every teardown that
// routes through close() — `remove_tunnel()` and `close_all()` included —
// silently does nothing for such a tunnel. These assert the *resource*
// outcomes, because both bugs are invisible if you only look at the state
// field: the target socket must actually be closed and the active gauge must
// not be leaked in either direction.

class UnpublishedTunnelTeardownTest : public ::testing::Test {
   protected:
    template <typename Predicate>
    /// See pump_io_until(): one mechanism for every asynchronous wait here.
    void pump_until(Predicate done, std::chrono::milliseconds timeout = kRetryWaitBudget) {
        pump_io_until(io_ctx, done, timeout);
    }

    /// Bring up a real loopback pair plus a manager holding the server tunnel,
    /// exactly as `wire_tcp_to_tunnel()` leaves things just before the gate is
    /// armed: tunnel registered, socket connected, nothing published.
    void SetUpUnpublishedTunnel() {
        acceptor = std::make_unique<asio::ip::tcp::acceptor>(
            io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));

        target = std::make_unique<asio::ip::tcp::socket>(io_ctx);
        bool accepted = false;
        acceptor->async_accept(*target, [&accepted](const std::error_code& ec) { accepted = !ec; });

        conn = std::make_shared<core::TcpConnection>(io_ctx);
        bool connected = false;
        conn->async_connect(acceptor->local_endpoint(),
                            [&connected](const std::error_code& ec) { connected = !ec; });
        pump_until([&] { return accepted && connected; });
        ASSERT_TRUE(accepted);
        ASSERT_TRUE(connected);

        manager = std::make_shared<TunnelManager>(io_ctx);
        manager->set_send_handler([this](const std::vector<std::uint8_t>& wire) -> SendOutcome {
            sent.push_back(type_of(wire));
            return SendOutcome::Sent;
        });

        tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        tunnel->set_tcp_connection(conn);
        ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));

        gauge = app::detail::make_active_gauge_latch();
        tunnel->set_on_state_change([this](Tunnel::State new_state) {
            if (new_state == Tunnel::State::Closed || new_state == Tunnel::State::Error) {
                app::detail::active_gauge_release(gauge);
            }
        });

        // The tunnel is unpublished: still None, and never counted.
        ASSERT_EQ(tunnel->state(), Tunnel::State::None);
        gauge_before =
            util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server);
    }

    /// True once the far end has observed our socket closing.
    [[nodiscard]] bool TargetSawClose() {
        std::array<std::uint8_t, 16> scratch{};
        std::error_code ec;
        target->non_blocking(true, ec);
        const std::size_t got = target->read_some(asio::buffer(scratch), ec);
        return got == 0 && ec && ec != asio::error::would_block && ec != asio::error::try_again;
    }

    asio::io_context io_ctx;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
    std::unique_ptr<asio::ip::tcp::socket> target;
    std::shared_ptr<core::TcpConnection> conn;
    std::shared_ptr<TunnelManager> manager;
    std::shared_ptr<TunnelImpl> tunnel;
    app::detail::ActiveGaugeLatch gauge;
    std::vector<FrameType> sent;
    std::uint64_t gauge_before{0};
};

TEST_F(UnpublishedTunnelTeardownTest, AbandonClosesTheTargetSocketAndDoesNotTouchTheGauge) {
    SetUpUnpublishedTunnel();

    app::detail::abandon_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);
    pump_until([&] { return !conn->is_connected(); });

    // The peer must be told, terminally.
    EXPECT_NE(std::find(sent.begin(), sent.end(), FrameType::TUNNEL_ERROR), sent.end())
        << "the client is waiting in Connecting; only a terminal frame resolves it";

    // The resource outcome, which is the part remove_tunnel() cannot deliver on
    // its own: close() no-ops in None, so nothing would have shut this socket.
    EXPECT_FALSE(conn->is_connected()) << "the target socket was left open";
    pump_until([this] { return TargetSawClose(); });
    EXPECT_TRUE(TargetSawClose()) << "the far end never saw the connection close";

    EXPECT_FALSE(manager->has_tunnel(kTunnelId));
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before)
        << "the gauge was never counted for this tunnel, so nothing may decrement it";
}

TEST_F(UnpublishedTunnelTeardownTest, CommitOnADetachedTunnelReleasesInsteadOfPublishing) {
    SetUpUnpublishedTunnel();

    // A concurrent close_all() detaches the tunnel while the ACK is in flight.
    // It now also tears it down: close() no-ops in None, so close_all() and
    // remove_tunnel() force-close an unpublished tunnel instead. That is what
    // gives the publication claim below something to lose against.
    manager->close_all();
    ASSERT_FALSE(manager->has_tunnel(kTunnelId));
    ASSERT_NE(tunnel->state(), Tunnel::State::None)
        << "precondition: detaching an unpublished tunnel must actually resolve it";

    const auto outcome =
        app::detail::commit_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);
    pump_until([&] { return !conn->is_connected(); });

    EXPECT_EQ(outcome, app::detail::OpenAckCommit::Detached);
    EXPECT_NE(tunnel->state(), Tunnel::State::Connected)
        << "a detached tunnel must never be published";
    EXPECT_FALSE(conn->is_connected()) << "the target socket was left open";
    pump_until([this] { return TargetSawClose(); });
    EXPECT_TRUE(TargetSawClose());
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before)
        << "the active gauge leaked for a tunnel that was never routable";
}

TEST_F(UnpublishedTunnelTeardownTest, CommitOnAnOwnedTunnelStillPublishesAndBalancesTheGauge) {
    // The mirror image, so the ownership check cannot be "satisfied" by never
    // publishing anything.
    SetUpUnpublishedTunnel();

    const auto outcome =
        app::detail::commit_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);
    EXPECT_EQ(outcome, app::detail::OpenAckCommit::Published);
    EXPECT_EQ(tunnel->state(), Tunnel::State::Connected);
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before + 1);

    // And the count is given back exactly once at the terminal transition.
    tunnel->force_close();
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before);
    app::detail::active_gauge_release(gauge);
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before)
        << "release must be idempotent";

    std::error_code ignored;
    target->close(ignored);
    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 11. Holdback overflow, and concurrent open() target integrity
// ===========================================================================

TEST_F(PeerCloseHoldbackTest, HoldbackOverflowFailsTheHandshakeRatherThanGivingUpDetection) {
    // Standing the watch down at the cap would silently abandon close
    // detection: any later FIN stays hidden behind the unread bytes, and with
    // the OPEN_ACK still backpressured the peer waits in Connecting for a
    // tunnel whose target may already be gone. Overflow therefore terminates
    // the unpublished handshake, so the peer gets a definite TUNNEL_ERROR.
    auto pair = Connect();

    std::vector<std::string> wire;
    auto gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx, []() -> tunnel::SendOutcome { return tunnel::SendOutcome::SendqFull; },
        [&wire]() {
            wire.emplace_back("START_READ");
            wire.emplace_back("DATA");
            return true;
        },
        [&wire]() { wire.emplace_back("ERROR"); },
        [&wire]() { wire.emplace_back("POST_COMMIT_CLOSE"); });

    pair->conn->set_on_disconnect([&wire, gate](const std::error_code&) {
        if (gate->target_gone()) {
            return;
        }
        wire.emplace_back("ORDINARY_CLOSE");
    });

    pair->conn->watch_peer_close();
    gate->start();
    ASSERT_TRUE(wire.empty());

    // Push well past the 64 KiB cap, then go quiet WITHOUT closing — the case
    // where a stood-down watch would wait forever.
    const std::vector<std::uint8_t> chunk(32u * 1024u, 0xAB);
    std::error_code ec;
    pair->target.non_blocking(false, ec);
    for (int i = 0; i < 8; ++i) {
        asio::write(pair->target, asio::buffer(chunk), ec);
        if (ec) {
            break;
        }
        // Opportunistic drain between writes; the authoritative wait is the
        // pump_io_until() below. Time-bounded rather than iteration-bounded so
        // it cannot silently do nothing on a contended runner.
        pump_io_until(io_ctx, [&]() { return !wire.empty(); }, kTimerGranularity * 4);
        if (!wire.empty()) {
            break;
        }
    }

    pump_until([&] { return !wire.empty(); });

    const std::vector<std::string> observed = wire;
    EXPECT_EQ(observed, (std::vector<std::string>{"ERROR"}))
        << "overflowing the read-ahead cap must resolve the handshake, not go quiet";
    EXPECT_FALSE(gate->committed());

    gate->target_gone();
    pair->target.close(ec);
    pair->conn->force_close();
    io_ctx.restart();
    io_ctx.run();
}

TEST_F(OpenTerminalOwnershipTest, ConcurrentOpensNeverCorruptTheWinnersTarget) {
    // Two callers can both pass open()'s fast-path None check. If both write the
    // target and the CAS loser then clears it, the winner serializes a
    // TUNNEL_OPEN for an empty or foreign host. TunnelImpl documents its public
    // methods as safe from any thread, so this is in contract.
    for (int i = 0; i < kRaceIterations; ++i) {
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        TunnelImpl* raw = tunnel.get();

        std::mutex observed_mutex;
        std::vector<std::string> observed_hosts;
        tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> wire) -> SendOutcome {
            if (type_of(wire) == FrameType::TUNNEL_OPEN) {
                auto frame = ProtocolFrame::deserialize(wire);
                if (frame) {
                    if (auto payload = frame.value().as_tunnel_open()) {
                        std::lock_guard<std::mutex> lock(observed_mutex);
                        observed_hosts.push_back(payload->host);
                    }
                }
            }
            return SendOutcome::Sent;
        });

        std::atomic<bool> ready{false};
        std::atomic<bool> go{false};
        std::thread other([&]() {
            ready.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            (void)raw->open("second.example", 2222);
        });

        while (!ready.load(std::memory_order_acquire)) {
        }
        go.store(true, std::memory_order_release);
        (void)tunnel->open("first.example", 1111);
        other.join();

        // Exactly one open may win, and the frame it put on the wire must carry
        // that same caller's host — never the other's, and never empty.
        std::lock_guard<std::mutex> lock(observed_mutex);
        ASSERT_LE(observed_hosts.size(), 1u) << "iteration " << i << ": two opens both sent";
        if (!observed_hosts.empty()) {
            ASSERT_TRUE(observed_hosts[0] == "first.example" ||
                        observed_hosts[0] == "second.example")
                << "iteration " << i << ": TUNNEL_OPEN carried '" << observed_hosts[0] << "'";
            ASSERT_EQ(tunnel->target_host(), observed_hosts[0])
                << "iteration " << i << ": the recorded target does not match the frame sent";
        }
    }
}

// ===========================================================================
// 12. Publication vs teardown, once two threads are involved
// ===========================================================================

TEST_F(UnpublishedTunnelTeardownTest, CommitDoesNotPublishATunnelResolvedAfterTheOwnershipCheck) {
    SetUpUnpublishedTunnel();

    // The tunnel is STILL REGISTERED — so commit's ownership pre-filter passes —
    // but has already been resolved. That is exactly what a teardown landing
    // between `get_tunnel()` and publication looks like from commit's point of
    // view: `get_tunnel()` releases the manager's lock before its answer can be
    // acted on, so the pre-filter alone is check-then-act. The claim has to be
    // the compare-exchange on the tunnel's own state.
    tunnel->force_close();
    ASSERT_TRUE(manager->has_tunnel(kTunnelId)) << "precondition: still registered";
    ASSERT_NE(tunnel->state(), Tunnel::State::None) << "precondition: already resolved";

    const auto outcome =
        app::detail::commit_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);

    EXPECT_EQ(outcome, app::detail::OpenAckCommit::Detached);
    EXPECT_NE(tunnel->state(), Tunnel::State::Connected)
        << "a resolved tunnel must never be resurrected into Connected";
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before)
        << "publishing a resolved tunnel would leak the active gauge";
}

TEST_F(UnpublishedTunnelTeardownTest, AbandonDoesNotRemoveATunnelThatRecycledTheId) {
    SetUpUnpublishedTunnel();

    // By the time this deferred cleanup runs, our tunnel is long gone and a
    // different tunnel object has inherited the id. Removing by id alone would
    // tear down that replacement — the recycled-id failure this whole slice
    // exists to eliminate, reintroduced by the cleanup itself.
    manager->remove_tunnel(kTunnelId);
    auto replacement = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    ASSERT_TRUE(manager->add_tunnel(kTunnelId, replacement));

    app::detail::abandon_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);

    ASSERT_TRUE(manager->has_tunnel(kTunnelId)) << "the replacement was torn down";
    EXPECT_EQ(manager->get_tunnel(kTunnelId).get(), static_cast<Tunnel*>(replacement.get()));
    EXPECT_EQ(replacement->state(), Tunnel::State::None)
        << "the replacement must be untouched, not force-closed";

    io_ctx.restart();
    io_ctx.run();
}

TEST(ActiveGaugeTest, ReleaseRacingTheCountLeavesTheGaugeBalanced) {
    // The latch has to serialize the metric SIDE EFFECT, not just the state
    // word. With the state published before the increment, a release poised on
    // that exact transition decrements first — saturating at zero, so doing
    // nothing — and the delayed increment then strands the gauge at +1.
    //
    // The releasing thread spins on the published state rather than racing
    // blind, so it is poised precisely at the transition under test.
    for (int i = 0; i < 500; ++i) {
        auto latch = app::detail::make_active_gauge_latch();
        const auto before =
            util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server);

        std::thread releaser([&latch]() {
            while (app::detail::active_gauge_state(latch) !=
                   app::detail::ActiveGaugeState::Counted) {
            }
            app::detail::active_gauge_release(latch);
        });

        app::detail::active_gauge_count(latch);
        releaser.join();
        app::detail::active_gauge_release(latch);  // Idempotent.

        ASSERT_EQ(
            util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
            before)
            << "iteration " << i << ": the gauge did not come back to baseline";
    }
}

TEST_F(OpenTerminalOwnershipTest, ConcurrentOpensKeepTheCloseObligationConsistent) {
    // A losing open() that resets the handshake phase can overwrite the
    // winner's Sending/Sent and only then lose the state claim. After that,
    // cancel_open_retry() reads Pending and suppresses a TUNNEL_CLOSE the peer
    // actually needed, because the winner's TUNNEL_OPEN had in fact gone out.
    //
    // The window is between the loser's fast-path state check and its reset,
    // with no callback in between, so this is raced from a tight rendezvous
    // rather than injected. The assertion is an invariant.
    for (int i = 0; i < kRaceIterations; ++i) {
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        TunnelImpl* raw = tunnel.get();

        std::atomic<int> opens_sent{0};
        std::atomic<int> closes_sent{0};
        tunnel->set_on_send_to_tox(
            [&opens_sent, &closes_sent](std::span<const std::uint8_t> wire) -> SendOutcome {
                if (type_of(wire) == FrameType::TUNNEL_OPEN) {
                    opens_sent.fetch_add(1);
                } else if (type_of(wire) == FrameType::TUNNEL_CLOSE) {
                    closes_sent.fetch_add(1);
                }
                return SendOutcome::Sent;
            });

        std::atomic<bool> ready{false};
        std::atomic<bool> go{false};
        std::thread other([&]() {
            ready.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            (void)raw->open("second.example", 2222);
        });

        while (!ready.load(std::memory_order_acquire)) {
        }
        go.store(true, std::memory_order_release);
        (void)tunnel->open("first.example", 1111);
        other.join();

        tunnel->close();

        ASSERT_LE(opens_sent.load(), 1) << "iteration " << i << ": two opens both sent";
        if (opens_sent.load() == 1) {
            ASSERT_EQ(closes_sent.load(), 1)
                << "iteration " << i
                << ": the peer was told about this tunnel but never told to let go";
        } else {
            ASSERT_EQ(closes_sent.load(), 0)
                << "iteration " << i << ": TUNNEL_CLOSE for a tunnel the peer never heard of";
        }
    }
}

// ===========================================================================
// 13. Wire obligations: what the peer is owed once it has been told something
// ===========================================================================
//
// These assert what reaches the peer, not what the local state field says. A
// tunnel torn down with the right state and the wrong (or missing) frame leaves
// the peer holding half a tunnel until its own reaper fires — invisible to any
// state assertion.

class WireObligationTest : public ::testing::Test {
   protected:
    std::shared_ptr<TunnelImpl> MakeTunnel() {
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        tunnel->set_on_send_to_tox([this](std::span<const std::uint8_t> wire) -> SendOutcome {
            // Guarded: the racing test below sends from two threads at once, and
            // an unsynchronised vector silently drops one of them — which looks
            // exactly like the bug under test.
            std::lock_guard<std::mutex> lock(sent_mutex);
            sent.push_back(type_of(wire));
            return SendOutcome::Sent;
        });
        return tunnel;
    }

    [[nodiscard]] std::size_t count(FrameType type) {
        std::lock_guard<std::mutex> lock(sent_mutex);
        return static_cast<std::size_t>(std::count(sent.begin(), sent.end(), type));
    }

    void clear_sent() {
        std::lock_guard<std::mutex> lock(sent_mutex);
        sent.clear();
    }

    [[nodiscard]] bool sent_empty() {
        std::lock_guard<std::mutex> lock(sent_mutex);
        return sent.empty();
    }

    /// The peer's view, in order. Ordering properties must be asserted against
    /// this, not against per-type counts.
    [[nodiscard]] std::vector<FrameType> snapshot() {
        std::lock_guard<std::mutex> lock(sent_mutex);
        return sent;
    }

    asio::io_context io_ctx;
    std::mutex sent_mutex;
    std::vector<FrameType> sent;
};

TEST_F(WireObligationTest, ForceClosingAPublishedTunnelTellsThePeer) {
    // The ordering finding 1 is about: a removal snapshots the tunnel as
    // unpublished, a racing commit publishes it (so the peer now has the
    // OPEN_ACK), and the removal's force_close then runs. Silence there strands
    // a peer that believes it holds a working tunnel.
    auto tunnel = MakeTunnel();
    tunnel->set_state(Tunnel::State::Connected);  // The peer has the OPEN_ACK.

    tunnel->force_close();

    EXPECT_EQ(count(FrameType::TUNNEL_CLOSE), 1u)
        << "a peer holding our OPEN_ACK must be told the tunnel is over";
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed);
}

TEST_F(WireObligationTest, ForceClosingAnUnpublishedTunnelSaysNothing) {
    // The mirror image, so the obligation above cannot be "satisfied" by always
    // shouting: a tunnel the peer has never heard of must NOT draw a frame
    // naming an id that, after recycling, belongs to somebody else.
    auto tunnel = MakeTunnel();
    ASSERT_EQ(tunnel->state(), Tunnel::State::None);

    tunnel->force_close();

    EXPECT_TRUE(sent_empty()) << "the peer never heard of this tunnel";
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed);
}

TEST_F(WireObligationTest, RemovingAPublishedTunnelTellsThePeerEvenViaTheAbruptPath) {
    // Same obligation, exercised through the manager's teardown rather than a
    // bare force_close, since that is the path a detach actually takes.
    auto manager = std::make_shared<TunnelManager>(io_ctx);
    auto tunnel = MakeTunnel();
    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    tunnel->set_state(Tunnel::State::Connected);

    manager->remove_tunnel(kTunnelId);
    io_ctx.restart();
    io_ctx.run();

    EXPECT_EQ(count(FrameType::TUNNEL_CLOSE), 1u);
}

TEST_F(WireObligationTest, ForceCloseRacingOpenNeverLeavesAnOpenUnmatched) {
    // Finding 2 as a wire obligation: force_close() cancels the open phase and
    // claims the terminal state, and open() claims None -> Connecting and resets
    // that phase. Interleaved wrongly, the OPEN goes out and no CLOSE follows —
    // the peer holds a tunnel we have already destroyed.
    for (int i = 0; i < kRaceIterations; ++i) {
        io_ctx.restart();
        clear_sent();
        auto tunnel = MakeTunnel();
        TunnelImpl* raw = tunnel.get();

        std::atomic<bool> ready{false};
        std::atomic<bool> go{false};
        std::thread closer([&]() {
            ready.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            raw->force_close();
        });

        while (!ready.load(std::memory_order_acquire)) {
        }
        go.store(true, std::memory_order_release);
        (void)tunnel->open("example.com", 443);
        closer.join();

        // ORDER, not counts. The property is "the peer never sees a CLOSE
        // before the OPEN it retracts", and a count-only assertion is blind to
        // exactly that inversion: the CLOSE is present, so the count passes,
        // while the peer discards it as naming an unknown tunnel and is then
        // left holding the OPEN that arrives afterwards.
        const std::vector<FrameType> wire = snapshot();
        const auto open_at = std::find(wire.begin(), wire.end(), FrameType::TUNNEL_OPEN);
        const auto close_at = std::find(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE);

        ASSERT_LE(std::count(wire.begin(), wire.end(), FrameType::TUNNEL_OPEN), 1)
            << "iteration " << i;
        ASSERT_LE(std::count(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE), 1)
            << "iteration " << i << ": duplicate TUNNEL_CLOSE";

        if (open_at != wire.end()) {
            ASSERT_NE(close_at, wire.end())
                << "iteration " << i
                << ": TUNNEL_OPEN reached the peer with no TUNNEL_CLOSE behind it";
            ASSERT_LT(open_at, close_at)
                << "iteration " << i << ": TUNNEL_CLOSE preceded the TUNNEL_OPEN it retracts";
        } else {
            ASSERT_EQ(close_at, wire.end())
                << "iteration " << i << ": TUNNEL_CLOSE for a tunnel the peer never heard of";
        }
    }
}

TEST_F(UnpublishedTunnelTeardownTest, FailedCommitTellsThePeerThatAlreadyHasTheAck) {
    // A commit that cannot publish is NOT the same as a pre-ACK abandonment:
    // the OPEN_ACK has already reached the peer, so it believes it holds a
    // working tunnel. Going quiet there strands it.
    SetUpUnpublishedTunnel();
    manager->close_all();
    ASSERT_FALSE(manager->has_tunnel(kTunnelId));

    const auto outcome =
        app::detail::commit_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);
    ASSERT_EQ(outcome, app::detail::OpenAckCommit::Detached);

    EXPECT_NE(std::find(sent.begin(), sent.end(), FrameType::TUNNEL_ERROR), sent.end())
        << "the peer has our OPEN_ACK and was told nothing";

    io_ctx.restart();
    io_ctx.run();
}

TEST_F(UnpublishedTunnelTeardownTest, PostAckAbortDoesNotRemoveARecycledId) {
    // The post-ACK abort must be as identity-safe as the pre-ACK one.
    SetUpUnpublishedTunnel();
    manager->remove_tunnel(kTunnelId);
    auto replacement = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    ASSERT_TRUE(manager->add_tunnel(kTunnelId, replacement));

    app::detail::abort_open_ack_after_send(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);

    ASSERT_TRUE(manager->has_tunnel(kTunnelId)) << "the replacement was torn down";
    EXPECT_EQ(manager->get_tunnel(kTunnelId).get(), static_cast<Tunnel*>(replacement.get()));

    io_ctx.restart();
    io_ctx.run();
}

TEST(GenerationSafeTeardownTest, IdOnlyRemovalIsRefusedWhenTheCallerNamesATunnel) {
    // remove_tunnel_if / close_tunnel_if with a null expectation must be inert
    // rather than falling back to "whatever is registered". The deferred server
    // and client cleanups reach that case whenever their weak_ptr has lapsed —
    // and a lapsed tunnel cannot still be registered, so anything under that id
    // belongs to somebody else.
    asio::io_context io_ctx;
    auto manager = std::make_shared<TunnelManager>(io_ctx);
    auto occupant = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    ASSERT_TRUE(manager->add_tunnel(kTunnelId, occupant));

    // BOTH primitives, because they had DIFFERENT nullptr semantics: the
    // earlier version of this test only exercised close_tunnel_if, so
    // remove_tunnel_if kept a wildcard nullptr that deleted whatever was
    // registered — and that is the case the deferred cleanups actually reach.
    EXPECT_FALSE(manager->close_tunnel_if(kTunnelId, nullptr));
    EXPECT_TRUE(manager->has_tunnel(kTunnelId));

    EXPECT_FALSE(manager->remove_tunnel_if(kTunnelId, nullptr))
        << "a null expectation must remove nothing";
    ASSERT_TRUE(manager->has_tunnel(kTunnelId))
        << "remove_tunnel_if(nullptr) deleted the registered occupant";
    EXPECT_EQ(manager->get_tunnel(kTunnelId).get(), static_cast<Tunnel*>(occupant.get()));

    // And naming a different object is refused too.
    auto stranger = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    EXPECT_FALSE(manager->remove_tunnel_if(kTunnelId, stranger.get()));
    EXPECT_TRUE(manager->has_tunnel(kTunnelId));

    EXPECT_TRUE(manager->remove_tunnel_if(kTunnelId, occupant.get()));
    EXPECT_FALSE(manager->has_tunnel(kTunnelId));

    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 14. Terminal states are final, and ids are not recycled mid-teardown
// ===========================================================================

TEST_F(WireObligationTest, AGracefulCloseRacingForceCloseEmitsExactlyOneClose) {
    // Both paths emit a TUNNEL_CLOSE and both then write the state. Without a
    // single-shot latch the peer receives two CLOSEs for one tunnel — and the
    // second names an id that, after recycling, is somebody else's. Without a
    // terminal-state guard the graceful close also overwrites Closed with
    // Disconnecting, resurrecting a tunnel whose socket is already gone.
    // Injected at the exact point the race exists: the graceful close has
    // already decided to announce and is INSIDE its send callback when
    // force_close() arrives. Calling the two sequentially cannot reach this —
    // the second one just sees a terminal state and returns, which is why the
    // first version of this test passed against the broken code.
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();
    bool injected = false;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> wire) -> SendOutcome {
        {
            std::lock_guard<std::mutex> lock(sent_mutex);
            sent.push_back(type_of(wire));
        }
        if (type_of(wire) == FrameType::TUNNEL_CLOSE && !injected) {
            injected = true;
            raw->force_close();
        }
        return SendOutcome::Sent;
    });
    tunnel->set_state(Tunnel::State::Connected);

    tunnel->close();

    ASSERT_TRUE(injected) << "precondition: the graceful close reached its send callback";
    EXPECT_EQ(count(FrameType::TUNNEL_CLOSE), 1u) << "the peer received a duplicate TUNNEL_CLOSE";
    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "a graceful close must not resurrect a terminal tunnel into Disconnecting";
}

// GUARD, not a reproduction: the ACK handler's own `if (current == Connecting)`
// filter means a sequential call cannot reach the blind publish, and there is no
// injection point between its state load and its transition. The terminal-state
// claim in transition_state() is proven by
// AGracefulCloseRacingForceCloseEmitsExactlyOneClose above; this pins the
// invariant on the ACK path so a future edit cannot quietly reopen it.
TEST_F(WireObligationTest, ALateAckCannotResurrectATerminalTunnel) {
    // handle_tunnel_ack_frame loads Connecting and then blindly published
    // Connected. An ACK that crosses a force_close() on the wire would revive a
    // tunnel whose socket is gone and whose close has already been booked.
    auto tunnel = MakeTunnel();
    ASSERT_TRUE(tunnel->open("example.com", 443));
    ASSERT_EQ(tunnel->state(), Tunnel::State::Connecting);

    tunnel->force_close();
    ASSERT_EQ(tunnel->state(), Tunnel::State::Closed);

    tunnel->handle_frame(ProtocolFrame::make_tunnel_ack(kTunnelId, 0));

    EXPECT_EQ(tunnel->state(), Tunnel::State::Closed)
        << "a late TUNNEL_ACK republished Connected over a terminal state";
}

TEST(GenerationSafeTeardownTest, AnIdIsNotReusableUntilItsCloseHasBeenEmitted) {
    // The teardown that emits a tunnel's TUNNEL_CLOSE runs unlocked. If the id
    // were released when the map entry is erased, a replacement could claim it
    // first and that CLOSE would name the replacement instead. So the id stays
    // reserved until the teardown resolves — asserted here from inside the
    // emitting callback, which is the only moment the window is observable.
    asio::io_context io_ctx;
    auto manager = std::make_shared<TunnelManager>(io_ctx);
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);

    manager->set_send_handler([](const std::vector<std::uint8_t>&) { return SendOutcome::Sent; });

    std::optional<bool> peer_reopen_accepted;
    bool close_seen = false;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> wire) -> SendOutcome {
        if (type_of(wire) == FrameType::TUNNEL_CLOSE) {
            close_seen = true;
            // We are mid-teardown, with this tunnel's CLOSE on its way out.
            // Ask the real production gate whether the id it names could be
            // handed to a replacement right now. (Asking the allocator instead
            // proves nothing: it returns the lowest free id, which is not this
            // one either way — that is why the first version of this test
            // passed against the broken code.)
            peer_reopen_accepted =
                manager->handle_incoming_open(ProtocolFrame::make_tunnel_open(kTunnelId, "h", 80));
        }
        return SendOutcome::Sent;
    });

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    tunnel->set_state(Tunnel::State::Connected);

    manager->remove_tunnel_if(kTunnelId, tunnel.get());

    ASSERT_TRUE(close_seen) << "precondition: the teardown emitted a TUNNEL_CLOSE";
    ASSERT_TRUE(peer_reopen_accepted.has_value());
    EXPECT_FALSE(*peer_reopen_accepted)
        << "the id was handed to a replacement while its previous owner's TUNNEL_CLOSE was "
           "still in flight — that CLOSE would land on the replacement";

    // Once the teardown has resolved the id is free again.
    EXPECT_FALSE(manager->has_tunnel(kTunnelId));
    auto replacement = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    EXPECT_TRUE(manager->add_tunnel(kTunnelId, replacement));

    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 15. The id reservation must outlive the CLOSE obligation, not close()
// ===========================================================================
//
// `Tunnel::close()` can RETURN with its TUNNEL_CLOSE still owed. Releasing the
// id at that point lets a replacement take it before the old CLOSE goes out,
// and the CLOSE then names the replacement. Two ways to owe one:
//
//   * a graceful close deferred behind a backpressured coalesce buffer, and
//   * a handshake close handed to a send that is still inside the transport
//     (CloseObligation::DeferredToSender).
//
// The earlier version of this test always returned `Sent` synchronously, so it
// exercised neither and passed against the broken code.

class IdReservationTest : public ::testing::Test {
   protected:
    /// Ask the real production gate whether the id could be handed to a
    /// replacement right now. nullopt when it was never asked.
    [[nodiscard]] bool peer_could_reopen() {
        return manager->handle_incoming_open(ProtocolFrame::make_tunnel_open(kTunnelId, "h", 80));
    }

    void SetUp() override {
        manager = std::make_shared<TunnelManager>(io_ctx);
        manager->set_send_handler(
            [](const std::vector<std::uint8_t>&) { return SendOutcome::Sent; });
    }

    asio::io_context io_ctx;
    std::shared_ptr<TunnelManager> manager;
};

TEST_F(IdReservationTest, ABackpressuredCloseKeepsTheIdReservedUntilItIsEmitted) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);

    // Backpressure everything so the graceful close cannot drain, and record
    // what actually reaches the transport.
    std::atomic<bool> transport_blocked{true};
    std::mutex wire_mutex;
    std::vector<FrameType> wire;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
        if (transport_blocked.load()) {
            return SendOutcome::SendqFull;
        }
        std::lock_guard<std::mutex> lock(wire_mutex);
        wire.push_back(type_of(frame));
        return SendOutcome::Sent;
    });
    tunnel->configure_coalesce(/*max_delay_us=*/0, /*max_bytes=*/1362);

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    tunnel->set_state(Tunnel::State::Connected);

    // Buffer some bytes so the close has something it cannot drain.
    const std::vector<std::uint8_t> payload(64, 0xAB);
    ASSERT_TRUE(tunnel->send_data_to_tox(payload));

    manager->remove_tunnel_if(kTunnelId, tunnel.get());

    // close() has returned, but its CLOSE is still owed behind the buffer.
    {
        std::lock_guard<std::mutex> lock(wire_mutex);
        ASSERT_EQ(std::count(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE), 0)
            << "precondition: the CLOSE has not been emitted yet";
    }
    EXPECT_FALSE(peer_could_reopen())
        << "the id was released while a deferred TUNNEL_CLOSE still named it";

    // Let the transport drain; the retry timer emits the owed CLOSE.
    //
    // This wait is on a sendq_retry timer, so it is bounded by kRetryWaitBudget
    // — derived from that cadence and sized for Windows timer granularity. It
    // was an iteration count, which expired in about a millisecond and so could
    // never outlast even the 2 ms base delay.
    transport_blocked.store(false);
    pump_io_until(io_ctx, [&]() {
        std::lock_guard<std::mutex> lock(wire_mutex);
        return std::count(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE) > 0;
    });
    {
        std::lock_guard<std::mutex> lock(wire_mutex);
        ASSERT_EQ(std::count(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE), 1)
            << "the deferred CLOSE never reached the transport";
    }

    // Only now may the id be reused.
    EXPECT_TRUE(peer_could_reopen()) << "the id was never released after its CLOSE went out";

    io_ctx.restart();
    io_ctx.run();
}

TEST_F(IdReservationTest, ADeferredHandshakeCloseKeepsTheIdReservedUntilTheSenderEmitsIt) {
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();

    std::mutex wire_mutex;
    std::vector<FrameType> wire;
    std::optional<bool> reopen_while_open_in_flight;
    bool still_registered_in_flight = true;

    // The close arrives while the OPEN is INSIDE the transport — the
    // DeferredToSender case. From in here, close() cannot emit (that would put
    // the CLOSE ahead of the OPEN), so the obligation is still outstanding.
    //
    // The removal must happen HERE too, not after open() returns: otherwise the
    // tunnel is still registered when the id is probed, and handle_incoming_open
    // rejects on the map entry rather than on the reservation — a proxy that
    // passes against the broken code.
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
        if (type_of(frame) == FrameType::TUNNEL_OPEN && !reopen_while_open_in_flight.has_value()) {
            raw->close();
            manager->remove_tunnel_if(kTunnelId, raw);
            still_registered_in_flight = manager->has_tunnel(kTunnelId);
            reopen_while_open_in_flight = peer_could_reopen();
        }
        std::lock_guard<std::mutex> lock(wire_mutex);
        wire.push_back(type_of(frame));
        return SendOutcome::Sent;
    });

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    (void)tunnel->open("example.com", 443);

    ASSERT_TRUE(reopen_while_open_in_flight.has_value())
        << "precondition: the close landed while the OPEN was in flight";
    ASSERT_FALSE(still_registered_in_flight)
        << "precondition: only the reservation can be keeping the id at that point";
    EXPECT_FALSE(*reopen_while_open_in_flight)
        << "the id was released while a TUNNEL_CLOSE was still owed to the sender";

    // The sender emits the owed CLOSE after its OPEN, in that order.
    std::vector<FrameType> observed;
    {
        std::lock_guard<std::mutex> lock(wire_mutex);
        observed = wire;
    }
    ASSERT_EQ(observed, (std::vector<FrameType>{FrameType::TUNNEL_OPEN, FrameType::TUNNEL_CLOSE}));

    // The sender discharged the obligation, so the id comes back.
    EXPECT_TRUE(peer_could_reopen()) << "the id was never released after its CLOSE went out";

    io_ctx.restart();
    io_ctx.run();
}

TEST_F(IdReservationTest, AnAbandonedHandshakeCloseStillReleasesTheId) {
    // The mirror image, so the reservation cannot be "satisfied" by never
    // releasing: when the OPEN turns out NOT to have reached the peer, no CLOSE
    // is owed and the id must come back promptly.
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();

    bool closed_from_send = false;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
        if (type_of(frame) == FrameType::TUNNEL_OPEN && !closed_from_send) {
            closed_from_send = true;
            raw->close();
        }
        return SendOutcome::PermanentFail;  // The OPEN never reaches the peer.
    });

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    (void)tunnel->open("example.com", 443);
    ASSERT_TRUE(closed_from_send);

    manager->remove_tunnel_if(kTunnelId, tunnel.get());
    EXPECT_TRUE(peer_could_reopen()) << "no CLOSE was owed, so the id must not stay reserved";

    io_ctx.restart();
    io_ctx.run();
}

TEST(ForceCloseResourceTest, ForceCloseOnAnErroredTunnelKeepsErrorAndStillClosesTheSocket) {
    // force_close() blindly exchanged Error -> Closed, overwriting a resolution
    // another path had already published and booked. It must respect
    // terminality — but the resource cleanup must NOT be skipped just because
    // the state is terminal: send_error() never closes the socket.
    //
    // The previous version of this test asserted only the state and the frame
    // count, which says nothing about resources. It now uses a real loopback
    // socket and asserts the far end actually observes the close.
    asio::io_context io_ctx;
    asio::ip::tcp::acceptor acceptor(
        io_ctx, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));

    asio::ip::tcp::socket target(io_ctx);
    bool accepted = false;
    acceptor.async_accept(target, [&accepted](const std::error_code& ec) { accepted = !ec; });

    auto conn = std::make_shared<core::TcpConnection>(io_ctx);
    bool connected = false;
    conn->async_connect(acceptor.local_endpoint(),
                        [&connected](const std::error_code& ec) { connected = !ec; });
    pump_io_until(io_ctx, [&]() { return accepted && connected; });
    ASSERT_TRUE(accepted);
    ASSERT_TRUE(connected);

    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    std::vector<FrameType> sent;
    tunnel->set_on_send_to_tox([&sent](std::span<const std::uint8_t> wire) -> SendOutcome {
        sent.push_back(type_of(wire));
        return SendOutcome::Sent;
    });
    tunnel->set_tcp_connection(conn);
    tunnel->set_state(Tunnel::State::Connected);

    tunnel->send_error(3, "boom");
    ASSERT_EQ(tunnel->state(), Tunnel::State::Error);
    ASSERT_TRUE(conn->is_connected())
        << "precondition: send_error() leaves the socket open, which is the point";

    const std::size_t frames_before = sent.size();
    tunnel->force_close();

    EXPECT_EQ(tunnel->state(), Tunnel::State::Error)
        << "force_close overwrote a terminal Error with Closed";
    EXPECT_EQ(sent.size(), frames_before)
        << "force_close announced over a tunnel another path had already resolved";

    // THE RESOURCE ASSERTION: the socket is really gone, observed from both
    // ends rather than inferred from the state field.
    pump_io_until(io_ctx, [&]() { return !conn->is_connected(); });
    EXPECT_FALSE(conn->is_connected()) << "force_close skipped the cleanup and leaked the socket";

    std::array<std::uint8_t, 8> scratch{};
    std::error_code ec;
    target.non_blocking(true, ec);
    bool far_end_saw_close = false;
    pump_io_until(io_ctx, [&]() {
        std::error_code read_ec;
        const std::size_t got = target.read_some(asio::buffer(scratch), read_ec);
        far_end_saw_close = got == 0 && read_ec && read_ec != asio::error::would_block &&
                            read_ec != asio::error::try_again;
        return far_end_saw_close;
    });
    EXPECT_TRUE(far_end_saw_close) << "the far end never saw the connection close";

    target.close(ec);
    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 16. Handoff, not intent; and the gauge across a graceful removal
// ===========================================================================

TEST_F(IdReservationTest, TheIdIsNotReleasedWhileTheCloseIsStillInsideTheTransport) {
    // "We are about to hand the CLOSE over" and "the transport has taken it" are
    // different moments, and only the second one makes the id reusable. Probing
    // from INSIDE the transport callback is the only place the difference is
    // observable — a latch published before the call looks identical to one
    // published after it from everywhere else.
    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    TunnelImpl* raw = tunnel.get();

    std::optional<bool> reopen_while_close_in_flight;
    bool still_registered_in_flight = true;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
        if (type_of(frame) == FrameType::TUNNEL_CLOSE &&
            !reopen_while_close_in_flight.has_value()) {
            // We are mid-handoff: the frame has not reached the transport yet.
            still_registered_in_flight = manager->has_tunnel(kTunnelId);
            // A SECOND resolver arriving now is what makes the difference
            // observable. It drives a terminal transition, which runs the
            // id-releasable notifier — and that notifier must not conclude the
            // id is free while this frame is still inside the callback. Probing
            // alone proves nothing: nothing would have called the notifier.
            raw->force_close();
            reopen_while_close_in_flight = peer_could_reopen();
        }
        return SendOutcome::Sent;
    });

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    tunnel->set_state(Tunnel::State::Connected);

    // remove_tunnel_if installs the id-releasable hook and then tears down,
    // which is what emits the CLOSE we intercept above.
    manager->remove_tunnel_if(kTunnelId, raw);

    ASSERT_TRUE(reopen_while_close_in_flight.has_value())
        << "precondition: the teardown emitted a TUNNEL_CLOSE";
    ASSERT_FALSE(still_registered_in_flight)
        << "precondition: only the reservation can be keeping the id at that point";
    EXPECT_FALSE(*reopen_while_close_in_flight)
        << "the id was released while its TUNNEL_CLOSE was still inside the transport callback";

    // Once the transport has taken it, the id comes back.
    EXPECT_TRUE(peer_could_reopen()) << "the id was never released after the handoff";

    io_ctx.restart();
    io_ctx.run();
}

TEST(ActiveGaugeTest, AGracefulRemovalOfAPublishedTunnelSettlesTheGauge) {
    // A published tunnel removed gracefully stops at `Disconnecting`, which is
    // NOT terminal. Wiring the gauge release solely to Closed/Error therefore
    // held the count for as long as the tunnel sat half-closed — and forever
    // when the half-close reaper is disabled. This is the window commit_open_ack
    // can publish into after its ownership re-check, so the count is real.
    asio::io_context io_ctx;
    auto manager = std::make_shared<TunnelManager>(io_ctx);
    manager->set_send_handler([](const std::vector<std::uint8_t>&) { return SendOutcome::Sent; });

    auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) -> SendOutcome { return SendOutcome::Sent; });

    auto gauge = app::detail::make_active_gauge_latch();
    // THE production wiring, not a hand-rolled copy of it: an earlier version of
    // this test installed the callbacks itself, which made it assert its own
    // wiring rather than the server's and pass against the broken code.
    app::detail::wire_active_gauge(*tunnel, gauge, nullptr);

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    tunnel->set_state(Tunnel::State::Connected);

    const auto before =
        util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server);
    ASSERT_TRUE(app::detail::active_gauge_count(gauge)) << "precondition: commit counted it";
    ASSERT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              before + 1);

    // The graceful removal: Connected -> Disconnecting, on_close fires, the
    // tunnel never reaches a terminal state on its own.
    manager->remove_tunnel_if(kTunnelId, tunnel.get());
    ASSERT_EQ(tunnel->state(), Tunnel::State::Disconnecting)
        << "precondition: a graceful removal stops short of terminal";

    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              before)
        << "the active gauge was left counted for a tunnel the manager has let go of";

    io_ctx.restart();
    io_ctx.run();
}

TEST(ForceCloseResourceTest, ConcurrentForceClosesStillAnnounceAndNotifyExactlyOnce) {
    // force_close() has two independent one-shots: the state claim and the
    // resource release. Different threads can win them. When the state claimant
    // lost the resource latch it used to return from the whole function, so
    // NOBODY announced the CLOSE and NOBODY published the Closed transition —
    // the peer was stranded and every state observer missed it.
    //
    // GUARD, not a reproduction — stated plainly because an earlier report of
    // mine implied otherwise. The window is between the two latches, with no
    // callback in between, so there is nothing to inject at; racing it does not
    // reliably hit a gap this narrow, and this test passes against the broken
    // code unless the revert is artificially slowed at that exact point (which
    // is how the defect was actually demonstrated). It is kept because it costs
    // little and would catch a coarser regression, but it is NOT evidence.
    for (int i = 0; i < 4000; ++i) {
        asio::io_context io_ctx;
        auto tunnel = std::make_shared<TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        TunnelImpl* raw = tunnel.get();

        std::mutex wire_mutex;
        std::vector<FrameType> wire;
        tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
            std::lock_guard<std::mutex> lock(wire_mutex);
            wire.push_back(type_of(frame));
            return SendOutcome::Sent;
        });

        std::atomic<int> closed_observed{0};
        tunnel->set_on_state_change([&closed_observed](Tunnel::State new_state) {
            if (new_state == Tunnel::State::Closed) {
                closed_observed.fetch_add(1);
            }
        });
        tunnel->set_state(Tunnel::State::Connected);

        std::atomic<bool> ready{false};
        std::atomic<bool> go{false};
        std::thread other([&]() {
            ready.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            raw->force_close();
        });
        while (!ready.load(std::memory_order_acquire)) {
        }
        go.store(true, std::memory_order_release);
        raw->force_close();
        other.join();

        std::size_t closes = 0;
        {
            std::lock_guard<std::mutex> lock(wire_mutex);
            closes = static_cast<std::size_t>(
                std::count(wire.begin(), wire.end(), FrameType::TUNNEL_CLOSE));
        }
        ASSERT_EQ(closes, 1u) << "iteration " << i
                              << ": the peer had our OPEN_ACK and was told nothing";
        ASSERT_EQ(closed_observed.load(), 1)
            << "iteration " << i << ": the Closed transition was never published";
        ASSERT_EQ(tunnel->state(), Tunnel::State::Closed) << "iteration " << i;
    }
}

// ===========================================================================
// 17. The CLOSE obligation, on both the under- and over-counting paths
// ===========================================================================

TEST_F(IdReservationTest, ForceCloseDuringAnInFlightOpenKeepsTheIdReservedUntilTheSenderEmits) {
    // force_close() receives CloseObligation::DeferredToSender and deliberately
    // does NOT announce — the sender must, so the CLOSE cannot overtake the OPEN
    // it retracts. But it used to record nothing either, so the id-releasable
    // hook saw a terminal tunnel owing nothing and recycled the id while the
    // sender still had that CLOSE to emit.
    //
    // NOTE ON SCOPE: this probes only AFTER force_close() has returned, so it
    // does NOT cover the window inside it — between the terminal state claim and
    // the CLOSE obligation being published. An earlier version of this comment
    // claimed it did; that claim was wrong. That window is covered by
    // ClaimTerminalIsAtomicTest, which holds the claimant still inside the
    // critical section while an observer proves it cannot sample the state.
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel::TunnelImpl* raw = tunnel.get();

    std::optional<bool> reopen_after_force_close;
    bool still_registered = true;
    std::vector<FrameType> wire;
    tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
        if (type_of(frame) == FrameType::TUNNEL_OPEN && !reopen_after_force_close.has_value()) {
            // A second resolver arrives while this OPEN is inside the transport.
            raw->force_close();
            manager->remove_tunnel_if(kTunnelId, raw);
            still_registered = manager->has_tunnel(kTunnelId);
            reopen_after_force_close = peer_could_reopen();
        }
        wire.push_back(type_of(frame));
        return SendOutcome::Sent;
    });

    ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
    (void)tunnel->open("example.com", 443);

    ASSERT_TRUE(reopen_after_force_close.has_value())
        << "precondition: force_close landed while the OPEN was in flight";
    ASSERT_FALSE(still_registered)
        << "precondition: only the reservation can be keeping the id at that point";
    EXPECT_FALSE(*reopen_after_force_close)
        << "the id was recycled while the sender still owed a TUNNEL_CLOSE for it";

    // The sender emits it, after the OPEN, and only then is the id free.
    EXPECT_EQ(wire, (std::vector<FrameType>{FrameType::TUNNEL_OPEN, FrameType::TUNNEL_CLOSE}));
    EXPECT_TRUE(peer_could_reopen()) << "the id was never released after the handoff";

    io_ctx.restart();
    io_ctx.run();
}

TEST_F(IdReservationTest, AnOwedCloseThatIsNeverEmittedStillReleasesTheIdOnDestruction) {
    // The over-counting half: an owed CLOSE that no path ever discharges must
    // not pin the id for the life of the manager. Nothing can emit once the
    // tunnel is destroyed, so destruction resolves the owed-ness.
    {
        auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        tunnel::TunnelImpl* raw = tunnel.get();
        tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
            if (type_of(frame) == FrameType::TUNNEL_OPEN) {
                raw->close();  // DeferredToSender: the CLOSE is now owed.
            }
            // The OPEN never reaches the peer, so the owed CLOSE is abandoned
            // rather than emitted.
            return SendOutcome::SendqFull;
        });

        ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
        (void)tunnel->open("example.com", 443);
        manager->remove_tunnel_if(kTunnelId, raw);
    }

    EXPECT_TRUE(peer_could_reopen())
        << "an owed-but-never-emitted TUNNEL_CLOSE pinned the id permanently";

    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 18. commit_open_ack's post-claim ownership recheck
// ===========================================================================

TEST_F(UnpublishedTunnelTeardownTest, CommitCatchesADetachThatLandsDuringTheStateClaim) {
    // try_publish_connected() invokes the Connected state callback SYNCHRONOUSLY
    // before returning, which is the one place a detach can land after commit's
    // first ownership check and before it publishes. Only the second check can
    // catch it.
    //
    // The existing detached-tunnel tests resolve the tunnel BEFORE entering
    // commit_open_ack(), so the first check catches those and they say nothing
    // about the second one.
    SetUpUnpublishedTunnel();

    bool detached_from_callback = false;
    tunnel->set_on_state_change([&](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected && !detached_from_callback) {
            detached_from_callback = true;
            manager->remove_tunnel_if(kTunnelId, tunnel.get());
        }
    });

    const auto outcome =
        app::detail::commit_open_ack(manager, tunnel, conn, kTunnelId, kFriendNumber, gauge);

    ASSERT_TRUE(detached_from_callback) << "precondition: the detach ran inside the state claim";
    EXPECT_EQ(outcome, app::detail::OpenAckCommit::Detached)
        << "commit published a tunnel that was detached during its own state claim";
    EXPECT_EQ(util::MetricsRegistry::instance().tunnels_active(util::MetricsRegistry::Role::Server),
              gauge_before)
        << "the active gauge was counted for a detached tunnel";

    // Tear the socket down explicitly: a regression here publishes the tunnel
    // and starts its read loop, which would otherwise keep the io_context busy
    // and hang the suite instead of failing it.
    conn->force_close();
    io_ctx.restart();
    io_ctx.run();
}

// ===========================================================================
// 19. The terminal claim and the CLOSE obligation are ONE observable step
// ===========================================================================

// GUARD, not deterministic evidence: it races the window rather than holding it
// open, so it can pass against broken code. The deterministic version is
// ClaimTerminalIsAtomicTest below, which uses the claim's test hook.
//
// Kept because it exercises the same invariant under real contention and would
// catch a coarser regression (an obligation dropped entirely, or a claim that
// never resolves).
TEST(ForceCloseTerminalClaimTest, NoObserverEverSeesTerminalWithoutTheCloseObligation) {
    // The window: force_close() claims Connected -> Closed, is preempted, and a
    // resolver observes "terminal + owes nothing" — exactly the state that means
    // the id is free. It recycles the id; the claimant then emits its CLOSE
    // against whatever took it.
    //
    // Observed from a second thread sampling id_releasable() in a tight loop,
    // because that is what the manager's id-releasable hook effectively does.
    // The invariant is one-directional and cannot false-positive: the id may
    // only become releasable once the CLOSE has been resolved, so ANY sample of
    // releasable-before-resolved is a real violation.
    for (int i = 0; i < 2000; ++i) {
        asio::io_context io_ctx;
        auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        tunnel::TunnelImpl* raw = tunnel.get();

        std::atomic<bool> close_resolved{false};
        tunnel->set_on_send_to_tox(
            [&close_resolved](std::span<const std::uint8_t> frame) -> SendOutcome {
                if (type_of(frame) == FrameType::TUNNEL_CLOSE) {
                    // Set only AFTER the transport has taken it; the observer
                    // uses this to tell a legitimate release from a premature
                    // one.
                    close_resolved.store(true, std::memory_order_release);
                }
                return SendOutcome::Sent;
            });
        tunnel->set_state(tunnel::Tunnel::State::Connected);

        std::atomic<bool> stop{false};
        std::atomic<bool> saw_premature_release{false};
        std::thread observer([&]() {
            while (!stop.load(std::memory_order_acquire)) {
                if (raw->id_releasable() && !close_resolved.load(std::memory_order_acquire)) {
                    saw_premature_release.store(true, std::memory_order_release);
                    return;
                }
            }
        });

        raw->force_close();
        stop.store(true, std::memory_order_release);
        observer.join();

        ASSERT_FALSE(saw_premature_release.load())
            << "iteration " << i
            << ": the id was observed releasable while a TUNNEL_CLOSE was still owed";
        ASSERT_TRUE(raw->id_releasable()) << "iteration " << i << ": the id was never released";
    }
}

TEST(ForceCloseTerminalClaimTest, AClaimThatOwesNothingReleasesTheIdImmediately) {
    // The mirror image, so the invariant above cannot be satisfied by simply
    // never releasing: a tunnel the peer never heard of owes no CLOSE, and its
    // id must come back as soon as the claim resolves it.
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    std::vector<FrameType> wire;
    tunnel->set_on_send_to_tox([&wire](std::span<const std::uint8_t> frame) -> SendOutcome {
        wire.push_back(type_of(frame));
        return SendOutcome::Sent;
    });

    ASSERT_FALSE(tunnel->id_releasable()) << "a live tunnel can still start owing a CLOSE";
    tunnel->force_close();

    EXPECT_TRUE(wire.empty()) << "the peer never heard of this tunnel";
    EXPECT_TRUE(tunnel->id_releasable());
}

// ===========================================================================
// 20. A backpressured TUNNEL_CLOSE is retained and retried, not dropped
// ===========================================================================

TEST_F(IdReservationTest, ABackpressuredCloseFrameIsRetriedAndKeepsTheIdReservedMeanwhile) {
    // The emit path used to ignore its own typed result and resolve on ANY
    // outcome — including SendqFull, where the transport did not take the frame
    // and the tunnel still owns it. That dropped the CLOSE (the peer never
    // learns the tunnel is over) AND released the id (so it could be recycled
    // while the peer still thinks the old tunnel is open).
    //
    // The test holds NO strong reference across the retry, on purpose: removal
    // drops the manager's, so if the retry owner did not retain itself the
    // tunnel would be destroyed and the frame silently abandoned. An earlier
    // version of this test kept its own reference alive and so could not see
    // that.
    //
    // SCOPE: this injects SendqFull directly through the per-tunnel callback, so
    // it covers the CALLBACK CONTRACT, not today's production CLOSE path.
    // Production senders go through app::detail::make_tunnel_senders(), and
    // route_sendq_full() excludes TUNNEL_CLOSE from driver-owned retry — a
    // backpressured CLOSE is parked in TunnelManager's queue and reported Sent,
    // so this retry never arms for it. The machinery is the contract for the
    // slice that moves CLOSE off that queue; do not read this test as evidence
    // that production CLOSEs are retried today.
    std::atomic<int> close_attempts{0};
    std::atomic<bool> transport_blocked{true};
    std::weak_ptr<tunnel::TunnelImpl> weak_tunnel;

    {
        auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        weak_tunnel = tunnel;
        tunnel->set_on_send_to_tox([&](std::span<const std::uint8_t> frame) -> SendOutcome {
            if (type_of(frame) != FrameType::TUNNEL_CLOSE) {
                return SendOutcome::Sent;
            }
            close_attempts.fetch_add(1);
            return transport_blocked.load() ? SendOutcome::SendqFull : SendOutcome::Sent;
        });

        ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
        tunnel->set_state(tunnel::Tunnel::State::Connected);
        manager->remove_tunnel_if(kTunnelId, tunnel.get());
    }

    ASSERT_EQ(close_attempts.load(), 1) << "precondition: the teardown attempted a TUNNEL_CLOSE";
    ASSERT_FALSE(weak_tunnel.expired())
        << "the retry owner must keep itself alive; nobody else is holding it";
    EXPECT_FALSE(peer_could_reopen())
        << "the id was released while a backpressured TUNNEL_CLOSE was still owed";

    // Let the transport accept it; the retry timer re-emits. Bounded by a
    // DEADLINE, not an iteration count: the retry is a real 2 ms timer, and a
    // fixed number of non-blocking poll() calls can finish before it expires —
    // especially on the Windows ARM VM, whose timer granularity is ~15.6 ms.
    transport_blocked.store(false);
    pump_io_until(io_ctx, [&]() { return close_attempts.load() >= 2; });

    EXPECT_GE(close_attempts.load(), 2)
        << "the backpressured TUNNEL_CLOSE was dropped instead of retried";
    EXPECT_TRUE(peer_could_reopen()) << "the id was never released after the retry succeeded";

    io_ctx.restart();
    io_ctx.run();
    EXPECT_TRUE(weak_tunnel.expired())
        << "the retry owner held its self-reference after the obligation resolved";
}

// ===========================================================================
// 21. The terminal claim is atomic — held open and proved, not raced
// ===========================================================================

TEST(ClaimTerminalIsAtomicTest, AnObserverCannotSampleTheStateBetweenClaimAndObligation) {
    // Deterministic, via the claim's test hook plus a NON-BLOCKING probe.
    //
    // The hook pauses the claimant immediately after the terminal
    // compare-exchange, while `close_frame_mutex_` is still held — widening
    // SCHEDULING without opening the atomicity boundary.
    //
    // The observer probes with try_lock rather than calling the blocking
    // `id_releasable()`. That matters: a blocking observer that gets descheduled
    // is indistinguishable from one that is correctly blocked, so the claimant's
    // pause could expire and the whole window be missed — the test would then
    // pass against broken code purely by being late. "I could not acquire the
    // lock" is an observation that needs no luck to make, and the claimant does
    // not resume until the observer has actually made it.
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel::TunnelImpl* raw = tunnel.get();

    // Set once the CLOSE has been offered to the transport. A `Releasable`
    // probe after that point is correct; before it, it is the violation.
    std::atomic<bool> close_attempted{false};
    tunnel->set_on_send_to_tox(
        [&close_attempted](std::span<const std::uint8_t> frame) -> SendOutcome {
            if (type_of(frame) == FrameType::TUNNEL_CLOSE) {
                close_attempted.store(true, std::memory_order_release);
            }
            return SendOutcome::Sent;
        });
    tunnel->set_state(tunnel::Tunnel::State::Connected);

    // The claimant BLOCKS on this until the observer has probed enough. Blocking
    // — not spinning, not yielding — is what makes the rendezvous independent of
    // the scheduler: a blocked thread leaves the run queue entirely, so the OS
    // must run the observer. Yielding was measured insufficient on Windows
    // (4/5 failures pinned to one CPU); SwitchToThread only offers the core to a
    // thread already ready on that processor and returns immediately otherwise.
    std::mutex rendezvous_mutex;
    std::condition_variable rendezvous_cv;

    std::atomic<bool> claimant_paused{false};
    std::atomic<bool> claimant_resumed{false};
    std::atomic<int> probes{0};
    std::atomic<bool> saw_premature_release{false};

    // EVERYTHING ASSERTED ON IS SNAPSHOTTED AT THE HOOK BOUNDARY.
    //
    // This test has been wrong three times, each time the same way: the
    // assertion was evaluated at a moment when the property it describes no
    // longer held, so work the observer did AFTER the window could satisfy it.
    // The property is "the observer probed while the claimant was held", so the
    // only honest measurement is the one taken as the hook releases. Nothing
    // that happens afterwards can move these two values.
    std::atomic<int> probes_at_hook_exit{-1};
    std::atomic<bool> violation_at_hook_exit{false};

    constexpr int kRequiredProbes = 64;

    tunnel->set_terminal_claim_test_hook([&]() {
        {
            std::unique_lock<std::mutex> rendezvous(rendezvous_mutex);
            claimant_paused.store(true, std::memory_order_release);
            rendezvous_cv.notify_all();
            // BLOCK until the observer has genuinely probed. Two earlier
            // versions of this wait were scheduler-dependent and both failed on
            // Windows CI with `probes_at_hook_exit == 0`: a bounded iteration
            // count (a proxy for time), then a yielding loop. Reproduced here by
            // pinning the process to a single CPU — the bounded spin failed 5/5
            // and the yielding wait 4/5.
            //
            // Blocking is not a stronger proxy, it is a different mechanism: the
            // claimant leaves the run queue, so the observer is scheduled by
            // necessity rather than by the scheduler's goodwill. The deadline is
            // only a safety bound, and reaching it still fails loudly below.
            //
            // Safe even though close_frame_mutex_ is held: the observer probes
            // with try_lock, so it progresses WITHOUT that mutex and cannot
            // deadlock against this wait. A blocking observer could not be
            // waited for like this.
            rendezvous_cv.wait_for(rendezvous, std::chrono::seconds(30), [&]() {
                return probes.load(std::memory_order_acquire) >= kRequiredProbes;
            });
        }
        // The boundary.
        //
        // ORDER MATTERS — DO NOT SWAP THESE TWO. The count is read FIRST, and
        // the violation flag second.
        //
        // The observer stores its violation before incrementing the count, so an
        // acquire load of the count synchronizes with every violation store that
        // preceded a counted increment. Reading the count first therefore puts
        // all of those stores before the violation read that follows it in
        // program order, which is exactly what the assertions rely on: "the
        // count reached 64" has to imply "the violations belonging to those 64
        // probes are visible here".
        //
        // Reading the violation flag first breaks that. The count's acquire
        // cannot order a read that already happened, so a probe could be counted
        // while its violation store stayed invisible to the earlier read — and a
        // real violation would be silently dropped.
        const int counted = probes.load(std::memory_order_acquire);
        probes_at_hook_exit.store(counted, std::memory_order_release);
        violation_at_hook_exit.store(saw_premature_release.load(std::memory_order_acquire),
                                     std::memory_order_release);
    });

    std::thread observer([&]() {
        {
            // Block rather than spin, for the same reason as the claimant.
            std::unique_lock<std::mutex> rendezvous(rendezvous_mutex);
            rendezvous_cv.wait_for(rendezvous, std::chrono::seconds(30), [&]() {
                return claimant_paused.load(std::memory_order_acquire);
            });
        }
        while (!claimant_resumed.load(std::memory_order_acquire)) {
            // Never blocks, so being descheduled costs a probe rather than the
            // whole observation.
            const auto probe = raw->probe_id_releasable();
            const bool close_seen = close_attempted.load(std::memory_order_acquire);
            if (probe == tunnel::TunnelImpl::IdReleasableProbe::Releasable && !close_seen) {
                saw_premature_release.store(true, std::memory_order_release);
            }
            probes.fetch_add(1, std::memory_order_acq_rel);
            // Wake the claimant as soon as the quota is met. Taking the
            // rendezvous mutex here is what gives the notification a
            // happens-before edge with the claimant's predicate check.
            { std::lock_guard<std::mutex> rendezvous(rendezvous_mutex); }
            rendezvous_cv.notify_all();
        }
    });

    raw->force_close();
    claimant_resumed.store(true, std::memory_order_release);
    observer.join();

    ASSERT_GE(probes_at_hook_exit.load(), kRequiredProbes)
        << "the observer did not probe while the claim was held open — probes made after the "
           "hook released prove nothing, so the test proved nothing";
    EXPECT_FALSE(violation_at_hook_exit.load())
        << "the id was observed releasable between the terminal claim and the CLOSE obligation";
    // The claim really happened, so the assertion above is not vacuous.
    EXPECT_EQ(raw->state(), tunnel::Tunnel::State::Closed);
    EXPECT_TRUE(raw->id_releasable()) << "the id must be released once the CLOSE resolves";
}

// ===========================================================================
// 22. Cancellation fences an in-flight CLOSE attempt
// ===========================================================================

TEST_F(IdReservationTest, CancellationFencesAnInFlightCloseSoALateSendqFullCannotRearm) {
    // cancel_close_retry() could only reach the `Owed` state, so an attempt
    // already INSIDE the transport was untouched. When that call came back
    // SendqFull it restored `Owed` and armed a fresh strong-self timer — after
    // cancellation — which kept the tunnel alive past teardown and contradicted
    // the shutdown contract.
    //
    // The observable is lifetime: a strong-self timer is the only thing that can
    // hold this tunnel once the manager and the test have both let go.
    std::weak_ptr<tunnel::TunnelImpl> weak_tunnel;
    std::atomic<int> close_attempts{0};

    {
        auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
        weak_tunnel = tunnel;
        tunnel::TunnelImpl* raw = tunnel.get();

        tunnel->set_on_send_to_tox([&, raw](std::span<const std::uint8_t> frame) -> SendOutcome {
            if (type_of(frame) != FrameType::TUNNEL_CLOSE) {
                return SendOutcome::Sent;
            }
            close_attempts.fetch_add(1);
            // Teardown lands while this very call is in flight, and the call
            // then reports backpressure — the exact ordering that used to
            // re-arm after cancellation.
            raw->close_outbound_gate();
            return SendOutcome::SendqFull;
        });

        ASSERT_TRUE(manager->add_tunnel(kTunnelId, tunnel));
        tunnel->set_state(tunnel::Tunnel::State::Connected);
        manager->remove_tunnel_if(kTunnelId, tunnel.get());
    }

    ASSERT_EQ(close_attempts.load(), 1)
        << "precondition: the teardown attempted a TUNNEL_CLOSE and it was in flight";
    EXPECT_TRUE(weak_tunnel.expired())
        << "a late SendqFull re-armed a strong-self retry after cancellation, so the tunnel "
           "outlived teardown";

    // And nothing is left to run: a surviving timer would keep the io_context
    // busy and re-enter the (now destroyed) tunnel.
    io_ctx.restart();
    io_ctx.run();
    EXPECT_EQ(close_attempts.load(), 1) << "a retry ran after cancellation";
}

TEST(ForceCloseResourceTest, AClaimAfterCancellationDoesNotPinTheIdForTheObjectsLifetime) {
    // Cancellation fences EMISSION, so a claim that publishes `Owed` afterwards
    // creates an obligation nothing can ever discharge — the id stays pinned
    // until the tunnel is destroyed. Obligation publication has to be
    // cancellation-aware too, not just arming.
    asio::io_context io_ctx;
    auto tunnel = std::make_shared<tunnel::TunnelImpl>(io_ctx, kTunnelId, kFriendNumber);
    tunnel->set_on_send_to_tox(
        [](std::span<const std::uint8_t>) -> SendOutcome { return SendOutcome::Sent; });
    tunnel->set_state(tunnel::Tunnel::State::Connected);

    // Teardown first: this cancels, and from here every send is a no-op.
    tunnel->close_outbound_gate();

    // A terminal claim arrives afterwards. It would normally owe the peer a
    // CLOSE (the tunnel was Connected), but with emission fenced that debt can
    // never be paid.
    tunnel->force_close();

    EXPECT_EQ(tunnel->state(), tunnel::Tunnel::State::Closed);
    EXPECT_TRUE(tunnel->id_releasable())
        << "a post-cancellation claim recorded an obligation nothing can discharge, pinning the "
           "id for the object's lifetime";
}
