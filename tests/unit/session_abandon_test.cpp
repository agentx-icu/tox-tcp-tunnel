// Issues #41 / #44: how a tunnel ends when its session is abandoned, when the
// local application resets its socket, and who owns a server open that ends
// before its target connection is wired.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
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
using tunnel::SendOutcome;
using tunnel::Tunnel;
using tunnel::TunnelImpl;
using tunnel::TunnelManager;
using TeardownMode = TunnelManager::TeardownMode;

/// Every frame a tunnel hands to "toxcore", decoded. `outcome` scripts the
/// transport's answer.
struct Wire {
    std::mutex mutex;
    std::vector<ProtocolFrame> frames;
    SendOutcome outcome = SendOutcome::Sent;

    TunnelImpl::SendToToxCallback sender() {
        return [this](std::span<const std::uint8_t> data) {
            std::lock_guard<std::mutex> lock(mutex);
            if (outcome != SendOutcome::Sent) {
                return outcome;
            }
            if (auto f = ProtocolFrame::deserialize(data)) {
                frames.push_back(f.value());
            }
            return SendOutcome::Sent;
        };
    }

    std::vector<FrameType> types() {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<FrameType> out;
        for (const auto& f : frames) {
            out.push_back(f.type());
        }
        return out;
    }

    /// The single TUNNEL_ERROR on the wire, or nullopt.
    std::optional<tunnel::TunnelErrorPayload> error() {
        std::lock_guard<std::mutex> lock(mutex);
        std::optional<tunnel::TunnelErrorPayload> found;
        for (const auto& f : frames) {
            if (f.type() == FrameType::TUNNEL_ERROR) {
                EXPECT_FALSE(found.has_value()) << "more than one TUNNEL_ERROR";
                found = f.as_tunnel_error();
            }
        }
        return found;
    }
};

std::shared_ptr<TunnelImpl> make_tunnel(asio::io_context& io_ctx, std::uint16_t id, Wire& wire,
                                        Tunnel::State state) {
    auto t = std::make_shared<TunnelImpl>(io_ctx, id, /*friend_number=*/0);
    t->set_on_send_to_tox(wire.sender());
    if (state == Tunnel::State::Connected || state == Tunnel::State::Disconnecting) {
        t->set_state(Tunnel::State::Connecting);
        t->set_state(Tunnel::State::Connected);
    } else {
        t->set_state(state);
    }
    return t;
}

void pump_until(asio::io_context& io_ctx, const std::function<bool()>& done,
                std::chrono::milliseconds budget = std::chrono::milliseconds(3000)) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!done() && std::chrono::steady_clock::now() < deadline) {
        io_ctx.restart();
        io_ctx.run_for(std::chrono::milliseconds(10));
    }
}

// ---------------------------------------------------------------------------
// TunnelManager::close_all(Abandon)  (#41)
// ---------------------------------------------------------------------------

TEST(SessionAbandonTest, ConnectedTunnelEndsWithErrorCode4) {
    asio::io_context io_ctx;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    Wire wire;
    auto t = make_tunnel(io_ctx, 1, wire, Tunnel::State::Connected);
    ASSERT_TRUE(mgr->add_tunnel(1, t));

    mgr->close_all(TeardownMode::Abandon);

    EXPECT_EQ(t->state(), Tunnel::State::Error)
        << "Error is what resets the local socket and settles the client's books";
    auto err = wire.error();
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->error_code, 4);
    EXPECT_EQ(wire.types(), std::vector<FrameType>{FrameType::TUNNEL_ERROR})
        << "no graceful CLOSE ahead of the ERROR";
    EXPECT_EQ(mgr->tunnel_count(), 0u);
}

TEST(SessionAbandonTest, HalfClosedTunnelGetsTheErrorAfterItsClose) {
    asio::io_context io_ctx;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    Wire wire;
    auto t = make_tunnel(io_ctx, 2, wire, Tunnel::State::Connected);
    ASSERT_TRUE(mgr->add_tunnel(2, t));
    t->close();  // the application half-closed: CLOSE sent, now Disconnecting
    ASSERT_EQ(t->state(), Tunnel::State::Disconnecting);

    mgr->close_all(TeardownMode::Abandon);

    EXPECT_EQ(t->state(), Tunnel::State::Error);
    EXPECT_EQ(wire.types(),
              (std::vector<FrameType>{FrameType::TUNNEL_CLOSE, FrameType::TUNNEL_ERROR}));
    ASSERT_TRUE(wire.error().has_value());
    EXPECT_EQ(wire.error()->error_code, 4);
}

TEST(SessionAbandonTest, HandshakeTunnelKeepsTheGracefulPath) {
    asio::io_context io_ctx;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    Wire wire;
    // Connecting with no OPEN on the wire yet: close() owes the peer nothing.
    auto t = make_tunnel(io_ctx, 3, wire, Tunnel::State::Connecting);
    ASSERT_TRUE(mgr->add_tunnel(3, t));

    mgr->close_all(TeardownMode::Abandon);

    EXPECT_EQ(t->state(), Tunnel::State::Closed);
    EXPECT_TRUE(wire.types().empty()) << "an ERROR here could overtake a pending OPEN";
}

TEST(SessionAbandonTest, GracefulModeIsUnchanged) {
    asio::io_context io_ctx;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    Wire wire;
    auto t = make_tunnel(io_ctx, 4, wire, Tunnel::State::Connected);
    ASSERT_TRUE(mgr->add_tunnel(4, t));

    mgr->close_all();

    EXPECT_EQ(t->state(), Tunnel::State::Disconnecting);
    EXPECT_EQ(wire.types(), std::vector<FrameType>{FrameType::TUNNEL_CLOSE});
}

// Round-1 review finding: a graceful CLOSE deferred behind backpressured DATA
// died with the detached tunnel. The abandon ERROR must survive on its own —
// nobody here keeps a reference to the tunnel once close_all() returns.
TEST(SessionAbandonTest, BackpressuredErrorStillReachesTheWireWithoutAnOwner) {
    asio::io_context io_ctx;
    auto mgr = std::make_shared<TunnelManager>(io_ctx);
    Wire wire;
    std::weak_ptr<TunnelImpl> weak;
    {
        auto t = make_tunnel(io_ctx, 5, wire, Tunnel::State::Connected);
        weak = t;
        ASSERT_TRUE(mgr->add_tunnel(5, t));
        wire.outcome = SendOutcome::SendqFull;
        const std::vector<std::uint8_t> bytes(4000, 0x5a);
        t->on_tcp_data_received(bytes.data(), bytes.size());  // parked: SENDQ full
        mgr->close_all(TeardownMode::Abandon);
    }
    {
        std::lock_guard<std::mutex> lock(wire.mutex);
        wire.outcome = SendOutcome::Sent;
    }
    pump_until(io_ctx, [&] { return wire.error().has_value(); });

    ASSERT_TRUE(wire.error().has_value()) << "the abandon ERROR was lost with its tunnel";
    EXPECT_EQ(wire.error()->error_code, 4);
    for (auto type : wire.types()) {
        EXPECT_NE(type, FrameType::TUNNEL_DATA) << "abandoned DATA must not follow the ERROR";
    }
    pump_until(io_ctx, [&] { return weak.expired(); });
    EXPECT_TRUE(weak.expired()) << "the settled ERROR must release its retry ownership";
}

// Review finding: the server reset its target from on_close, which a terminal
// ERROR held back by SENDQ backpressure fires only once toxcore takes it. The
// reset hook rides the Error transition instead.
TEST(SessionAbandonTest, ServerTargetResetDoesNotWaitForTheErrorToReachTheWire) {
    asio::io_context io_ctx;
    Wire wire;
    auto t = make_tunnel(io_ctx, 8, wire, Tunnel::State::Connected);
    int resets = 0;
    int closes = 0;
    app::detail::wire_active_gauge(
        *t, app::detail::make_active_gauge_latch(), [&] { ++closes; }, [&] { ++resets; });
    {
        std::lock_guard<std::mutex> lock(wire.mutex);
        wire.outcome = SendOutcome::SendqFull;
    }

    t->send_error(4, "session abandoned (peer failed over or judged unresponsive)");

    EXPECT_EQ(t->state(), Tunnel::State::Error);
    EXPECT_EQ(resets, 1) << "the target is reset on the Error transition";
    EXPECT_EQ(closes, 0) << "on_close still waits for the ERROR to settle";

    {
        std::lock_guard<std::mutex> lock(wire.mutex);
        wire.outcome = SendOutcome::Sent;
    }
    pump_until(io_ctx, [&] { return closes == 1; });
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(resets, 1);
    ASSERT_TRUE(wire.error().has_value());
}

// ---------------------------------------------------------------------------
// detail::end_tunnel_for_local_disconnect  (#44, client side)
// ---------------------------------------------------------------------------

struct LocalEndCase {
    std::error_code ec;
    bool expect_error;
    const char* description_part;
};

TEST(LocalDisconnectTest, AbnormalEndsBecomeErrorCode4CleanEndsStayGraceful) {
    const std::vector<LocalEndCase> cases = {
        {asio::error::connection_reset, true, "ended abnormally"},
        {asio::error::broken_pipe, true, "ended abnormally"},
        {asio::error::no_buffer_space, true, "write queue cap"},
        {asio::error::eof, false, nullptr},
        {asio::error::operation_aborted, false, nullptr},
        {std::error_code{}, false, nullptr},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.ec.message());
        asio::io_context io_ctx;
        Wire wire;
        auto t = make_tunnel(io_ctx, 6, wire, Tunnel::State::Connected);

        app::detail::end_tunnel_for_local_disconnect(t, c.ec);

        if (c.expect_error) {
            EXPECT_EQ(t->state(), Tunnel::State::Error);
            auto err = wire.error();
            ASSERT_TRUE(err.has_value());
            EXPECT_EQ(err->error_code, 4);
            EXPECT_NE(err->description.find(c.description_part), std::string::npos)
                << err->description;
        } else {
            EXPECT_EQ(t->state(), Tunnel::State::Disconnecting);
            EXPECT_EQ(wire.types(), std::vector<FrameType>{FrameType::TUNNEL_CLOSE});
        }
    }
}

TEST(LocalDisconnectTest, ResetDuringHandshakeDoesNotRaceTheOpen) {
    asio::io_context io_ctx;
    Wire wire;
    auto t = make_tunnel(io_ctx, 7, wire, Tunnel::State::Connecting);
    app::detail::end_tunnel_for_local_disconnect(t, asio::error::connection_reset);
    EXPECT_EQ(t->state(), Tunnel::State::Closed);
    EXPECT_FALSE(wire.error().has_value());
}

TEST(LocalDisconnectTest, LapsedTunnelIsANoOp) {
    std::weak_ptr<TunnelImpl> gone;
    EXPECT_NO_THROW(
        app::detail::end_tunnel_for_local_disconnect(gone, asio::error::connection_reset));
}

// ---------------------------------------------------------------------------
// detail::PendingOpen  (#41 / #44, server pre-wire ownership)
// ---------------------------------------------------------------------------

using Phase = app::detail::PendingOpen::Phase;

TEST(PendingOpenTest, CancelWinsWhileResolvingAndSilencesTheContinuations) {
    app::detail::PendingOpen p;
    EXPECT_TRUE(p.try_cancel());
    EXPECT_TRUE(p.resolved());
    EXPECT_FALSE(p.advance(Phase::Resolving, Phase::Connecting))
        << "a resolve completing after the cancel must not start a connect";
    EXPECT_FALSE(p.try_cancel()) << "one teardown owner";
}

TEST(PendingOpenTest, CancelWinsWhileConnecting) {
    app::detail::PendingOpen p;
    ASSERT_TRUE(p.advance(Phase::Resolving, Phase::Connecting));
    EXPECT_TRUE(p.try_cancel());
    EXPECT_FALSE(p.advance(Phase::Connecting, Phase::Handed))
        << "a connect completing after the cancel must not be wired";
}

TEST(PendingOpenTest, HandedOpenBelongsToWiring) {
    app::detail::PendingOpen p;
    ASSERT_TRUE(p.advance(Phase::Resolving, Phase::Connecting));
    ASSERT_TRUE(p.advance(Phase::Connecting, Phase::Handed));
    EXPECT_FALSE(p.try_cancel()) << "wiring re-checks the tunnel itself once handed";
    EXPECT_FALSE(p.resolved());
}

TEST(PendingOpenTest, InitiationRunsUnderTheMoveOrNotAtAll) {
    app::detail::PendingOpen p;
    int started = 0;
    EXPECT_TRUE(p.advance_and(Phase::Resolving, Phase::Connecting, [&] { ++started; }));
    EXPECT_EQ(started, 1);
    app::detail::PendingOpen cancelled;
    ASSERT_TRUE(cancelled.try_cancel());
    EXPECT_FALSE(cancelled.advance_and(Phase::Resolving, Phase::Connecting, [&] { ++started; }));
    EXPECT_EQ(started, 1) << "a cancelled open must not start a connect";
}

// The re-check in wire_tcp_to_tunnel() silences a not-yet-started gate before
// tearing the socket down: the target end it then reports must not turn into
// abandon_open_ack()'s TUNNEL_ERROR and second booking.
TEST(OpenAckGateDisarmTest, DisarmedGateIgnoresTheTargetEndSilently) {
    asio::io_context io_ctx;
    int acks = 0;
    int commits = 0;
    int abandons = 0;
    auto gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx,
        [&] {
            ++acks;
            return SendOutcome::Sent;
        },
        [&] {
            ++commits;
            return true;
        },
        [&] { ++abandons; }, [] {});
    EXPECT_TRUE(gate->disarm());
    EXPECT_TRUE(gate->target_gone()) << "still the gate's teardown, not the ordinary close";
    EXPECT_FALSE(gate->disarm()) << "already resolved";
    EXPECT_EQ(acks, 0);
    EXPECT_EQ(commits, 0);
    EXPECT_EQ(abandons, 0);
}

TEST(OpenAckGateDisarmTest, DisarmLosesToAnEarlierResolution) {
    asio::io_context io_ctx;
    int abandons = 0;
    auto gate = std::make_shared<app::detail::OpenAckGate>(
        io_ctx, [] { return SendOutcome::Sent; }, [] { return true; }, [&] { ++abandons; }, [] {});
    EXPECT_TRUE(gate->target_gone());
    EXPECT_EQ(abandons, 1);
    EXPECT_FALSE(gate->disarm()) << "the abandon owns the teardown";
}

TEST(PendingOpenTest, FailureIsBookedOnce) {
    app::detail::PendingOpen p;
    EXPECT_TRUE(p.claim_failure_booking());
    EXPECT_FALSE(p.claim_failure_booking());
}

}  // namespace
}  // namespace toxtunnel::test
