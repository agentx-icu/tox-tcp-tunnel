// Unit tests for tunnel::FriendSendGate (issue #42): the per-friend DATA gate
// at the toxcore boundary, driven with a scripted clock, key resolver and
// fence transport. The long-outage cases are the schedules the design review
// used to find wedges in earlier drafts.

#include "toxtunnel/tunnel/friend_send_gate.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <asio.hpp>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace toxtunnel::tunnel {
namespace {

using Gate = FriendSendGate;
using Key = tox::LosslessSendGate::PublicKey;

constexpr std::int64_t kMs = 1'000'000;
constexpr std::int64_t kSec = 1'000 * kMs;

Key key_of(std::uint8_t b) {
    Key k{};
    k.fill(b);
    return k;
}

std::vector<std::uint8_t> lossless(const ProtocolFrame& f) {
    const auto wire = f.serialize();
    std::vector<std::uint8_t> p;
    p.push_back(kLosslessPacketByte);
    p.insert(p.end(), wire.begin(), wire.end());
    return p;
}

std::vector<std::uint8_t> data_packet(std::size_t payload = 1300) {
    return lossless(ProtocolFrame::make_tunnel_data(7, std::vector<std::uint8_t>(payload, 0x5a)));
}

std::uint64_t seq_of(const std::vector<std::uint8_t>& fence) {
    std::uint64_t v = 0;
    for (int i = 15; i < 23; ++i) {
        v = (v << 8) | fence[static_cast<std::size_t>(i)];
    }
    return v;
}

/// The PONG a current peer sends for a fence packet.
std::vector<std::uint8_t> echo_of(const std::vector<std::uint8_t>& fence_packet) {
    auto ping = ProtocolFrame::deserialize(
        std::span<const std::uint8_t>(fence_packet.data() + 1, fence_packet.size() - 1));
    EXPECT_TRUE(ping.has_value());
    return lossless(ProtocolFrame::make_pong_for(ping.value()));
}

/// Scripted toxcore around one gate.
struct Harness {
    Gate gate;
    std::map<std::uint32_t, Key> keys{{1, key_of(1)}};
    std::vector<std::vector<std::uint8_t>> fences;  // fence packets toxcore accepted
    bool send_ok = true;
    std::int64_t now = 1 * kSec;
    tox::LosslessSendGate::Io io;

    explicit Harness(const Gate::Config& cfg = {}) : gate(cfg, /*epoch=*/0x1122334455667788ULL) {
        io.public_key = [this](std::uint32_t n) -> std::optional<Key> {
            auto it = keys.find(n);
            if (it == keys.end()) {
                return std::nullopt;
            }
            return it->second;
        };
        io.send = [this](std::uint32_t, std::span<const std::uint8_t> p) {
            if (!send_ok) {
                return false;
            }
            fences.emplace_back(p.begin(), p.end());
            return true;
        };
    }

    /// Offer one DATA frame like ToxAdapter does: admit, then account.
    bool offer_data(std::uint32_t fn = 1, std::size_t payload = 1300) {
        const auto p = data_packet(payload);
        if (!gate.admit(io, fn, p, now)) {
            return false;
        }
        gate.on_accepted(io, fn, p, now);
        return true;
    }
    int fill(std::uint32_t fn = 1, int max = 10000) {
        int n = 0;
        while (n < max && offer_data(fn)) {
            ++n;
        }
        return n;
    }
    void tick() { gate.on_tick(io, now); }
    void deliver(const std::vector<std::uint8_t>& pong, std::uint32_t fn = 1) {
        gate.on_received(io, fn, pong, now);
    }
    Gate::View view(std::uint8_t k = 1) { return gate.view(key_of(k)).value(); }
};

TEST(FriendSendGateTest, ControlFramesAreNeverHeldBack) {
    Harness h;
    h.fill();
    ASSERT_FALSE(h.offer_data()) << "DATA is gated at the bootstrap floor";
    for (const auto& f :
         {ProtocolFrame::make_ping(), ProtocolFrame::make_pong(),
          ProtocolFrame::make_tunnel_ack(3, 100), ProtocolFrame::make_tunnel_close(3),
          ProtocolFrame::make_tunnel_error(3, 4, "x")}) {
        EXPECT_TRUE(h.gate.admit(h.io, 1, lossless(f), h.now)) << to_string(f.type());
    }
}

TEST(FriendSendGateTest, BootstrapStopsAtTheFloorAndSendsAFenceWhenBlocked) {
    Harness h;
    const int admitted = h.fill();
    EXPECT_GT(admitted, 0);
    EXPECT_LE(h.view().emitted, Gate::Config{}.floor_bytes + data_packet().size());
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    const auto fences_after_block = h.fences.size();
    h.tick();
    EXPECT_EQ(h.fences.size(), fences_after_block) << "the debt is covered; no fence storm";
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap);
}

TEST(FriendSendGateTest, AnEchoActivatesTheGateAndCreditsEverythingBeforeIt) {
    Harness h;
    h.fill();
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    h.now += 300 * kMs;
    h.deliver(echo_of(h.fences.back()));
    const auto v = h.view();
    EXPECT_EQ(v.phase, Gate::Phase::Active);
    EXPECT_EQ(v.delivered, v.emitted);
    EXPECT_EQ(v.entries, 0u);
    EXPECT_TRUE(h.offer_data()) << "credit reopens the gate";
}

TEST(FriendSendGateTest, OnlyAnExactEchoOfThisProcessCredits) {
    Harness h;
    h.fill();
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    // Another process's fence (other epoch), an unknown seq, a plain PONG.
    h.deliver(echo_of(Gate::make_fence_packet(0x99, seq_of(h.fences.back()))));
    h.deliver(echo_of(Gate::make_fence_packet(h.view().epoch, 424242)));
    EXPECT_EQ(h.view().delivered, 0u);
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap);
}

TEST(FriendSendGateTest, APlainPongAnsweringAFenceMeansALegacyPeer) {
    Harness h;
    // A keepalive PING and its plain PONG are not evidence.
    const auto ka = lossless(ProtocolFrame::make_ping());
    h.gate.on_accepted(h.io, 1, ka, h.now);
    h.fill();
    h.tick();
    h.deliver(lossless(ProtocolFrame::make_pong()));
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap) << "that PONG answered the keepalive";
    h.deliver(lossless(ProtocolFrame::make_pong()));
    EXPECT_EQ(h.view().phase, Gate::Phase::Legacy) << "this one answered the fence";
    EXPECT_TRUE(h.offer_data()) << "legacy peers run ungated";
}

TEST(FriendSendGateTest, NoEchoWithinTheTimeoutMeansALegacyPeer) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 11 * kSec;
    h.tick();
    EXPECT_EQ(h.view().phase, Gate::Phase::Legacy);
    EXPECT_TRUE(h.offer_data());
}

TEST(FriendSendGateTest, ReconnectReArmsDetectionForALegacyPeer) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 11 * kSec;
    h.tick();
    ASSERT_EQ(h.view().phase, Gate::Phase::Legacy);
    h.gate.on_connection_status(h.io, 1, true, h.now);
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap);
}

TEST(FriendSendGateTest, OfflineDoesNotWriteOffDebt) {
    Harness h;
    h.fill();
    const auto before = h.view();
    h.gate.on_connection_status(h.io, 1, false, h.now);
    h.gate.on_connection_status(h.io, 1, true, h.now);
    const auto after = h.view();
    EXPECT_EQ(after.emitted, before.emitted);
    EXPECT_EQ(after.delivered, before.delivered);
    EXPECT_FALSE(h.offer_data()) << "the stream may have survived; the debt still stands";
}

TEST(FriendSendGateTest, RecoveryFencesOfAnOutageShareOneEntry) {
    Harness h;
    h.fill();
    h.tick();
    h.deliver(echo_of(h.fences.back()));  // ACTIVE; then the peer goes silent
    h.fill();
    h.tick();
    const std::size_t entries_at_outage = h.view().entries;
    for (int i = 0; i < 2000; ++i) {
        h.now += 1 * kSec;
        h.offer_data();  // keep demand alive
        h.tick();
    }
    EXPECT_GT(h.fences.size(), 10u);
    EXPECT_EQ(h.view().entries, entries_at_outage)
        << "blocked: every recovery fence extends the newest entry";
}

TEST(FriendSendGateTest, NoEchoesEverStaysBoundedAndBlocked) {
    Harness h;
    h.fill();
    h.tick();
    h.deliver(echo_of(h.fences.back()));  // ACTIVE
    for (int round = 0; round < 3000; ++round) {
        h.now += 60 * kSec;  // 50 simulated hours
        h.fill();
        h.tick();
        ASSERT_LE(h.view().entries, Gate::Config{}.max_ledger_entries);
    }
    EXPECT_FALSE(h.offer_data()) << "a peer that answers nothing keeps the gate closed";
    EXPECT_EQ(h.view().phase, Gate::Phase::Active);
}

/// A lost oldest echo, then every later echo delivered after `latency`.
void run_lost_oldest_then_latency(std::int64_t latency, std::int64_t horizon) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 200 * kMs;
    h.deliver(echo_of(h.fences.back()));  // ACTIVE, and a backoff reset
    h.fill();
    h.tick();
    ASSERT_FALSE(h.offer_data());
    const std::size_t lost = h.fences.size() - 1;  // the oldest fence of the outage
    std::deque<std::pair<std::int64_t, std::vector<std::uint8_t>>> in_flight;
    std::size_t seen = lost + 1;
    bool resumed = false;
    for (std::int64_t t = 0; t < horizon && !resumed; t += 1 * kSec) {
        h.now += 1 * kSec;
        h.offer_data();
        h.tick();
        for (; seen < h.fences.size(); ++seen) {
            in_flight.emplace_back(h.now + latency, echo_of(h.fences[seen]));
        }
        while (!in_flight.empty() && in_flight.front().first <= h.now) {
            h.deliver(in_flight.front().second);
            in_flight.pop_front();
        }
        ASSERT_LE(h.view().entries, Gate::Config{}.max_ledger_entries);
        resumed = h.view().delivered == h.view().emitted;
    }
    (void)lost;
    EXPECT_TRUE(resumed) << "a single lost echo must not wedge the gate";
}

TEST(FriendSendGateTest, LostOldestEchoThenFourHourLatencyRecovers) {
    run_lost_oldest_then_latency(4 * 3600 * kSec, 5 * 3600 * kSec);
}

TEST(FriendSendGateTest, LostOldestEchoThenTwoMinuteLatencyRecovers) {
    run_lost_oldest_then_latency(120 * kSec, 600 * kSec);
}

TEST(FriendSendGateTest, BudgetGrowsWithTheMeasuredPath) {
    // 100 kB/s path, 100 ms RTT: echoes return 100 ms after the fence plus the
    // time its backlog takes to drain.
    Harness h;
    double backlog_bytes = 0;
    std::deque<std::pair<std::int64_t, std::vector<std::uint8_t>>> in_flight;
    std::size_t seen = 0;
    // Each fence's echo leaves after the bytes queued ahead of it drain at
    // 100 kB/s, then crosses the 100 ms path.
    const auto stamp_new_fences = [&] {
        for (; seen < h.fences.size(); ++seen) {
            const auto drain = static_cast<std::int64_t>(backlog_bytes / 100'000.0 * 1e9);
            in_flight.emplace_back(h.now + 100 * kMs + drain, echo_of(h.fences[seen]));
        }
    };
    for (int ms = 0; ms < 20'000; ms += 10) {
        h.now += 10 * kMs;
        backlog_bytes = std::max(0.0, backlog_bytes - 1000.0);  // 100 kB/s
        while (h.offer_data()) {
            backlog_bytes += static_cast<double>(data_packet().size());
            stamp_new_fences();
        }
        h.tick();
        stamp_new_fences();
        std::sort(in_flight.begin(), in_flight.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        while (!in_flight.empty() && in_flight.front().first <= h.now) {
            h.deliver(in_flight.front().second);
            in_flight.pop_front();
        }
    }
    const auto v = h.view();
    EXPECT_EQ(v.phase, Gate::Phase::Active);
    EXPECT_GT(v.rate_bps, 50'000.0);
    EXPECT_GT(v.budget, Gate::Config{}.floor_bytes) << "the budget follows the measured BDP";
    EXPECT_LT(v.budget, 200'000u) << "~ rate x (RTT + 50 ms) x 1.5, not unbounded";
}

TEST(FriendSendGateTest, ProbeRttEndsOnAZeroBacklogEchoEvenWithoutAnExactSample) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 100 * kMs;
    h.deliver(echo_of(h.fences.back()));  // trusted sample, ACTIVE
    // Keep it backlogged — every fence goes out with a queue, so no sample is
    // trusted — until the probe starts.
    for (int i = 0; i < 200 && !h.view().probing; ++i) {
        h.now += 100 * kMs;
        h.fill();
        h.tick();
        if (!h.view().probing) {
            h.deliver(echo_of(h.fences.back()));
        }
    }
    ASSERT_TRUE(h.view().probing) << "no trusted sample for 10 s while backlogged";
    EXPECT_FALSE(h.offer_data()) << "the probe refuses DATA so the friend drains";
    // Drain: echo the newest fence (covers all debt).
    h.deliver(echo_of(h.fences.back()));
    ASSERT_EQ(h.view().delivered, h.view().emitted);
    // Alternating loss: the range's first fence (the exact sample) is lost, a
    // later fence of the same range is echoed.
    std::size_t before = h.fences.size();
    h.now += 10 * kMs;
    h.tick();  // zero-backlog fence (lo)
    ASSERT_EQ(h.fences.size(), before + 1);
    h.now += 600 * kMs;
    h.tick();  // recovery fence, same range
    ASSERT_GE(h.fences.size(), before + 2);
    h.deliver(echo_of(h.fences.back()));  // not lo: credit, no exact sample
    h.tick();
    EXPECT_FALSE(h.view().probing) << "a zero-backlog echo ends the probe";
    EXPECT_TRUE(h.offer_data());
}

TEST(FriendSendGateTest, FriendNumberReuseNeverCarriesAcrossKeys) {
    Harness h;
    h.fill();
    ASSERT_FALSE(h.offer_data());
    // Friend 1 deleted; the number is handed to a different key.
    h.gate.forget_friend_number(1);
    h.keys[1] = key_of(2);
    EXPECT_TRUE(h.offer_data()) << "the new friend starts with its own ledger";
    // The old key re-added under another number keeps its debt.
    h.keys[5] = key_of(1);
    EXPECT_FALSE(h.offer_data(5));
}

TEST(FriendSendGateTest, RestoredFriendIsResolvedLazily) {
    Harness h;  // friend 1 was never "added" in this process
    EXPECT_TRUE(h.offer_data());
    EXPECT_TRUE(h.gate.view(key_of(1)).has_value());
}

TEST(FriendSendGateTest, UnknownFriendIsNotGated) {
    Harness h;
    EXPECT_TRUE(h.offer_data(/*fn=*/77));
}

// --- Implementation-review regressions -------------------------------------

TEST(FriendSendGateTest, BunchedLateEchoesCannotReadAsABurstRate) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 200 * kMs;
    h.deliver(echo_of(h.fences.back()));  // ACTIVE
    // Two fences, each sent with a backlog, echoed 5 s later 5 ms apart.
    h.fill();
    h.tick();
    const auto backlog1 = h.view().emitted - h.view().delivered;
    const auto f1 = h.fences.back();
    h.now += 50 * kMs;
    h.deliver(echo_of(f1));
    h.fill();
    h.tick();
    const auto f2 = h.fences.back();
    h.now += 5 * kSec;
    h.deliver(echo_of(f2));
    h.now += 5 * kMs;
    // Whatever arrives bunched, no sample may exceed bytes-outstanding over
    // that fence's own round trip.
    EXPECT_LE(h.view().rate_bps, static_cast<double>(backlog1) / 0.05 * 1.01);
    EXPECT_LT(h.view().rate_bps, 400'000.0);
}

TEST(FriendSendGateTest, RateEstimateExpiresWhenIdle) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 100 * kMs;
    h.deliver(echo_of(h.fences.back()));
    h.fill();
    h.tick();
    h.now += 100 * kMs;
    h.deliver(echo_of(h.fences.back()));
    ASSERT_GT(h.view().rate_bps, 0.0);
    h.now += 30 * kSec;
    h.tick();
    EXPECT_EQ(h.view().rate_bps, 0.0) << "two silent buckets: back to the floor";
    EXPECT_EQ(h.view().budget, Gate::Config{}.floor_bytes);
}

TEST(FriendSendGateTest, UntrustedSamplesNeverGrowTheBudget) {
    Harness h;
    // Bootstrap fence goes out with a full floor of backlog (untrusted).
    for (int i = 0; i < 20; ++i) {
        h.fill();
        h.now += 10 * kMs;
        h.tick();
        h.now += 300 * kMs;
        if (!h.fences.empty()) {
            // Echo only the newest (high backlog) fences; lo samples untrusted.
            h.deliver(echo_of(h.fences.back()));
        }
    }
    if (h.view().base_rtt_us == 0) {
        EXPECT_EQ(h.view().budget, Gate::Config{}.floor_bytes);
    }
}

TEST(FriendSendGateTest, AnotherPeersEchoNeverCreditsThisPeer) {
    Harness h;
    h.keys[2] = key_of(2);
    h.fill(1);
    h.tick();
    const auto a_fence = h.fences.back();
    h.fill(2);
    h.tick();
    const auto b_fence = h.fences.back();
    ASSERT_NE(a_fence, b_fence);
    h.deliver(echo_of(b_fence), /*fn=*/1);  // B's echo arriving as A's
    EXPECT_EQ(h.view(1).delivered, 0u);
    h.deliver(echo_of(a_fence), /*fn=*/1);
    EXPECT_GT(h.view(1).delivered, 0u);
}

TEST(FriendSendGateTest, AFailedFenceSendConsumesNoSequence) {
    Harness h;
    h.fill();
    h.send_ok = false;
    h.tick();
    h.send_ok = true;
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    EXPECT_EQ(seq_of(h.fences.front()), 1u) << "only accepted fences take a seq";
}

TEST(FriendSendGateTest, ThinningKeepsTheOldestAndNewestEntries) {
    Gate::Config cfg;
    // Distinct snapshots only arise while DATA is admitted (about four per
    // budget), so a small cap is what exercises the thinning.
    cfg.max_ledger_entries = 3;
    Harness h(cfg);
    h.fill();
    h.tick();
    h.deliver(echo_of(h.fences.back()));  // ACTIVE
    const std::size_t first = h.fences.size();
    for (int i = 0; i < 40; ++i) {
        h.offer_data();  // one new snapshot per fence: distinct entries
        h.now += 10 * kMs;
        h.tick();
        if (h.fences.size() == first) {
            continue;
        }
        ASSERT_LE(h.view().entries, cfg.max_ledger_entries);
    }
    ASSERT_GT(h.fences.size(), first + cfg.max_ledger_entries);
    // The oldest retained entry is the first fence after activation; its echo
    // still credits.
    const auto before = h.view().delivered;
    h.deliver(echo_of(h.fences[first]));
    EXPECT_GT(h.view().delivered, before);
}

TEST(FriendSendGateTest, ProbeDoesNotReenterRightAfterANonExactExit) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 100 * kMs;
    h.deliver(echo_of(h.fences.back()));
    for (int i = 0; i < 200 && !h.view().probing; ++i) {
        h.now += 100 * kMs;
        h.fill();
        h.tick();
        if (!h.view().probing) {
            h.deliver(echo_of(h.fences.back()));
        }
    }
    ASSERT_TRUE(h.view().probing);
    h.deliver(echo_of(h.fences.back()));
    h.now += 10 * kMs;
    h.tick();  // zero-backlog lo, lost
    h.now += 600 * kMs;
    h.tick();  // same range
    h.deliver(echo_of(h.fences.back()));
    h.tick();
    ASSERT_FALSE(h.view().probing);
    // Backlogged again, all fences untrusted, for 5 s: no new probe yet.
    for (int i = 0; i < 50; ++i) {
        h.now += 100 * kMs;
        h.fill();
        h.tick();
        EXPECT_FALSE(h.view().probing) << "at most one probe per probe_after_ns";
        h.deliver(echo_of(h.fences.back()));
    }
}

TEST(FriendSendGateTest, RearmedLegacyDetectionStartsFromFreshEvidence) {
    Harness h;
    h.fill();
    h.tick();
    h.deliver(lossless(ProtocolFrame::make_pong()));  // answered a fence plainly
    ASSERT_EQ(h.view().phase, Gate::Phase::Legacy);
    h.gate.on_connection_status(h.io, 1, true, h.now);
    // The upgraded peer: a keepalive PING goes out, then fences; the
    // keepalive's plain PONG returns first.
    h.gate.on_accepted(h.io, 1, lossless(ProtocolFrame::make_ping()), h.now);
    h.fill();
    h.tick();
    h.deliver(lossless(ProtocolFrame::make_pong()));
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap) << "that PONG answered the keepalive";
    h.deliver(echo_of(h.fences.back()));
    EXPECT_EQ(h.view().phase, Gate::Phase::Active);
}

TEST(FriendSendGateTest, AnActivePeerRestartedOnAnOlderReleaseIsDetectedAgain) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 300 * kMs;
    h.deliver(echo_of(h.fences.back()));
    ASSERT_EQ(h.view().phase, Gate::Phase::Active);
    // More DATA, then the peer goes away with it unanswered.
    h.fill();
    h.tick();
    const auto debt = h.view().emitted - h.view().delivered;
    ASSERT_GT(debt, 0u);
    h.gate.on_connection_status(h.io, 1, false, h.now);
    h.now += 2 * kSec;
    h.gate.on_connection_status(h.io, 1, true, h.now);
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap);
    EXPECT_EQ(h.view().emitted - h.view().delivered, debt) << "the accounting survives";
    // Back on an older release: it answers our fences plainly. The first
    // fence goes out on the next blocked tick, not after the old backoff.
    ASSERT_FALSE(h.offer_data()) << "the debt exceeds the bootstrap floor";
    const auto before = h.fences.size();
    h.now += 1 * kMs;
    h.tick();
    ASSERT_GT(h.fences.size(), before) << "a post-reconnect fence was sent";
    h.deliver(lossless(ProtocolFrame::make_pong()));
    EXPECT_EQ(h.view().phase, Gate::Phase::Legacy);
    EXPECT_TRUE(h.offer_data()) << "an ungated peer is never stalled by debt it cannot answer";
}

TEST(FriendSendGateTest, AnActivePeerThatStillEchoesReactivatesWithItsDebtCovered) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 300 * kMs;
    h.deliver(echo_of(h.fences.back()));
    h.fill();
    h.gate.on_connection_status(h.io, 1, true, h.now);
    ASSERT_EQ(h.view().phase, Gate::Phase::Bootstrap);
    h.now += 600 * kMs;
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    h.now += 300 * kMs;
    h.deliver(echo_of(h.fences.back()));
    const auto v = h.view();
    EXPECT_EQ(v.phase, Gate::Phase::Active);
    EXPECT_EQ(v.delivered, v.emitted);
}

TEST(FriendSendGateTest, ARearmedPeerWhoseEchoIsSlowIsNotCondemnedByTheShortTimeout) {
    Harness h;
    h.fill();
    h.tick();
    h.now += 300 * kMs;
    h.deliver(echo_of(h.fences.back()));
    h.fill();
    h.gate.on_connection_status(h.io, 1, true, h.now);
    (void)h.offer_data();
    h.now += 1 * kMs;
    h.tick();
    ASSERT_FALSE(h.fences.empty());
    const auto fence = h.fences.back();
    // Eleven seconds of silence behind a backlog: past the first-contact
    // timeout, well inside the re-armed one.
    for (int i = 0; i < 110; ++i) {
        h.now += 100 * kMs;
        (void)h.offer_data();
        h.tick();
    }
    EXPECT_EQ(h.view().phase, Gate::Phase::Bootstrap);
    h.deliver(echo_of(fence));
    EXPECT_EQ(h.view().phase, Gate::Phase::Active);
    // Silence does still end it eventually.
    h.fill();
    h.gate.on_connection_status(h.io, 1, true, h.now);
    for (int i = 0; i < 700 && h.view().phase != Gate::Phase::Legacy; ++i) {
        h.now += 100 * kMs;
        (void)h.offer_data();
        h.tick();
    }
    EXPECT_EQ(h.view().phase, Gate::Phase::Legacy);
}

TEST(FriendSendGateTest, FastRejectMirrorsTheGateForDataOnly) {
    Harness h;
    EXPECT_FALSE(h.gate.fast_reject(1, data_packet()));
    h.fill();
    EXPECT_TRUE(h.gate.fast_reject(1, data_packet()));
    EXPECT_FALSE(h.gate.fast_reject(1, lossless(ProtocolFrame::make_tunnel_ack(3, 1))));
    h.tick();
    h.deliver(echo_of(h.fences.back()));
    EXPECT_FALSE(h.gate.fast_reject(1, data_packet())) << "credit reopens the hint";
}

TEST(FriendSendGateTest, FastPathRefusalsStillCountAsDemand) {
    Harness h;
    h.fill();
    h.tick();
    h.deliver(echo_of(h.fences.back()));  // ACTIVE
    h.fill();
    h.tick();
    const auto fences = h.fences.size();
    // From now on the tunnel only ever hears the fast path.
    for (int i = 0; i < 40; ++i) {
        h.now += 250 * kMs;
        ASSERT_TRUE(h.gate.fast_reject(1, data_packet()));
        h.tick();
    }
    EXPECT_GT(h.fences.size(), fences) << "recovery fences keep going on fast-path demand";
}

TEST(FriendSendGateTest, ReArmedDetectionStartsOnFastPathDemand) {
    Harness h;
    h.fill();
    h.tick();
    h.deliver(lossless(ProtocolFrame::make_pong()));
    ASSERT_EQ(h.view().phase, Gate::Phase::Legacy);
    for (int i = 0; i < 20; ++i) {
        h.offer_data();  // ungated: debt piles up
    }
    h.gate.on_connection_status(h.io, 1, true, h.now);
    const auto fences = h.fences.size();
    h.tick();  // closes the hint before any admit() refusal
    ASSERT_TRUE(h.gate.fast_reject(1, data_packet()));
    h.now += 10 * kMs;
    h.tick();
    EXPECT_GT(h.fences.size(), fences) << "the first fence of the re-armed detection goes out";
    h.now += 11 * kSec;
    h.tick();
    EXPECT_EQ(h.view().phase, Gate::Phase::Legacy) << "and its timeout can run";
}

TEST(FriendSendGateTest, CompressedEchoesOfAConstantSerializerReadAsItsRate) {
    // 6000 B/s serializer, 160 ms one way; echoes held back and released in
    // bunches every 2 s (reverse-path compression).
    Harness h;
    double delivered_at = 0;  // when the serializer frees up
    std::vector<std::pair<std::int64_t, std::vector<std::uint8_t>>> pending;
    std::size_t seen = 0;
    const auto stamp = [&] {
        for (; seen < h.fences.size(); ++seen) {
            // The fence is delivered once every byte before it has crossed.
            pending.emplace_back(static_cast<std::int64_t>(delivered_at) + 160 * kMs,
                                 echo_of(h.fences[seen]));
        }
    };
    for (int ms = 0; ms < 60'000; ms += 10) {
        h.now += 10 * kMs;
        while (h.offer_data()) {
            delivered_at = std::max(delivered_at, static_cast<double>(h.now)) +
                           static_cast<double>(data_packet().size()) / 6000.0 * 1e9;
            stamp();
        }
        h.tick();
        stamp();
        if (ms % 2000 == 0) {  // release every echo due by now, at once
            std::vector<std::pair<std::int64_t, std::vector<std::uint8_t>>> keep;
            for (auto& [due, pong] : pending) {
                if (due + 160 * kMs <= h.now) {
                    h.deliver(pong);
                } else {
                    keep.emplace_back(due, pong);
                }
            }
            pending.swap(keep);
        }
    }
    EXPECT_LT(h.view().rate_bps, 6000.0 * 1.25) << "bunched echoes must not read as a burst";
}

TEST(FriendSendGateTest, TheHintAdmitsASmallFrameThatFits) {
    Harness h;
    h.fill();  // leaves less than one full frame of room
    const auto small = data_packet(100);
    const bool admit_small = h.gate.admit(h.io, 1, small, h.now);
    EXPECT_EQ(h.gate.fast_reject(1, small), !admit_small)
        << "the hint must agree with admit() for the packet's real size";
}

TEST(PongEchoTest, PongEchoesSmallPingPayloadsOnly) {
    const auto fence = Gate::make_fence_packet(5, 6);
    auto ping = ProtocolFrame::deserialize(
        std::span<const std::uint8_t>(fence.data() + 1, fence.size() - 1));
    ASSERT_TRUE(ping.has_value());
    const auto pong = ProtocolFrame::make_pong_for(ping.value());
    EXPECT_EQ(pong.type(), FrameType::PONG);
    ASSERT_EQ(pong.payload().size(), kFencePayloadSize);
    EXPECT_TRUE(std::equal(pong.payload().begin(), pong.payload().end(), fence.begin() + 6));

    EXPECT_TRUE(ProtocolFrame::make_pong_for(ProtocolFrame::make_ping()).payload().empty());
}

TEST(PongEchoTest, TheManagerEchoesAFenceAndAnswersAPlainPingPlainly) {
    asio::io_context io_ctx;
    TunnelManager mgr(io_ctx);
    std::vector<std::vector<std::uint8_t>> sent;
    mgr.set_send_handler([&sent](const std::vector<std::uint8_t>& wire) {
        sent.push_back(wire);
        return SendOutcome::Sent;
    });
    const auto fence = Gate::make_fence_packet(9, 10);
    auto ping = ProtocolFrame::deserialize(
        std::span<const std::uint8_t>(fence.data() + 1, fence.size() - 1));
    ASSERT_TRUE(ping.has_value());
    mgr.route_frame(ping.value());
    mgr.route_frame(ProtocolFrame::make_ping());
    ASSERT_EQ(sent.size(), 2u);
    auto echo = ProtocolFrame::deserialize(sent[0]);
    ASSERT_TRUE(echo.has_value());
    EXPECT_EQ(echo.value().type(), FrameType::PONG);
    ASSERT_EQ(echo.value().payload().size(), kFencePayloadSize);
    EXPECT_TRUE(std::equal(echo.value().payload().begin(), echo.value().payload().end(),
                           fence.begin() + 6));
    auto plain = ProtocolFrame::deserialize(sent[1]);
    ASSERT_TRUE(plain.has_value());
    EXPECT_TRUE(plain.value().payload().empty());
}

}  // namespace
}  // namespace toxtunnel::tunnel
