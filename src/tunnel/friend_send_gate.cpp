#include "toxtunnel/tunnel/friend_send_gate.hpp"

#include <algorithm>
#include <random>

#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::tunnel {

namespace {

constexpr std::int64_t kMinRttBucketNs = 10'000'000'000;
/// DATA refused within this window counts as "blocked" (demand exists).
constexpr std::int64_t kBlockedWindowNs = 1'000'000'000;
/// Progress fences: a quarter budget apart, never closer than two frames.
/// Several fences per budget keep credit flowing while DATA is admitted; a
/// single fence per budget would turn the gate into stop-and-wait at
/// budget / RTT.
constexpr std::uint64_t kMinFenceIntervalBytes = 2 * 1372;
constexpr std::uint64_t kFencesPerBudget = 4;

std::uint64_t read_u64_be(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

void write_u64_be(std::uint8_t* out, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
    }
}

/// The parts of a lossless packet the gate looks at: prefix byte, then the
/// 5-byte frame header ([type][tunnel_id:2][length:2]), then the payload.
struct Peek {
    FrameType type;
    std::uint16_t tunnel_id;
    std::span<const std::uint8_t> payload;
};

std::optional<Peek> peek(std::span<const std::uint8_t> packet) noexcept {
    if (packet.size() < 1 + kFrameHeaderSize || packet[0] != kLosslessPacketByte) {
        return std::nullopt;
    }
    const auto tunnel_id = static_cast<std::uint16_t>((packet[2] << 8) | packet[3]);
    const std::size_t len = (static_cast<std::size_t>(packet[4]) << 8) | packet[5];
    if (packet.size() < 1 + kFrameHeaderSize + len) {
        return std::nullopt;
    }
    return Peek{static_cast<FrameType>(packet[1]), tunnel_id,
                packet.subspan(1 + kFrameHeaderSize, len)};
}

std::uint64_t random_epoch() {
    std::random_device rd;
    return (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
}

}  // namespace

FriendSendGate::FriendSendGate(Config cfg, std::uint64_t epoch) : cfg_(cfg), epoch_(epoch) {}

FriendSendGate::FriendSendGate() : FriendSendGate(Config{}, random_epoch()) {}

std::vector<std::uint8_t> FriendSendGate::make_fence_packet(std::uint64_t epoch,
                                                            std::uint64_t seq) {
    std::vector<std::uint8_t> p(1 + kFrameHeaderSize + kFencePayloadSize);
    p[0] = kLosslessPacketByte;
    p[1] = static_cast<std::uint8_t>(FrameType::PING);
    p[2] = 0;  // tunnel id 0: the control plane
    p[3] = 0;
    p[4] = 0;
    p[5] = static_cast<std::uint8_t>(kFencePayloadSize);
    p[6] = kFencePingKind;
    write_u64_be(&p[7], epoch);
    write_u64_be(&p[15], seq);
    return p;
}

FriendSendGate::Ledger* FriendSendGate::ledger_for(const Io& io, std::uint32_t friend_number) {
    auto it = number_to_key_.find(friend_number);
    if (it == number_to_key_.end()) {
        if (!io.public_key) {
            return nullptr;
        }
        auto key = io.public_key(friend_number);
        if (!key) {
            return nullptr;
        }
        it = number_to_key_.emplace(friend_number, *key).first;
    }
    Ledger& l = ledgers_[it->second];
    l.friend_number = friend_number;
    return &l;
}

std::int64_t FriendSendGate::base_rtt_us(const Ledger& l) const noexcept {
    std::int64_t m = l.cur_bucket_min_us;
    if (l.prev_bucket_min_us != 0 && (m == 0 || l.prev_bucket_min_us < m)) {
        m = l.prev_bucket_min_us;
    }
    return m;
}

std::uint64_t FriendSendGate::budget(const Ledger& l) const noexcept {
    if (l.phase != Phase::Active) {
        return cfg_.floor_bytes;
    }
    std::int64_t rtt = base_rtt_us(l);
    if (rtt <= 0) {
        rtt = l.srtt_us;
    }
    if (rtt <= 0 || l.rate_bps <= 0.0) {
        return cfg_.floor_bytes;
    }
    const double bytes = l.rate_bps * static_cast<double>(rtt + cfg_.queue_budget_us) / 1e6 *
                         static_cast<double>(cfg_.safety_factor_x100) / 100.0;
    if (bytes >= static_cast<double>(cfg_.max_bytes)) {
        return cfg_.max_bytes;
    }
    return std::max(cfg_.floor_bytes, static_cast<std::uint64_t>(bytes));
}

bool FriendSendGate::admit(const Io& io, std::uint32_t friend_number,
                           std::span<const std::uint8_t> packet, std::int64_t now_ns) {
    const auto pk = peek(packet);
    // The control lane: everything but DATA goes straight through.
    if (!pk || pk->type != FrameType::TUNNEL_DATA) {
        return true;
    }
    Ledger* l = ledger_for(io, friend_number);
    if (l == nullptr || l->phase == Phase::Legacy) {
        return true;
    }
    const std::uint64_t size = packet.size();
    const std::uint64_t backlog = l->emitted - l->delivered;
    bool ok = false;
    if (!l->probing) {
        // A frame always fits an empty pipe, so a budget smaller than one
        // frame still makes progress.
        ok = backlog == 0 || backlog + size <= budget(*l);
    }
    if (!ok) {
        l->last_refused_ns = now_ns;
        l->refused_since_credit = true;
        util::MetricsRegistry::instance().inc_friend_gate_refusals();
    }
    return ok;
}

void FriendSendGate::on_accepted(const Io& io, std::uint32_t friend_number,
                                 std::span<const std::uint8_t> packet, std::int64_t now_ns) {
    const auto pk = peek(packet);
    if (!pk) {
        return;
    }
    if (pk->type == FrameType::TUNNEL_DATA) {
        if (Ledger* l = ledger_for(io, friend_number)) {
            l->emitted += packet.size();
            // Progress fence right behind the DATA that completes an interval:
            // several fences per budget keep credit flowing, and echoes spaced
            // by the bottleneck's own serialization give the rate samples the
            // max filter needs. Same critical section, so stream order holds.
            if (l->phase != Phase::Legacy && l->emitted - l->last_fenced >= fence_interval(*l)) {
                (void)send_fence(io, *l, now_ns);
            }
        }
    } else if (pk->type == FrameType::PING && pk->tunnel_id == 0 && pk->payload.empty()) {
        // A keepalive PING: its reply is an empty PONG, which must not be
        // mistaken for a legacy peer answering one of our fences.
        if (Ledger* l = ledger_for(io, friend_number)) {
            ++l->empty_pings_sent;
        }
    }
}

void FriendSendGate::on_received(const Io& io, std::uint32_t friend_number,
                                 std::span<const std::uint8_t> packet, std::int64_t now_ns) {
    const auto pk = peek(packet);
    if (!pk || pk->type != FrameType::PONG || pk->tunnel_id != 0) {
        return;
    }
    Ledger* l = ledger_for(io, friend_number);
    if (l == nullptr) {
        return;
    }
    if (pk->payload.empty()) {
        ++l->empty_pongs_received;
        // More empty PONGs than empty PINGs we sent: one of them answered a
        // fence, so the peer does not echo.
        if (l->phase == Phase::Bootstrap && !l->entries.empty() &&
            l->empty_pongs_received > l->empty_pings_sent) {
            enter_legacy(*l, "the peer answered a fence with a plain PONG");
        }
        return;
    }
    if (pk->payload.size() != kFencePayloadSize || pk->payload[0] != kFencePingKind ||
        read_u64_be(&pk->payload[1]) != epoch_) {
        return;  // not ours: another process's fence, or a stranger's payload
    }
    const std::uint64_t seq = read_u64_be(&pk->payload[9]);
    for (std::size_t i = 0; i < l->entries.size(); ++i) {
        const Range r = l->entries[i];
        if (seq >= r.lo && seq <= r.hi) {
            // This entry and every older one are settled: their bytes are all
            // <= this snapshot, and their late echoes then match nothing.
            l->entries.erase(l->entries.begin(),
                             l->entries.begin() + static_cast<std::ptrdiff_t>(i) + 1);
            credit(*l, r, seq, now_ns);
            return;
        }
    }
    // An echo of a thinned-away or already-settled fence: nothing to credit.
}

void FriendSendGate::credit(Ledger& l, const Range& matched, std::uint64_t seq,
                            std::int64_t now_ns) {
    const std::uint64_t delivered = std::max(l.delivered, matched.snapshot);
    if (delivered > l.delivered) {
        // A delivery-rate sample only when the gate held demand back in the
        // interval; an application-limited interval measures the application.
        if (l.refused_since_credit && l.last_credit_ns > 0 && now_ns > l.last_credit_ns) {
            observe_rate(l,
                         static_cast<double>(delivered - l.delivered) * 1e9 /
                             static_cast<double>(now_ns - l.last_credit_ns),
                         now_ns);
        }
        l.delivered = delivered;
        l.last_credit_ns = now_ns;
        l.refused_since_credit = false;
    } else if (l.last_credit_ns == 0) {
        l.last_credit_ns = now_ns;
    }
    if (seq == matched.lo) {
        // The one fence of the range whose send time is exact.
        observe_rtt(l, (now_ns - matched.lo_sent_ns) / 1000,
                    matched.lo_backlog <= cfg_.trusted_backlog_bytes, now_ns);
    }
    if (l.probing && matched.lo_backlog == 0) {
        // A fence sent on an empty pipe was answered: the probe has drained
        // the friend even when this particular echo carries no exact sample.
        l.probe_released = true;
    }
    if (l.phase == Phase::Bootstrap) {
        l.phase = Phase::Active;
        l.activated_ns = now_ns;
        util::Logger::debug("Friend gate: friend {} echoes fences; gating its DATA",
                            l.friend_number);
    }
    l.recovery_interval_ns = 0;
    l.next_recovery_ns = 0;
}

void FriendSendGate::observe_rate(Ledger& l, double bps, std::int64_t now_ns) {
    if (l.rate_bucket_start_ns == 0 || now_ns - l.rate_bucket_start_ns >= kMinRttBucketNs) {
        const bool adjacent =
            l.rate_bucket_start_ns != 0 && now_ns - l.rate_bucket_start_ns < 2 * kMinRttBucketNs;
        l.rate_prev_max = adjacent ? l.rate_cur_max : 0.0;
        l.rate_cur_max = 0.0;
        l.rate_bucket_start_ns = now_ns;
    }
    l.rate_cur_max = std::max(l.rate_cur_max, bps);
    l.rate_bps = std::max(l.rate_cur_max, l.rate_prev_max);
}

std::uint64_t FriendSendGate::fence_interval(const Ledger& l) const noexcept {
    return std::max(kMinFenceIntervalBytes, budget(l) / kFencesPerBudget);
}

void FriendSendGate::observe_rtt(Ledger& l, std::int64_t rtt_us, bool trusted,
                                 std::int64_t now_ns) {
    if (rtt_us <= 0) {
        rtt_us = 1;
    }
    l.srtt_us = l.srtt_us > 0 ? (7 * l.srtt_us + rtt_us) / 8 : rtt_us;
    if (!trusted) {
        return;
    }
    if (l.bucket_start_ns == 0 || now_ns - l.bucket_start_ns >= kMinRttBucketNs) {
        const bool adjacent =
            l.bucket_start_ns != 0 && now_ns - l.bucket_start_ns < 2 * kMinRttBucketNs;
        l.prev_bucket_min_us = adjacent ? l.cur_bucket_min_us : 0;
        l.cur_bucket_min_us = 0;
        l.bucket_start_ns = now_ns;
    }
    if (l.cur_bucket_min_us == 0 || rtt_us < l.cur_bucket_min_us) {
        l.cur_bucket_min_us = rtt_us;
    }
    l.last_trusted_ns = now_ns;
    if (l.probing) {
        l.probe_released = true;
    }
}

void FriendSendGate::record_fence(Ledger& l, std::uint64_t seq, std::int64_t now_ns) {
    if (!l.entries.empty() && l.entries.back().snapshot == l.emitted) {
        l.entries.back().hi = seq;
    } else {
        l.entries.push_back(Range{seq, seq, l.emitted, now_ns, l.emitted - l.delivered});
    }
    if (l.entries.size() > cfg_.max_ledger_entries) {
        // Thin the middle, never the ends: the oldest entry is the next echo
        // to arrive, the newest holds the current debt (an outage's fences all
        // extend it). Dropping an entry never advances `delivered`.
        std::deque<Range> kept;
        kept.push_back(l.entries.front());
        for (std::size_t i = 1; i + 1 < l.entries.size(); ++i) {
            if (i % 2 == 0) {
                kept.push_back(l.entries[i]);
            }
        }
        kept.push_back(l.entries.back());
        l.entries.swap(kept);
    }
    l.last_fenced = l.emitted;
    if (l.first_fence_ns == 0) {
        l.first_fence_ns = now_ns;
    }
}

bool FriendSendGate::send_fence(const Io& io, Ledger& l, std::int64_t now_ns) {
    if (!io.send) {
        return false;
    }
    const std::uint64_t seq = next_seq_++;
    const auto packet = make_fence_packet(epoch_, seq);
    if (!io.send(l.friend_number, packet)) {
        return false;  // SENDQ or offline: the next tick tries again
    }
    record_fence(l, seq, now_ns);
    return true;
}

void FriendSendGate::enter_legacy(Ledger& l, const char* why) {
    l.phase = Phase::Legacy;
    l.entries.clear();
    l.probing = false;
    util::MetricsRegistry::instance().inc_friend_gate_legacy();
    util::Logger::info("Friend gate: friend {} is not gated ({})", l.friend_number, why);
}

void FriendSendGate::on_connection_status(const Io& io, std::uint32_t friend_number, bool connected,
                                          std::int64_t /*now_ns*/) {
    if (!connected) {
        return;  // accounting survives: NONE does not prove the stream is gone
    }
    if (Ledger* l = ledger_for(io, friend_number); l != nullptr && l->phase == Phase::Legacy) {
        // A reconnect may be an upgraded peer: detect again.
        l->phase = Phase::Bootstrap;
        l->first_fence_ns = 0;
    }
}

void FriendSendGate::on_tick(const Io& io, std::int64_t now_ns) {
    for (auto& [key, l] : ledgers_) {
        if (l.phase == Phase::Legacy) {
            continue;
        }
        // Only a ledger whose number still names this key may send.
        const auto it = number_to_key_.find(l.friend_number);
        if (it == number_to_key_.end() || it->second != key) {
            continue;
        }
        if (l.phase == Phase::Bootstrap && l.first_fence_ns > 0 &&
            now_ns - l.first_fence_ns > cfg_.legacy_timeout_ns) {
            enter_legacy(l, "no fence echo");
            continue;
        }
        const bool blocked = l.last_refused_ns > 0 && now_ns - l.last_refused_ns < kBlockedWindowNs;
        const std::int64_t trusted_ref = l.last_trusted_ns > 0 ? l.last_trusted_ns : l.activated_ns;
        if (l.phase == Phase::Active && !l.probing && blocked && trusted_ref > 0 &&
            now_ns - trusted_ref > cfg_.probe_after_ns) {
            // Every recent sample carried a queue: drain and measure again.
            l.probing = true;
            l.probe_released = false;
        }
        if (l.probing && l.probe_released && l.delivered == l.emitted) {
            l.probing = false;
        }

        bool want = false;
        bool recovery = false;
        const bool covered = !l.entries.empty() && l.entries.back().snapshot == l.emitted;
        if (l.probing && l.delivered == l.emitted &&
            !(covered && l.entries.back().lo_backlog == 0)) {
            want = true;  // the probe's zero-backlog fence
        } else if (l.emitted - l.last_fenced >= fence_interval(l)) {
            want = true;  // progress
        } else if ((blocked || l.probing) && !covered && l.emitted > l.delivered) {
            want = true;  // nothing outstanding covers the current debt
        } else if ((blocked || l.probing) && !l.entries.empty() && now_ns >= l.next_recovery_ns) {
            want = true;  // recovery: replies may have been lost
            recovery = true;
        }
        if (!want || !send_fence(io, l, now_ns)) {
            continue;
        }
        if (recovery || l.recovery_interval_ns == 0) {
            l.recovery_interval_ns =
                l.recovery_interval_ns == 0
                    ? cfg_.recovery_base_ns
                    : std::min(l.recovery_interval_ns * 2, cfg_.recovery_max_ns);
        }
        l.next_recovery_ns = now_ns + l.recovery_interval_ns;
    }
}

void FriendSendGate::forget_friend_number(std::uint32_t friend_number) {
    number_to_key_.erase(friend_number);
}

std::optional<FriendSendGate::View> FriendSendGate::view(const PublicKey& key) const {
    const auto it = ledgers_.find(key);
    if (it == ledgers_.end()) {
        return std::nullopt;
    }
    const Ledger& l = it->second;
    return View{l.phase,          l.emitted, l.delivered,    budget(l),
                l.entries.size(), l.probing, base_rtt_us(l), l.rate_bps};
}

}  // namespace toxtunnel::tunnel
