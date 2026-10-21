#pragma once

#include <array>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "toxtunnel/tox/lossless_send_gate.hpp"

namespace toxtunnel::tunnel {

/// Fence PING payload: [kind][epoch u64 BE][seq u64 BE].
inline constexpr std::uint8_t kFencePingKind = 0x46;  // 'F'
inline constexpr std::size_t kFencePayloadSize = 17;
/// A PONG echoes a PING payload of at most this many bytes (issue #42).
inline constexpr std::size_t kMaxPingEchoBytes = 32;

/// Per-friend DATA gate in front of toxcore (issue #42).
///
/// Every frame for a friend shares toxcore's single ordered lossless stream, and
/// toxcore's own congestion control lets that stream hold up to 64 packets before
/// it reacts — ~88 KB, ~14 s at 6 kB/s — so a TUNNEL_OPEN ACK, a PONG or another
/// tunnel's first bytes queued behind bulk DATA waited that long. A frame toxcore
/// has accepted cannot be overtaken, so the only lever is to keep DATA from
/// piling up inside toxcore in the first place.
///
/// The gate bounds, per friend, the DATA accepted by toxcore but not yet known
/// to be delivered. "Delivered" is learned from correlated fences: a fence is a
/// PING carrying [kind][epoch][seq]; a peer running this change echoes the
/// payload in its PONG. Lossless packets are delivered in stream order, so the
/// echo of fence `seq` proves every byte toxcore accepted before that PING has
/// reached the peer application. Credit is taken ONLY from an exact echo of a
/// fence this process sent — never from an empty (legacy or keepalive) PONG — so
/// lost, late, misrouted or stale replies can never over-credit.
///
/// Admission (`admit`) refuses DATA once `emitted - delivered + frame` would
/// exceed the friend budget; control frames are never refused, so they queue
/// behind at most one budget of DATA. Refused DATA stays in the tunnel's FIFO
/// and the emission driver retries it (SENDQ-full semantics).
///
/// Budget: rate x (base RTT + 50 ms) x 1.5 clamped to [floor, 4 MiB] — the same
/// shape as BdpFlowControl, at friend level. Base RTT is a windowed minimum of
/// TRUSTED fence samples (sent with <= 2 frames of backlog); without a trusted
/// sample for 10 s while backlogged, a ProbeRTT drains the friend to measure
/// again. Peers that never echo are detected (an empty PONG answering a fence,
/// or no echo within 10 s of the first fence) and run ungated, as before.
///
/// Thread-safety: none of its own. Every entry point runs under ToxAdapter's
/// tox_mutex_ (see tox::LosslessSendGate).
class FriendSendGate final : public tox::LosslessSendGate {
   public:
    struct Config {
        /// Smallest budget, and the budget before the first trusted sample.
        /// Friend credit is released by fence echoes, not tunnel ACKs, so this
        /// does not need to cover the receiver's 16 KiB ACK threshold.
        std::uint64_t floor_bytes = 8 * 1372;
        std::uint64_t max_bytes = 4 * 1024 * 1024;
        std::int64_t queue_budget_us = 50'000;
        /// 2x, as BBR's window gain: the rate samples see the pipe through the
        /// gate's own backlog, and below 2x the budget settles short of a full
        /// pipe on a long path.
        std::int64_t safety_factor_x100 = 200;
        /// A fence sent with at most this much backlog measures the path (the
        /// first progress fence goes out two frames in, so it qualifies).
        std::uint64_t trusted_backlog_bytes = 3 * 1372;
        std::size_t max_ledger_entries = 64;
        std::int64_t legacy_timeout_ns = 10'000'000'000;
        std::int64_t probe_after_ns = 10'000'000'000;
        std::int64_t recovery_base_ns = 500'000'000;
        std::int64_t recovery_max_ns = 60'000'000'000;
    };

    enum class Phase : std::uint8_t {
        Bootstrap,  ///< No correlated echo yet: admit up to the floor.
        Active,     ///< Echoes seen: bounded by the budget.
        Legacy,     ///< The peer does not echo: ungated (pre-#42 behaviour).
    };

    /// Read-only state for tests and introspection.
    struct View {
        Phase phase;
        std::uint64_t emitted;
        std::uint64_t delivered;
        std::uint64_t budget;
        std::size_t entries;
        bool probing;
        std::int64_t base_rtt_us;
        double rate_bps;
        std::uint64_t epoch;
    };

    explicit FriendSendGate(Config cfg, std::uint64_t epoch);
    /// Random per-process epoch.
    FriendSendGate();

    bool admit(const Io& io, std::uint32_t friend_number, std::span<const std::uint8_t> packet,
               std::int64_t now_ns) override;
    void on_accepted(const Io& io, std::uint32_t friend_number,
                     std::span<const std::uint8_t> packet, std::int64_t now_ns) override;
    void on_received(const Io& io, std::uint32_t friend_number,
                     std::span<const std::uint8_t> packet, std::int64_t now_ns) override;
    void on_connection_status(const Io& io, std::uint32_t friend_number, bool connected,
                              std::int64_t now_ns) override;
    void on_tick(const Io& io, std::int64_t now_ns) override;
    void forget_friend_number(std::uint32_t friend_number) override;
    [[nodiscard]] bool fast_reject(std::uint32_t friend_number,
                                   std::span<const std::uint8_t> packet) const noexcept override;

    [[nodiscard]] std::optional<View> view(const PublicKey& key) const;
    [[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }

    /// The fence PING wire packet (lossless prefix included).
    [[nodiscard]] static std::vector<std::uint8_t> make_fence_packet(std::uint64_t epoch,
                                                                     std::uint64_t seq);

   private:
    /// Fences sharing one emitted snapshot. While DATA is blocked emitted cannot
    /// advance, so every recovery fence of an outage extends the same entry:
    /// constant memory, and any of their echoes credits it.
    struct Range {
        std::uint64_t lo;
        std::uint64_t hi;
        std::uint64_t snapshot;
        std::int64_t lo_sent_ns;
        std::uint64_t lo_backlog;  ///< emitted - delivered when `lo` was sent
        /// Delivery state when `lo` was sent, for the rate sample (BBR's
        /// P.delivered / P.delivered_time / P.first_sent_time): the credited
        /// bytes, when that credit arrived, and when the fence it came from
        /// had been sent.
        std::uint64_t delivered_at_send;
        std::int64_t credit_ns_at_send;
        std::int64_t credit_sent_ns_at_send;
    };

    struct Ledger {
        std::uint32_t friend_number = 0;
        /// Fences are correlated per ledger: its own random epoch and a seq
        /// that only advances when toxcore accepted a fence, so a range is
        /// exactly the fences this peer was sent, and no other peer's echo
        /// (nor one of an unsent seq) can ever match it.
        std::uint64_t epoch = 0;
        std::uint64_t next_seq = 1;
        std::uint64_t emitted = 0;
        std::uint64_t delivered = 0;
        std::uint64_t last_fenced = 0;
        std::deque<Range> entries;
        Phase phase = Phase::Bootstrap;
        std::int64_t first_fence_ns = 0;
        // Legacy detection: an empty PONG beyond the empty PINGs we sent
        // answered a fence.
        std::uint64_t empty_pings_sent = 0;
        std::uint64_t empty_pongs_received = 0;
        // Demand.
        std::int64_t last_refused_ns = 0;
        /// The last credit: when it arrived and when its fence had been sent.
        std::int64_t last_credit_ns = 0;
        std::int64_t last_credit_sent_ns = 0;
        /// Delivery rate: a windowed MAXIMUM (two 10 s buckets, expiring with
        /// them) of per-fence samples — the bytes outstanding when a fence was
        /// sent over that fence's send-to-echo time. Each sample spans a whole
        /// round trip, so echoes arriving bunched cannot read as a burst rate.
        double rate_bps = 0.0;
        double rate_cur_max = 0.0;
        double rate_prev_max = 0.0;
        std::int64_t rate_bucket_start_ns = 0;
        // RTT.
        std::int64_t srtt_us = 0;
        std::int64_t bucket_start_ns = 0;
        std::int64_t cur_bucket_min_us = 0;
        std::int64_t prev_bucket_min_us = 0;
        std::int64_t last_trusted_ns = 0;
        /// When the friend became Active: the probe clock's start when no
        /// trusted sample has been taken yet (a bootstrap fence usually goes
        /// out with a queue behind it).
        std::int64_t activated_ns = 0;
        // Recovery fences while blocked.
        std::int64_t recovery_interval_ns = 0;
        std::int64_t next_recovery_ns = 0;
        // ProbeRTT.
        bool probing = false;
        bool probe_released = false;
        /// When the last probe ended: the next one is due probe_after_ns later,
        /// even if it ended on an echo that carried no exact RTT sample.
        std::int64_t last_probe_done_ns = 0;
    };

    Ledger* ledger_for(const Io& io, std::uint32_t friend_number);
    [[nodiscard]] std::uint64_t budget(const Ledger& l) const noexcept;
    [[nodiscard]] std::int64_t base_rtt_us(const Ledger& l) const noexcept;
    void credit(Ledger& l, const Range& matched, std::uint64_t seq, std::int64_t now_ns);
    void observe_rtt(Ledger& l, std::int64_t rtt_us, bool trusted, std::int64_t now_ns);
    void observe_rate(Ledger& l, double bps, std::int64_t now_ns);
    void age_rate(Ledger& l, std::int64_t now_ns);
    [[nodiscard]] std::uint64_t fence_interval(const Ledger& l) const noexcept;
    void publish_hint(const Ledger& l);
    [[nodiscard]] std::uint64_t next_ledger_epoch();
    void record_fence(Ledger& l, std::uint64_t seq, std::int64_t now_ns);
    bool send_fence(const Io& io, Ledger& l, std::int64_t now_ns);
    void enter_legacy(Ledger& l, const char* why);

    Config cfg_;
    std::uint64_t epoch_;  ///< per-process seed for the ledgers' epochs
    std::uint64_t ledgers_created_ = 0;
    std::map<PublicKey, Ledger> ledgers_;
    std::unordered_map<std::uint32_t, PublicKey> number_to_key_;
    /// fast_reject()'s view, indexed by friend number (larger numbers simply
    /// never get the fast path): the DATA bytes admit() would accept right
    /// now (kOpen = no limit). Written under tox_mutex_, read lock-free.
    static constexpr std::size_t kHintSlots = 4096;
    static constexpr std::int64_t kOpen = INT64_MAX;
    std::array<std::atomic<std::int64_t>, kHintSlots> hint_room_{};
    /// fast_reject() turned DATA away since the last tick: demand admit() never
    /// saw, folded into the ledger by on_tick (recovery fences, ProbeRTT and
    /// the first fence of a re-armed detection all key off demand).
    mutable std::array<std::atomic<std::uint8_t>, kHintSlots> hint_refused_{};
};

}  // namespace toxtunnel::tunnel
