#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>

namespace toxtunnel::tox {

/// A hook at ToxAdapter's lossless-packet boundary (issue #42).
///
/// ToxAdapter calls every method with its `tox_mutex_` held — i.e. serialized
/// with every toxcore call, on whichever thread is running toxcore at that
/// moment (the Tox thread, or the caller's thread on the inline path while the
/// adapter is stopping). That is the point: admission, the toxcore enqueue and
/// the bookkeeping of what was enqueued happen in one critical section, in
/// exactly the order toxcore puts packets on the friend's ordered stream.
/// Implementations must not call back into ToxAdapter; what they need from
/// toxcore comes through `Io`, whose functions assume the lock is held.
///
/// ToxAdapter itself stays frame-agnostic: `packet` is the full lossless
/// packet as handed to / received from toxcore, custom-packet prefix included.
class LosslessSendGate {
   public:
    using PublicKey = std::array<std::uint8_t, 32>;

    /// What a gate may ask of toxcore. Both functions run under tox_mutex_.
    struct Io {
        /// The friend's long-term public key, or nullopt if the number is unknown.
        std::function<std::optional<PublicKey>(std::uint32_t friend_number)> public_key;
        /// Hand a packet straight to toxcore; true when toxcore accepted it.
        std::function<bool(std::uint32_t friend_number, std::span<const std::uint8_t> packet)> send;
    };

    virtual ~LosslessSendGate() = default;

    /// May this packet be handed to toxcore now? False makes ToxAdapter report
    /// SENDQ-full to the caller without touching toxcore.
    virtual bool admit(const Io& io, std::uint32_t friend_number,
                       std::span<const std::uint8_t> packet, std::int64_t now_ns) = 0;

    /// toxcore accepted `packet` (called right after the enqueue, same lock).
    virtual void on_accepted(const Io& io, std::uint32_t friend_number,
                             std::span<const std::uint8_t> packet, std::int64_t now_ns) = 0;

    /// A lossless packet arrived from the friend (inside tox_iterate).
    virtual void on_received(const Io& io, std::uint32_t friend_number,
                             std::span<const std::uint8_t> packet, std::int64_t now_ns) = 0;

    /// The friend's connection status changed (inside tox_iterate).
    virtual void on_connection_status(const Io& io, std::uint32_t friend_number, bool connected,
                                      std::int64_t now_ns) = 0;

    /// Called after every tox_iterate: the gate's own deadlines and sends.
    virtual void on_tick(const Io& io, std::int64_t now_ns) = 0;

    /// The friend number was deleted, or handed out again by an add: whatever
    /// the gate cached for that NUMBER no longer describes the same friend.
    virtual void forget_friend_number(std::uint32_t friend_number) = 0;
};

}  // namespace toxtunnel::tox
