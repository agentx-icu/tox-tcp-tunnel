#include "toxtunnel/app/tunnel_senders.hpp"

#include <span>
#include <utility>
#include <vector>

#include "toxtunnel/tunnel/protocol.hpp"

namespace toxtunnel::app::detail {

TunnelSenders make_tunnel_senders(TypedLosslessSendFn send_lossless,
                                  std::shared_ptr<tunnel::TunnelManager> manager,
                                  std::uint32_t friend_number) {
    TunnelSenders senders;

    senders.span = [send_lossless, manager,
                    friend_number](std::span<const std::uint8_t> data) -> tunnel::SendOutcome {
        // FIFO barrier, consulted BEFORE toxcore rather than after a refusal.
        // Frame type byte is at offset 0 of the unprefixed wire.
        if (!data.empty() &&
            tunnel::frame_must_respect_outbound_barrier(static_cast<tunnel::FrameType>(data[0])) &&
            manager->outbound_queue_busy()) {
            // Something older is still on its way to toxcore. Report
            // backpressure so the handshake driver retries after it, instead of
            // putting this frame on the wire ahead of it — which for a recycled
            // tunnel id is the stale-CLOSE-kills-the-new-tunnel bug.
            return tunnel::SendOutcome::SendqFull;
        }

        std::vector<std::uint8_t> packet;
        packet.reserve(1 + data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), data.begin(), data.end());

        const auto outcome = send_lossless(friend_number, packet.data(), packet.size());
        if (outcome == tox::ToxAdapter::LosslessSendOutcome::Sent) {
            manager->record_frame_sent();
            manager->record_bytes_sent(data.size());
            return tunnel::SendOutcome::Sent;
        }
        if (outcome == tox::ToxAdapter::LosslessSendOutcome::PermanentFail) {
            // Peer disconnected, frame malformed, etc.: not retryable. Surface
            // it so e.g. TunnelImpl::open() rolls back to None instead of
            // leaving the tunnel hung in Connecting waiting for a frame that
            // will never deliver.
            return tunnel::SendOutcome::PermanentFail;
        }
        return tunnel::route_sendq_full(*manager, data);
    };

    // Wave B zero-copy outbound: the OwnedFrameBuffer already carries the
    // lossless prefix plus the 5-byte tunnel header in its reserved prefix, so
    // `wire_view()` goes straight to toxcore with no further copies. This path
    // carries TUNNEL_DATA only, which is why it needs no barrier check: DATA
    // only flows on a Connected tunnel, and reaching Connected required a
    // barriered OPEN (client) or OPEN_ACK (server).
    senders.owned = [send_lossless, manager,
                     friend_number](tunnel::OwnedFrameBuffer buf) -> tunnel::SendOutcome {
        const auto wire = buf.wire_view();
        const auto outcome = send_lossless(friend_number, wire.data(), wire.size());
        if (outcome == tox::ToxAdapter::LosslessSendOutcome::Sent) {
            manager->record_frame_sent();
            // The lossless prefix byte is bookkeeping overhead, not payload.
            manager->record_bytes_sent(wire.size() > 1 ? wire.size() - 1 : 0);
            return tunnel::SendOutcome::Sent;
        }
        // The per-tunnel coalesce buffer owns DATA retry, so this never parks —
        // that would put the same bytes on the wire twice.
        return outcome == tox::ToxAdapter::LosslessSendOutcome::PermanentFail
                   ? tunnel::SendOutcome::PermanentFail
                   : tunnel::SendOutcome::SendqFull;
    };

    return senders;
}

}  // namespace toxtunnel::app::detail
