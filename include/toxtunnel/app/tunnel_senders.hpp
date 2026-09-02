#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace toxtunnel::app::detail {

/// A typed lossless send, in the shape `ToxAdapter` exposes it.
///
/// Passed as a callable rather than a `ToxAdapter&` so each call site keeps its
/// own lifetime discipline: `TunnelClient` owns its adapter through a
/// `unique_ptr` member and must dereference it at call time, not capture it.
using TypedLosslessSendFn = std::function<tox::ToxAdapter::LosslessSendOutcome(
    std::uint32_t friend_number, const std::uint8_t* data, std::size_t length)>;

/// The pair of per-tunnel outbound callbacks a production tunnel is wired with.
struct TunnelSenders {
    tunnel::TunnelImpl::SendToToxCallback span;
    tunnel::TunnelImpl::SendOwnedToToxCallback owned;
};

/// Build the outbound send callbacks shared by every production tunnel — the
/// client's TCP-forward, SOCKS5 and pipe paths, and the server's target path.
///
/// These four sites had four copies of the same twenty lines, which is how the
/// FIFO barrier below came to be missing from all of them at once. One
/// definition, one place to get the policy right.
///
/// Two things happen here that a bare "prepend the prefix and call toxcore"
/// wrapper does not do:
///
///  * **Manager accounting.** `record_frame_sent()` / `record_bytes_sent()` on
///    every accepted frame, so `inspect status --json` reports real traffic.
///    (The per-tunnel counters track bytes *offered*, not bytes sent.)
///
///  * **The outbound FIFO barrier.** For TUNNEL_OPEN and TUNNEL_ACK, the
///    manager's retry queue is consulted BEFORE toxcore, not merely after a
///    refusal. Checking only afterwards leaves the design's central failure
///    live: a frame parked in that queue is reported as sent, the tunnel
///    resolves, the id is released and recycled, and a new OPEN for the same id
///    goes out directly — so the stale parked frame drains afterwards and kills
///    the new tunnel. (TUNNEL_CLOSE and TUNNEL_ERROR no longer park at all
///    since issue #24 slice 3 — they are driver-owned and retried in place —
///    so this recycled-id hazard now only concerns the frame types still on
///    the manager queue.) See `TunnelManager::outbound_queue_busy()` for the
///    exact ordering guarantee and its (concurrent, non-causal) residual.
///
/// @param send_lossless  Typed toxcore send. Must remain callable for the
///                       lifetime of the tunnel that owns these callbacks.
/// @param manager        Captured by shared_ptr value on purpose: capturing
///                       `manager.get()` is the UAF pattern called out on
///                       `TunnelClient::tunnel_mgr_`.
/// @param friend_number  Fixed for the life of the tunnel.
[[nodiscard]] TunnelSenders make_tunnel_senders(TypedLosslessSendFn send_lossless,
                                                std::shared_ptr<tunnel::TunnelManager> manager,
                                                std::uint32_t friend_number);

}  // namespace toxtunnel::app::detail
