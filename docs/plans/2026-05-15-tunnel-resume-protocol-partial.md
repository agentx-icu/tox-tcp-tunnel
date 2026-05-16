# Tunnel Resume Protocol — partial implementation note

**Status (2026-05-15):** Wire format + persistent state + config surface
shipped; full driver wiring deferred to v0.4.1.

## What v0.4 shipped

- New `FrameType` opcodes `TUNNEL_RESUME_REQUEST = 0x08` and
  `TUNNEL_RESUME_ACK = 0x09`, with binary payload structs and a leading
  schema version byte for future migration.
- `app::TunnelResumeStore` — client-side YAML persistence using the new
  `util::atomic_write_file` helper. Schema-versioned, prunes entries
  older than `max_age_seconds`, wipes itself on server-tox-id mismatch.
- Configuration `tunnel.resume:` sub-block: `enabled` (default false),
  `state_path`, `max_age_seconds`, `on_gap`. Non-reloadable.
- Metrics: `toxtunnel_resume_attempts_total`, `_successes_total`,
  `_failures_total`.
- Unit tests pinning the wire-format round-trip and the persistence
  contract.

## What is deferred

The "live" handshake wiring is not yet in the data flow:

1. **Client side:**
   - When a configured forward triggers, the `TunnelClient` should
     consult `TunnelResumeStore::find(local_listener_port)` (or
     equivalent) and, if a fresh entry exists, emit
     `TUNNEL_RESUME_REQUEST` instead of `TUNNEL_OPEN`. On
     `TUNNEL_RESUME_ACK status=Ok` the existing local TCP connection
     stays alive; on any other status it falls back to `TUNNEL_OPEN`.
   - The 5-second offset-checkpoint timer that persists current
     `last_local_recv_offset` / `last_local_send_offset` to the store.
   - The capability negotiation: an `INFO_REQUEST` early in the
     friendship lifecycle, capability advertisement via `INFO_REPLY`.

2. **Server side:**
   - `on_lossless_packet` -> `handle_tunnel_resume_request`. Validate
     against current `RulesEngine`, attempt `connect(2)` to the target,
     install a fresh `Tunnel` with the resume offsets, reply
     `TUNNEL_RESUME_ACK`.
   - `TunnelManager::reserve_tunnel_id(prior_id)` so the server can
     keep the client-requested ID when free.

## Why it was deferred

The design doc's risk register explicitly allows slipping the protocol
to v0.5 if integration testing surfaces corner cases. The wire format
and state store ship now so the v0.4 release establishes the contract;
the handshake driver depends on a deeper refactor of
`TunnelManager::handle_incoming_open` to carry the "resume into a
specific tunnel_id" semantic and the right hooks into
`TunnelClient::on_friend_connection`. Doing that refactor mid-v0.4
risks destabilising the rest of the release (which is already
shipping zero-copy, adaptive coalescing, BDP flow control, rate limiting,
and the watchdog).

## Compatibility

- `tunnel.resume.enabled: false` is the default. With the flag off, no
  TUNNEL_RESUME_REQUEST/ACK frames are ever emitted; v0.3.0 peers see
  no change.
- Old servers that *do* receive a TUNNEL_RESUME_REQUEST already follow
  the protocol convention of ignoring unknown opcodes silently. The
  client's existing 1-second timeout on the resume attempt handles
  that.

## Follow-up tasks (v0.4.1)

- [ ] Wire `TunnelClient` to emit `TUNNEL_RESUME_REQUEST` on reconnect.
- [ ] Wire `TunnelServer::handle_tunnel_resume_request` into
      `on_lossless_packet`.
- [ ] Add `TunnelManager::reserve_tunnel_id(uint16_t)` for the
      "resume into a specific ID" case (the allocator's `reserve()`
      method already exists; just plumb it).
- [ ] Add `INFO_REPLY` capability negotiation: `tunnel_resume: true`,
      `tunnel_resume_version: 1`.
- [ ] Per-tunnel `last_local_recv_offset` / `last_local_send_offset`
      checkpoint timer with the 5-second / 1 MiB throttle the design
      doc specifies.
- [ ] Integration test: spin up server + client, kill server mid-
      tunnel, restart, verify the local TCP session continues with the
      gap reported through the metrics.

Once these land, the feature flag flip from `false` -> `true` is the
v0.4.2 / v0.5 default-change candidate per the design doc's rollout
plan.
