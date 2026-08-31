# Outbound send driver — approved design

Status: **approved, partially implemented.** Slice 1 (typed seam + handshake)
shipped in v0.4.13. Slices 2-5 are specified here and not yet built — tracked as
https://github.com/agentx-icu/tox-tcp-tunnel/issues/24.

This document exists because the design took nine rounds of independent review
to converge, and eight of those rounds were rejections that each found a real
defect. Re-deriving it from scratch would almost certainly reproduce one of the
mistakes recorded below.

## The problem

Two paths invoke a Tox send callback **while holding `coalesce_mutex_`**: the
buffered drain (`coalesce_emit_front_locked`) and the immediate/bypass branch in
`send_data_to_tox`. That violates the rule the rest of the codebase follows
(snapshot under the lock, call outside it), and `OutboundSnapshot`'s own
documentation already promises callbacks run with no lock held.

It is not a tidiness problem. The coupling has produced a series of real bugs —
truncation, reordering, and teardown failures — because the mutex is invisible
at the callback end: nothing there hints that a close re-enters a lock the
caller already holds. Concretely it forced two compromises:

- `force_close()` cannot flush once re-entered from inside a send, so it takes a
  local-abandon path guarded by the outbound gate.
- `close_all_local()` cannot wait for in-flight sends, so its documented
  residual is that a send authorised just before the gate closed may still land.

## The shape of the fix

One **driver** owns all outbound emission. No send callback is ever invoked
under `coalesce_mutex_`. Every emission path — DATA, CLOSE, ERROR, explicit
flush, the coalesce timer, the ACK drain, the pending-TCP backlog, the
Connecting-state CLOSE, and `configure_coalesce()` — goes through it. No second
path may call a send callback.

### Result type

```
enum class EmitOutcome { RequestSatisfied, DeferredToActiveEmitter, Backpressured };
```

`DeferredToActiveEmitter` must **never** be read as satisfied. `RequestSatisfied`
for a full-frames-only request is compatible with a sub-MTU remainder still
buffered — name it for what it means, not "Drained".

### Terminal state — two orthogonal axes

Collapsing these into one enum was rejected twice.

- `PeerCloseObserved` — monotonic latch (today's `remote_close_received_`).
  Does **not** close outbound admission. A peer CLOSE does not move the tunnel
  to `Disconnecting`; that state comes from our own local EOF / close.
- `LocalTerminalIntent` — ordered, monotonic:
  `None < LocalEof < GracefulClose < Abort`.
  - `LocalEof` — local read side ended. Admission closes; sealed backlog drains.
  - `GracefulClose` — `Tunnel::close()`. Keeps draining, finalizes after CLOSE.
    The interface contract promises this and the server's disconnect path
    depends on it.
  - `Abort` — `force_close()` / session abandonment / error termination only.
    Abandons remaining not-yet-accepted bytes.

  Rule: **no graceful operation maps to `Abort`.**

Transitions: `LocalEof -> GracefulClose` keeps draining. Any `-> Abort` abandons
the remainder. A DATA callback already authorised is allowed to return — `Sent`
commits that frame and it cannot be unsent. An upgrade during a CLOSE callback
cannot retract it and must never emit a second CLOSE.

### Admission gate

The driver claims a terminal action **before** draining the pre-claim queue, not
after the queue empties — otherwise a continuous producer starves CLOSE forever.
The claim closes admission, which makes the remaining queue finite.

`close_outbound_gate()` publishes `Abort` in the same critical section in which
it closes the gate: one authority, not two.

### Two queues, one model

`pending_tcp_input_` is a second admission queue under a *different* mutex
(`tcp_backpressure_mutex_`). Three paths reach it without consulting the
coalesce gate, so a bare atomic flag leaves a check-then-append race.

The terminal claim therefore **seals** the backlog: publish the intent, then take
`tcp_backpressure_mutex_` once and mark it sealed. Because every append holds
that same mutex, the seal is a clean cut — every append is unambiguously before
or after it.

The seal alone is not enough. The ACK-driven drain selects a chunk, drops the
mutex to send, and a claim can seal while the cursor still covers that chunk —
sending the same bytes twice. So ownership spans
`select chunk -> common admission -> cursor commit`, single-flight under
`tcp_backpressure_mutex_`, and:

- the pending cursor is committed when the **cohort FIFO accepts ownership**, not
  when the transport callback succeeds. Bytes must never exist in a cohort and
  the backlog simultaneously.
- ordinary admission **queues behind any unhandled pending remainder**. Otherwise
  a callback-reentrant `send_data_to_tox(C)` during the handoff of `A1` with
  remainder `A2` produces `A1, C, A2`.
- an ACK that finds an existing owner **records a kick/generation**; otherwise it
  can reopen the window exactly as the owner parks and the only wakeup is lost.
  The owner re-reads the kick before releasing ownership.
- the owner re-loops only when the kick changed **and progress is possible** — a
  kick with the window still closed must not spin.

Draining the sealed backlog needs a **privileged capability**: ordinary
`send_data_to_tox()` must reject once a terminal intent is published, so it
cannot also be the thing that drains pre-claim bytes. The capability is
non-copyable, generation-bound to the pending owner, kept off the public
signature, and converges with ordinary admission **before** window accounting,
metrics, activity, cohort tagging and retry. It may bypass `LocalEof` /
`GracefulClose`; never `Abort`, never the session outbound gate.

Pre-claim bytes: `LocalEof` and `GracefulClose` **drain** the sealed backlog
before CLOSE — they are bytes already read off the local socket and owed to the
peer. `Abort` abandons them, deliberately.

### Fragmentation cohorts

Caps cannot be merged. 1000 buffered bytes tagged 1362 followed by a 1367-byte
bypass write: a merged cap of 1367 breaks the buffered contract, 1362 breaks the
bypass one-frame contract. So the buffer is a FIFO of cohorts each tagged with
the cap it was admitted under:

- immediate/bypass: the 1367-byte wire ceiling (`kMaxTcpPayloadPerToxFrame`)
- buffered: the configurable `coalesce_max_bytes_` (default 1362)

Adjacent cohorts merge only when caps are equal. A cohort keeps its cap across
backpressure and retry. Never materialize one frame spanning unequal caps.
Consume no cohort bytes until the callback accepts the frame. Front cursor with
lazy compaction keeps draining amortized O(n). `FlushAll` may emit a sub-cap
front remainder; `FullFramesOnly` may not.

"One frame per bypass write" is a property of the unobstructed synchronous path
only — it is not a promise that survives backlog-forced FIFO merging.

### Latency

Bypass keeps its latency if the caller that finds the driver idle runs it
synchronously on its own thread — no post, no dispatch, no timer — and bypass
requests `FlushAll` so a sub-MTU write reaches the callback before
`send_data_to_tox()` returns. A write arriving mid-send queues behind it, which
is the FIFO serialization we want and is no worse than today, where it would
block on `coalesce_mutex_` anyway. This matters because `coalesce_max_delay_us`
is effectively 0 on Windows.

### Typed transport outcome

`SendToToxCallback` must return `Sent / SendqFull / PermanentFail`, not `bool`.
Leaving CLOSE retry with `TunnelManager` was considered and **rejected**: the
manager's queue holds raw wire bytes with no tunnel identity or cancellation
handle, so

```
old CLOSE(id=7) -> SendqFull -> manager parks, callback returns true
  -> driver treats CLOSE as accepted -> on_close -> id 7 released
new OPEN(id=7) sent directly through the per-tunnel callback
manager drain timer fires -> stale CLOSE(id=7) -> kills the NEW tunnel
```

The driver retains a terminal CLOSE on `SendqFull`; `PermanentFail` maps to
`Abort`. `TunnelManager` remains retry owner for manager-originated control
frames, so there is still exactly one owner per frame.

Terminal CLOSE retries until `Sent`, `PermanentFail`, `Abort` or shutdown — no
attempt-count bound, which would be cadence-dependent and risk abandoning remote
state. But **not on the coalesce cadence**: use a dedicated SENDQ retry delay
with capped backoff. Reusing the timer object is fine; reusing
`coalesce_max_delay_us` is not.

OPEN and ACK likewise never fall back to the manager's raw-byte queue. OPEN
retains its opening intent; ACK restores the semantic byte count and retries
from the accumulator rather than replaying a stale serialized frame. ACK needs no
independent generation — take the pending credit atomically, consume on `Sent`,
restore on `SendqFull` if the driver generation is still live, `Abort` without
restoration on `PermanentFail`, and bytes accumulated during the attempt stay
additive.

### Bounds

One aggregate cap over pending backlog + cohort FIFO + in-flight owner bytes,
not per-queue. It must reserve capacity for one maximum TCP read:
`TcpConnection` hands out a borrowed buffer valid only during the callback, so
refusing ownership near the cap either drops those bytes or blows the cap by
copying them anyway. Pause at `cap - read_buffer_size` with an explicit
outstanding-read reservation, require `cap >= maximum_read_size`, and release the
reservation on success, EOF, error and cancellation.

TCP read admission must be centralized. `TcpConnection` exposes a single pause
bit while the ACK path can call `resume_read()` directly; the aggregate-cap
reservation and send-window backpressure have to compose as pause *reasons*, and
neither may resume reads while the other is still active.

Internal admission returns `{accepted, should_pause}`. The public boolean keeps
its meaning ("ownership accepted") — `on_tcp_data_received()` currently pauses
only when admission returns false, so "accepted but queued behind the barrier"
would otherwise fail to pause and let the backlog grow.

### `send_error()` ordering

Atomically: seal admission and publish `Abort`; abandon pending/cohort DATA;
establish the single terminal ERROR notification; then invoke transport and
state/error callbacks **outside** the mutex. `Abort` must be published before any
state/error callback, because those callbacks can re-enter admission.

## Slices

1. **Handshake — shipped in v0.4.13.** Typed seam; driver-owned OPEN and OPEN_ACK;
   OPEN retry off the coalesce cadence; the OPEN_ACK causal barrier (`Connected`,
   open metrics, `start_read()` and DATA admission all behind the same `Sent`);
   terminal ERROR when the target dies while OPEN_ACK is backpressured.
2. Cohort FIFO and the single emission driver for DATA.
3. CLOSE/ERROR driver ownership; `send_error()` reordering; `close_outbound_gate()`
   publishing `Abort`.
4. Pending-backlog seal, handoff ownership, privileged capability, aggregate cap.
5. Only then: revisit the strong `close_all_local()` fence and whether the
   `force_close()` local-abandon guard can be removed. Removing the mutex hold is
   **necessary but not sufficient** for the fence — an in-flight wait still needs
   an explicit answer for teardown invoked from inside the send being waited on.

## Mistakes this design already made, so they are not made again

- A boolean "another emitter owns the drain" flag conflates *deferred* with
  *drained*. At the `close()`, remote-close and TCP-EOF call sites that return
  gates whether CLOSE may be emitted, so a reentrant `close()` sends CLOSE while
  DATA is still in flight and CLOSE overtakes DATA.
- Fixing only `coalesce_emit_front_locked()` misses the immediate/bypass branch,
  which also calls the send callback under the mutex and is the path the existing
  reentrant-teardown regression actually exercises.
- A single flag cannot carry drain *policy*: append drains full frames and leaves
  a remainder by design, while close/timer/flush must drain the remainder too.
- The half-close direction is easy to invert. `Disconnecting` plus continued DATA
  acceptance is the **local**-EOF case, not the peer-close case.
- Detaching a tunnel from the manager before closing it does not make the close
  local: `close_for_timeout()` still sends, ids get released before the send
  resolves, and `on_close` handlers stop firing.
