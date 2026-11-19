# Outbound send driver — approved design

Status: **slices 1–5 implemented.** Slice 1 (typed seam + handshake)
shipped in v0.4.13. Slice 2 (cohort FIFO + the single emission driver for DATA)
is implemented on master: no Tox send callback runs under `coalesce_mutex_` on
any DATA path any more, and the deferred-close bookkeeping moved from the flush
timer into the driver's drain-complete step. Slice 3 is now **complete**: CLOSE
and ERROR are emitted only by `run_emission_driver` itself (CLOSE via a
request-and-kick `close_emit_requested_` + `CloseFrameState`; ERROR via the
terminal-ERROR slot `pending_terminal_error_` with its own SENDQ retry timer
and a two-party settle latch), so literally no second path invokes a send
callback for a per-tunnel terminal frame. `driver_owns_retry()` returns
CLOSE/ERROR backpressure verbatim (they no longer park in the manager queue);
the driver's selection order ERROR→DATA→CLOSE plus the commit-side
`terminal_error_claimed_` supersession fence make ERROR-before-CLOSE wire
ordering impossible; a throwing DATA callback completes to a terminal Abort;
every asio handler boundary (timers, io_context workers, signal contexts)
contains exceptions, with a diagnostic fatal worker boundary as the last
line. The full R-numbered review history and the completion plan live in
`slice3-close-error-routing-plan.md`. Companion / follow-up work is tracked
separately: resume stale-ACK identity (#28), pre-existing exception-safety
debt in stop/destructor/completion handlers (#29), manager pending-queue
session provenance (#30), and the resume-abort integration regressions (#31).
The pending TCP queue, cohort FIFO and local terminal intent now share one
admission lock. Session abandonment closes a permit at the native enqueue.
See the implementation notes below for [#24][issue24] and [#25][issue25].

[issue24]: https://github.com/agentx-icu/tox-tcp-tunnel/issues/24
[issue25]: https://github.com/agentx-icu/tox-tcp-tunnel/issues/25

This document exists because the design took nine rounds of independent review
to converge, and eight of those rounds were rejections that each found a real
defect. Re-deriving it from scratch would almost certainly reproduce one of the
mistakes recorded below.

## The problem

(As it stood before slice 2; kept for the record.) Two paths invoked a Tox send
callback **while holding `coalesce_mutex_`**: the buffered drain
(`coalesce_emit_front_locked`) and the immediate/bypass branch in
`send_data_to_tox`. That violated the rule the rest of the codebase follows
(snapshot under the lock, call outside it), and `OutboundSnapshot`'s own
documentation already promised callbacks run with no lock held. Slice 2
replaced both with `run_emission_driver` + the cohort FIFO; the CLOSE/ERROR
paths and the pending-backlog seal are described below.

It is not a tidiness problem. The coupling caused truncation, reordering and teardown failures because a
callback could close a tunnel while the caller still held its admission lock.
The earlier implementation had two compromises:

- A reentrant `force_close()` could not flush safely and used the local-abandon
  path when the outbound gate was closed.
- A previously copied callback could enqueue a packet after
  `close_all_local()` returned.

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

The pending input and cohort FIFO share `coalesce_mutex_`. Ordinary admission
queues behind a pending remainder. Pending handoff computes the window credit,
appends to the cohort FIFO and commits the pending cursor in the same critical
section. Another ACK can observe the old owner or the new owner, never both.
It always checks the current queues again after crediting the window.

EOF and graceful close seal ordinary admission. The private pending handoff can
still move bytes it already owns into cohorts. It uses the same accounting and
coalescing logic as ordinary admission, and both reject an Abort. The driver
waits for both queues before emitting a graceful CLOSE. Abort clears both
queues, including the deferred-close bookkeeping.

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

The configured maximum send window bounds the sum of pending input, cohort
bytes and the selected frame. The selected frame stays charged to its cohort
until its send verdict is committed. Ordinary producers cannot borrow the
extra capacity reserved for the TCP connection's one outstanding read. The
TCP callback pauses further reads while input remains pending, the send window
is full, or that extra capacity is still in use. An ACK checks all three
conditions before resuming reads.

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
2. **Cohort FIFO and the single emission driver for DATA — implemented.**
   `run_emission_driver` (single-flight under `coalesce_mutex_`, frame
   selection and consumption-commit under the lock, the send between them with
   no lock held), cohorts tagged with their admission cap, `EmitOutcome` with
   `DeferredToActiveEmitter` distinct from satisfied, and the deferred-close
   bookkeeping executed by whichever emitter completes the drain.
3. **Terminal ordering.** The driver owns terminal CLOSE and ERROR selection.
   Abort shuts admission before a pending ERROR is driven. The close obligation
   and ERROR settle latch hold the tunnel id until their terminal sends settle.
4. **Pending input.** EOF and graceful close seal admission, and pending handoff
   moves the already-owned bytes to the driver before calling transport. Both
   queues share the capacity limit and one TCP read reservation.
5. **Session abandonment.** Production packet callbacks take a per-manager
   permit on the Tox thread immediately before native enqueue.
   `close_all_local()` revokes that permit before local teardown. This settles
   already-started native enqueues without waiting for reentrant callbacks or
   I/O threads blocked on the Tox thread. Toxcore owns packets that were already
   accepted. `force_close()` still skips flushing an abandoned session.

The reaper captures exact tunnel instances and atomically claims a timeout
under the matching manager epoch and tunnel admission lock. It dispatches
transport and user callbacks after releasing both the generation and map
locks. A stale scan cannot claim a replacement with the same numeric id.

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
