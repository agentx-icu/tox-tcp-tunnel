# Plan v16: route CLOSE/ERROR emission through run_emission_driver (issue #24, slice 3 completion)

Status: DRAFT v16. Round 15 closed R14-1. Every remaining finding since
round 13 lives in ONE pre-existing defect class — posted events, inbound
dispatch and the manager pending queue lack session provenance — which is
precisely the session-lifecycle/generation machinery issue #25 already
says this work is building toward. v16 therefore does two things: it
incorporates the round-15 contracts [R15-1]..[R15-5] into the companion
sections, and it adds an explicit IMPLEMENTATION SCOPE SPLIT so the
finding-free core can ship while the provenance class proceeds as its
own tracked work.

## Implementation scope split [v16]

- **Core slice 3 (implement NOW, this plan's subject):** CLOSE/ERROR
  routed through run_emission_driver; the ERROR slot + two-party
  settlement + fences + dedicated retry timer; the CLOSE request
  predicate + supersession fence; DATA-throw completes to terminal; the
  driver exit/unwind protocol; manager dispatch predicate
  (abort_teardown_required in close_all/remove_tunnel_impl); shutdown
  settlement sites incl. gate split; the worker fatal boundary; the
  cancel_timer_noexcept inventory (R11-1/R12-1/R13-3 timer sites);
  force_close exception discipline; the `outbound_aborted()` resume
  eligibility/revalidation hardening (generation-free, round-16 scope
  note); comment updates; the core regression list. No review round since 8 has found a defect in this core.
- **Companion A — issue #28 (resume identity):** the token machinery,
  deadline state machine, invalidate_resume_session, source-session
  provenance for resume producers and peer-dead events, EXTENDED per
  round 15: ingress-generation validation covers ALL manager-routed
  inbound frames (ordinary ACK/DATA/CLOSE/ERROR, not only RESUME_ACK)
  [R15-2]; the peer-dead revalidation and close_all run without a gap
  (revalidate, then publish nothing before the teardown) [R15-1]; the
  server's peer-dead/resurrection teardown validates a per-friend
  session/keepalive generation, reusing the prune-timer identity
  pattern (tunnel_server.cpp:1425) [R15-5].
- **Companion B — session provenance for the manager pending queue
  (filed as issue #30):** `pending_drain_epoch_` validated at handler entry,
  every dequeue, and the post-send commit; a late SendqFull after
  invalidation DROPS, never requeues [R15-3]; disposition per the
  round-15 table [R15-4]: an already-authorized attempt returning Sent
  is contained to the old friend; an entry not yet selected when its
  epoch/session is invalidated is DROPPED; an in-flight SendqFull after
  invalidation is DROPPED — old-friend delivery is NOT the default for
  an invalidated queue, and tunnel_client.cpp:1729 keeps its
  drop-on-session-retirement rationale (only the false ordering claim
  goes); any pinned-route delivery would need an explicit
  draining-old-session state and a SendHandler API that carries the
  route, which this series does not introduce.

The core does not depend on either companion: CLOSE/ERROR emission,
settlement and teardown are per-tunnel and in-manager; the provenance
class concerns which SESSION posted an event, a dimension the core
never touches. The companions are tracked upstream and implemented as
their own reviewed commits. The round-15 regression list (old ordinary
inbound vs switch+id-reuse; peer-dead revalidate-then-close_all;
admission racing the switch's close_all for forward/pipe/SOCKS; drain
blocked in transport then Sent — no successor consumption; same with
SendqFull — no requeue; stale client peer-dead across same-friend
reconnect + successor keepalive works; stale server peer-dead across
resurrection) attaches to the companions.

## Invariant scope [R3-6a]

"No second path invokes a send callback for CLOSE/ERROR" is scoped to
**TunnelImpl-originated terminal frames** (this tunnel's one CLOSE and one
terminal ERROR). Manager-originated ERRORs (unknown-tunnel replies etc.,
`TunnelManager::send_frame`) carry ids with no local tunnel object and keep
the manager's park-and-drain — they cannot race a per-tunnel driver that does
not exist. `driver_owns_retry()` gains CLOSE+ERROR, which affects only the
per-tunnel `route_sendq_full()` seam; manager `send_frame()` callers are
unaffected. Comments at tunnel_manager.cpp:1374 and the CloseFrameState
Resolved doc are updated to the narrowed residual. Also updated
[R12-5]: the stale close_all_local rationale at tunnel_manager.cpp:900
and tunnel_manager.hpp:410, which still claim DATA sends hold
`coalesce_mutex_` across callbacks (false since slice 2) — replaced
with the current reason (snapshots are not registered/waitable, and a
reentrant teardown cannot wait on its own send). Two further statements
of the removed behaviour join the list [R13-5]:
tunnel_manager.cpp:962 and test_tunnel_manager.cpp:1282.

## ERROR slot state (all under `coalesce_mutex_`) [R3-6b]

```
struct PendingTerminalError { std::vector<std::uint8_t> wire; unsigned attempt{0}; };
std::optional<PendingTerminalError> pending_terminal_error_;
bool error_retry_armed_{false};        // THE single readiness/backoff bit
bool error_attempt_in_flight_{false};  // selected; transport attempt outstanding [R3-1]
bool error_retry_cancelled_{false};    // persistent shutdown fence [R5-1], mirrors
                                       // close_retry_cancelled_
std::uint64_t error_retry_epoch_{0};
asio::steady_timer error_retry_timer_;
bool error_producer_arrived_{false};
bool error_transport_arrived_{false};
```

(The v3 slot-local `retry_armed` and the stray `settle_parties_ = 2` are
gone; the two one-shot booleans are the whole latch.)

Slot lifecycle: deposited (unselected, `!error_retry_armed_`) → selected
(`error_attempt_in_flight_=true`, slot retained) → commit: Sent /
PermanentFail / gate-closed-Sent → clear slot, clear in-flight, arrive
transport party; SendqFull → FIRST consult `error_retry_cancelled_` in the same commit
critical section [R5-1]: if set (a shutdown settlement ran while this
attempt was inside the transport — force_close / gate / destructor), the
commit settles permanently (clear slot, clear in-flight, arrive transport
party) instead of re-arming; this is the exact late-SendqFull-after-
cancellation fence CLOSE already has (`close_retry_cancelled_`, regression
open_handshake_test.cpp:3014), applied to ERROR. Otherwise: keep slot,
clear in-flight, `error_retry_armed_=true` + ++attempt + epoch published
in the commit critical section; the PHYSICAL arm
(`expires_after`/`async_wait`, strong self-reference in the handler,
mirroring `arm_close_retry_timer` [R3-2]) runs after release under a
re-taken lock validating epoch + cancellation — the same
publish-then-arm shape as the CLOSE timer [holistic fix]; timer handler:
epoch check, clear `error_retry_armed_`, kick. Selection eligibility also excludes a
cancelled slot. Failed arming (not shared-owned) → settle as shutdown.
Every shutdown-settlement site sets `error_retry_cancelled_` in its
coalesce critical section, whether or not a slot is present at that
moment.

### The claim consults the fence [R6-1]

The producer's claim/deposit critical section checks
`error_retry_cancelled_` FIRST. If it is already set (shutdown won before
the claim), the producer still claims (`terminal_error_claimed_` — later
send_error calls stay suppressed duplicates, and the CLOSE fence stays
correct) but deposits NOTHING; after releasing the lock it arrives the
transport party immediately (shutdown settlement — nothing will ever be
sent) and proceeds with its local terminal transition and callbacks. This
is the same claim-without-deposit shape as the serialization-failure path,
so no new observer assumptions arise (round-4 Q3 already established that
no code assumes claim ⇒ slot).

### Timer-arm exception guard [R4-2]

Publishing `*_retry_armed_ = true` and physically arming
(`expires_after`/`async_wait`) are two steps, and the physical step can
throw. BOTH timers therefore arm through one exception-guarded helper shape:
on a throw from the physical arm, re-take the guarding mutex, validate the
epoch published with the ownership, and — exactly once — clear the published
ownership and settle: for ERROR, clear `error_retry_armed_` + slot and
arrive the transport party (permanent failure); for CLOSE, clear
`close_retry_armed_` and resolve the obligation (Resolved + notify, the
same fallback the not-shared-owned path uses). The predicate that refuses
producer requests while `*_retry_armed_` is set can therefore never be
wedged by a phantom timer.

## Transport-party arrival sites (exactly-once via the one-shot bool)

1. Selected-attempt commit (Sent / PermanentFail / gate-closed-Sent).
2. Selected-attempt exception guard (throwing send → permanent failure:
   clear slot, clear in-flight, arrive) [R2-2].
3. Shutdown settlement — ONLY for an UNSELECTED parked slot
   (`pending_terminal_error_ && !error_attempt_in_flight_`) [R3-1]: a
   selected attempt's OutboundSnapshot may already be past the gate, so its
   own commit/exception guard must be the one to arrive; the
   `terminal_error_in_flight_` fence keeps the id unreleasable meanwhile.
   SCOPE OF THAT CLAIM [R11-2]: the fence reserves the id WITHIN this
   tunnel's own manager/allocator. It cannot reserve anything in a
   DIFFERENT manager for the same friend — the resurrection-loser path
   (`close_all_local()` on the losing manager while the winner already
   serves that friend, possibly with the same numeric id) can still see
   the loser's pre-gate-authorised send land after the winner's tunnel
   exists. That is the EXISTING, documented close_all_local residual ("a
   send already authorised may still land", tunnel_manager.cpp:1274) —
   unchanged in either direction by this slice, and closable only by the
   slice-5 strong fence / a session-generation suppressor, not by a
   per-tunnel flag.
4. Pre-claim serialization failure [R3-3]: `send_error()` serializes inside
   try/catch BEFORE the claim; on throw it still enters the claim critical
   section (Abort seal + fences + claim, but NO deposit) and, after release,
   arrives the transport party immediately (permanent failure — nothing to
   send), then proceeds with the terminal transition and callbacks exactly
   as if the transport had failed. Today's behaviour (TerminalSettleGuard
   catches the serialize throw) is preserved in effect. `close_for_timeout`
   uses the same shape; its loser path (claim already taken) deposits and
   arrives nothing.
5. Destructor backstop: cancel timer; if a slot survives, clear it and
   arrive.

## Shutdown settlement sites [R3-2]

`close_outbound_gate()` is NOT the universal teardown authority; the
reachable set is:

- `close_outbound_gate()` (session abandon / close_all_local): in its
  coalesce critical section — epoch-bump + cancel `error_retry_timer_`,
  shutdown-settle an unselected parked slot (arrival performed after the
  locks drop). EVERY cancellation on this path — including the
  pre-existing `cancel_close_retry()` it calls first, whose throwing
  `timer.cancel()` would otherwise strand the rest of close_all_local's
  gate loop under the manager lock — is made non-throwing (via the shared
  `cancel_timer_noexcept()` helper — see the R13-3 note below), then epoch
  invalidation, slot settlement and the remaining tunnels proceed
  [R11-1]. Injected-cancel regressions cover gate and force_close, not
  only claim_terminal/destructor. The non-throwing-cancel contract also
  covers [R12-1]: the `close_all_local()` PRELUDE — `disable_keepalive()`
  (tunnel_manager.cpp:375), `disable_reaper()` (tunnel_manager.cpp:155)
  and `pending_drain_timer_.cancel()` (tunnel_manager.cpp:883), whose
  throw would prevent the per-tunnel gates from ever closing — and
  `flush_pending_writes()`'s `coalesce_timer_.cancel()` (tunnel.cpp:2597)
  on the force_close path, whose throw would otherwise become the
  synchronous force_close exception despite the policy. Additionally
  [R13-3]: `clear_pending_outbound()`'s `pending_drain_timer_.cancel()`
  (tunnel_manager.cpp:1558), reached from active-friend disconnect
  (tunnel_client.cpp:749) and from the endpoint switch immediately
  before close_all (tunnel_client.cpp:1735) — including from inside the
  Tox callback, OUTSIDE the asio fatal runner. Serialization is BOTH,
  not either [R14-3]: every arm/cancel publication happens under
  `pending_mutex_`, AND a `pending_drain_epoch_` — bumped on
  clear/invalidate, captured by each wait, validated before draining —
  rejects a stale handler that was already queued when the cancel
  landed (serialization alone cannot un-queue it), so it cannot drain a
  newly repopulated queue concurrently with the successor timer.
  DISPOSITION CORRECTION [R15-4, replacing v15's session-bound-friend
  claim]: friend number is endpoint provenance, not session provenance,
  and the manager's SendHandler API carries no route — so invalidated
  queued work is DROPPED, not redirected: entries not yet selected when
  the epoch/session is invalidated drop; an in-flight attempt returning
  SendqFull after invalidation drops, never requeues; only an attempt
  already authorized and accepted (Sent) is contained to the old
  friend. This preserves tunnel_client.cpp:740's deliberate
  clear-on-disconnect rationale. The stale commentary at
  tunnel_manager.cpp:1555 and the false clear-before-switch ordering
  claim at tunnel_client.cpp:1729 join the comment-update list (the
  drop rationale at :1729 stays). Regressions: stale pending-drain
  handler rejected by epoch at entry/dequeue/commit; invalidated
  SendqFull not requeued; blocked-in-transport drain returning Sent
  consumes no successor entries. Implementation note for the WHOLE non-throwing-cancel
  contract [R13-3]: this build defines ASIO_NO_DEPRECATED
  (CMakeLists.txt:179), so the deprecated cancel(error_code&) overload
  does not exist — every listed site (here and in the R11-1 clause
  above) uses ONE shared noexcept `cancel_timer_noexcept(timer)`
  try/catch helper instead. Each listed site gets an injected-cancel
  regression.
- `force_close()`: its owns_resources abort section does the same.
- Manager dispatch [R4-1, R5-1b, R6-2]: the predicate becomes a TunnelImpl
  method — `abort_teardown_required()` ≡ state ∈ {None, Disconnecting,
  Closed, Error} OR `outbound_abort_published_` — and is used by BOTH
  `close_all()` AND `remove_tunnel_impl()` (which today has the same
  state-sampled dispatch and the same sealed-but-Connected `close()` no-op
  hole; without this, a tunnel Abort-sealed by a DATA throw is reaped via
  `close_for_timeout`→`close()`→no-op and detached with no terminal
  transition, no notify_close_once, and its resources unsettled). Both
  route matches to `force_close()`.
  Sampling the Abort seal (not just `state == Error`) closes the
  state-dispatch window where the ERROR claim precedes the Error
  transition: a tunnel whose seal is up but whose state still reads
  Connected must not be sent to `close()`, which no-ops on the seal. A
  stopped-but-alive io_context after `close_all()` therefore cannot strand
  a parked ERROR — force_close settles synchronously. Side benefit: the
  Error-state target socket, which today's `close()` no-op dispatch never
  releases, is closed by force_close's resource half.

  DOCUMENTED RESIDUAL [R7-4, R8-5]: a send_error whose claim lands after
  the dispatch sample deposits into a tunnel the teardown pass has already
  visited. `close_all()` is ALSO used with a RETAINED, still-operating
  manager — online preference failback (tunnel_client.cpp:1727) and
  keepalive failover — so the claim is NOT assumed dead:
  (a) the id stays reserved for the whole interval: the
      `terminal_error_in_flight_` fence holds until settlement, and the
      manager's on_id_releasable hook releases the id only then;
  (b) retained until settlement, in full: the `TunnelImpl` object; its
      `error_retry_timer_` plus the STRONG self-reference in that
      handler; the deposited ERROR wire bytes; the TcpConnection when no
      path has closed it yet; the send/state/close std::function
      callbacks and their captures, including the manager shared_ptr
      inside the sender lambdas;
  (c) the retry chain emits only through the sender bound at construction
      to the OLD friend number (tunnel_senders.cpp:16), so no
      interleaving can deliver the frame to the NEW server. Offline
      promotion: the disconnected friend returns PermanentFail on the
      first retry — prompt settlement. Online failback: the old friend
      is still up, so the send returns Sent (ERROR delivered to the old
      server, naming the old session's tunnel — correct addressing) or
      SendqFull (ordinary SENDQ-cadence retry against that live friend
      until Sent/PermanentFail, bounded by the friend link's lifecycle);
  (d) if the io_context stops instead: destructor backstop at handler
      destruction.
  Deterministic regression construction [R7-4]: the teardown pass is
  blocked on a test barrier immediately after sampling the predicate for
  the target tunnel; `send_error()` fires from another thread and
  deposits; the barrier is released. Assertions: the id is not recycled
  before settlement; with the sender stubbed disconnected, the first
  retry's PermanentFail settles the latch and nothing is emitted after
  settlement; with the sender stubbed online, Sent settles it.
- The strong-self-reference timer + destructor backstop remain the backstop
  chain for owners that bypass every explicit site.

## Unwind-guard recovery — TIMER-PACED, no asio::post [R3-4, R4-3, R4-4]

v4's posted recovery is REMOVED. The driver's unwind guard, after clearing
`driver_active_` (+ flush latch) under `coalesce_mutex_`, recovers every
stranded obligation through the SENDQ retry timers, which already carry
strong ownership, epoch validation, the arm-exception guard [R4-2], and
failed-arm settlement:

- Unselected parked-eligible ERROR (present, !in-flight, !retry_armed,
  !cancelled): arm `error_retry_timer_` (sets `error_retry_armed_`,
  attempt unchanged). The timer handler is the wakeup; arm failure settles
  permanently.
- Unselected CLOSE request (Owed + requested, unfenced): under
  `close_frame_mutex_`, clear the request flag, publish
  `close_retry_armed_` and arm the close-retry timer — converting the
  request into timer ownership [R4-3]; the handler relatches and kicks as
  usual; arm failure resolves via the R4-2 fallback. Destructor-only
  recovery is no longer load-bearing.
- The three recovery actions are individually exception-isolated so one
  failure cannot skip the others, no callback runs under either mutex, and
  the two mutexes are never held together across a physical arm [R5-Q4].

### Unwind ordering constraints [R6-4]

- ONE `coalesce_mutex_` critical section performs, together: Abort
  publication + FIFO abandonment (`publish_abort_locked`),
  `driver_active_ = false`, flush-latch clearing, and the publication of
  ERROR recovery ownership (`error_retry_armed_`) when applicable.
  Clearing `driver_active_` before the Abort is published would let a
  timer thread become the driver and emit retained DATA that the Abort is
  about to abandon.
- Callback-kind attribution is by construction, not inference: each
  callback kind is invoked inside its OWN try/catch (DATA send; CLOSE
  send; ERROR send; the post-drain deferred-close/finalize actions), so a
  throw is handled by the handler for exactly the kind that threw —
  Abort-then-terminal for DATA [R7-1], Resolved-guard for CLOSE,
  permanent-settle for ERROR, per-action isolation for post-drain
  actions. No phase flag can be misread because there is none.

### Post-drain exception repair [R7-3]

The driver's three post-drain actions (`emit_close_and_transition`,
`emit_local_close_only`, `finalize_remote_close`) are each wrapped in
their own try/catch; the first captured exception is remembered, the
REMAINING actions still run, and the captured exception is rethrown after
all three have been attempted — a throwing state-change callback in the
first action can no longer skip a deferred remote finalization. Inside
those actions, the obligations that must survive a user-callback throw
are guarded: the close-metric/transition/notify sequence gets an RAII
guard ensuring `maybe_notify_id_releasable()` and `notify_close_once()`
still run when `notify_state_change()` (or the on_close callback itself)
throws mid-sequence — matching the settled principle that a callback
throw may skip nothing but its own remainder. Regressions: throwing
state-change callback after a successful deferred CLOSE; throwing
on_close during remote finalization; first-post-drain-action throw with a
pending remote finalization behind it.

After the R6-4 critical section, the physical arms (ERROR timer, CLOSE
timer) run separately, each holding at most its own guarding mutex,
revalidating epoch + cancellation, individually exception-isolated. ERROR
is armed before CLOSE (non-semantic given the predicates, but it matches
supersession).

### Exception propagation — worker boundary aborts with diagnostics [R9-1, R10-1]

Round 10 demonstrated that blanket catch-and-continue can wedge the
daemon (a throwing on_data_ leaves a socket with no outstanding read; a
throwing accept callback leaks capacity and stops accepting; a throwing
drain-chain send loses a parked frame; a swallowed reload apply() leaves
a promise unfulfilled forever) while the watchdog — which only monitors
the Tox iterate heartbeat — sees nothing. v11 therefore adopts the
conservative alternative: each io_context worker wraps `run()` in
try/catch whose handler LOGS the exception (type + what()), bumps a
metric, and calls `std::abort()`. Today the same exception reaches
std::terminate with no diagnostics, so this is a strict improvement with
zero behavioural risk: the process dies exactly as before, but says why,
and systemd/launchd restarts it (the watchdog-abort pattern this
codebase already relies on). Mechanics [R11-Q1]: the fatal handler is
`noexcept` and best-effort — the log/metric attempt is itself wrapped so
a throwing logger cannot preempt the unconditional `std::abort()`; and
the boundary is ONE shared noexcept fatal-runner helper used by EVERY
site that pumps handlers [R12-3]: the core pool (io_context.cpp:35), the
POSIX client and server signal-context run() sites (cli/main.cpp:999,
cli/main.cpp:1004), the Windows service run() site (cli/main.cpp:1089),
and equivalent containment around the service-mode `poll_one()` loop
(cli/main.cpp:994) — no run()/poll_one() call site remains outside the
diagnostic-abort boundary. Handler-local RAII repair guards
remain the correctness layer that makes such deaths rare; nothing about
them is made moot. Synchronous API callers still receive repaired
exceptions on their own stacks as today. Regression: a throwing handler produces the
diagnostic log line (death test or log assertion, platform permitting).

### In-slice exception-hardening scope [R10-2]

Bounded to what this slice ADDS or TOUCHES:
- all driver guards, the settlement latch, both retry-timer arm guards
  (specified above);
- `TunnelImpl::~TunnelImpl`: the NEW error_retry_timer_ cancel is
  wrapped in try/catch like the backstop it joins;
- `claim_terminal()` made non-throwing END TO END: the timer
  cancellations in `cancel_open_retry_locked()` get local try/catch (a
  failed cancel only leaves an epoch-rejected handler), and the test
  hook — production-null — is invoked through the same local try/catch
  so an unrestricted test hook cannot void the claim contract either;
- `close_all()` / `close_all_local()` per-tunnel loops catch/log and
  continue (their callers include destructors);
- `force_close()` remember-first/finish-all/rethrow-last across its
  obligations as already specified.

PRE-EXISTING and OUT OF SCOPE, filed as its own upstream issue: the
stop() chains' irreversible-latch-then-throwing-cancel shape
(tunnel_client.cpp:375, tunnel_server.cpp equivalent), throwing
timer-cancel overloads in ~TunnelManager (tunnel_manager.cpp:43) and the
pre-existing half of ~TunnelImpl, and completion handlers that run
essential rearm work after user callbacks (tcp_connection.cpp:527/716,
tcp_listener.cpp:262, tunnel_manager.cpp:1485, the reload promise at
tunnel_client.cpp:653). None of these interact with the driver machinery
this slice introduces beyond the worker boundary above; fixing them here
would balloon an already ten-round slice.

### force_close() / teardown exception discipline [R8-2, R9-2, R9-3, R9-4]

`force_close()` (single-tunnel, synchronous API) adopts
remember-first/finish-all/rethrow-last across ALL its obligations,
including the prelude [R9-3]: `claim_terminal()` is made non-throwing —
the timer cancellations inside `cancel_open_retry_locked()` are wrapped
in local try/catch (a failed cancel only leaves a handler the epoch check
already rejects), so the terminal claim can never publish a state and
then lose its notification ownership to a throwing cancel. Then: flush,
announce, Abort publication + ERROR shutdown settlement, pending-
finalizer drain, socket release, state notification, close notification —
the FIRST exception remembered, every step attempted, and that first
exception rethrown at the end (later ones logged) — so the original DATA
exception wins, as the regressions assert [holistic fix].
Regression: injectable cancel/claim failure; throwing DATA during
force_close (socket released, single notification, original exception
surfaced).

Batch teardown does NOT rethrow [R9-2]: `close_all()` and
`close_all_local()`'s per-tunnel loops catch and log per tunnel and
continue — their callers include `TunnelManager`'s destructor and
`TunnelClient`/`TunnelServer::stop()` (invoked from destructors), where a
rethrow terminates the process. Scope note [holistic fix]: this slice
guarantees only that `close_all()` / `close_all_local()` themselves never
propagate; the surrounding stop() chains still contain pre-existing
throwing cancellations BEFORE close_all (tunnel_client.cpp:394) — that
phase isolation is issue #29, out of scope, so no unconditional
all-phases claim is made here.

The two-party terminal finalizer is `noexcept` and returns an
`std::exception_ptr` [R9-4]: per-action isolation inside (fence-lower,
cancel_close_retry, notify_close_once — each in try/catch, first captured
wins), never throws out. A synchronous caller that drains it
(force_close, an arrival site on a sync path) adds the returned
exception_ptr to its own accumulator; an async boundary (timer handler,
destructor) logs it. This reconciles R8-2's accumulator contract with the
noexcept finalizer without ambiguity.

### Gate settlement must not run callbacks under the manager lock [R8-4]

`close_all_local()` calls `close_outbound_gate()` while holding
`TunnelManager::mutex_`, under a documented never-calls-back contract —
and the v6 gate settlement could complete the two-party latch and run
`notify_close_once()` right there (client close callbacks synchronously
re-enter `remove_tunnel_if`). Split publication from delivery: under the
gate's locks the settlement only mutates state (cancel timer, clear slot,
set fences, mark the transport one-shot arrived) and latches
"finalizer pending" when the pair completes; the finalizer itself runs
from the next out-of-lock drain point — force_close (which
close_all_local invokes for every tunnel right after releasing the
manager lock), any later arrival site, or the destructor — via an
internal `run_pending_terminal_finalizer()` called outside all locks.
Regression: an on_close that re-enters the same manager during
close_all_local.

### Resume stale-ACK identity [R8-3 — companion fix, own issue]

The seal/terminal checks close R7-2's eligibility hole, but a stale
RESUME_ACK accepted from the OLD friend can sit in the strand while
failback closes the old tunnel and REUSES its id — the ACK then acts on
the replacement incarnation. This is a PRE-EXISTING defect (reachable
today, independent of this slice) and gets its own upstream issue; the
fix ships as a companion commit in this series: the client records an
outstanding-resume token {endpoint/session generation,
weak_ptr<TunnelImpl>, tunnel_id} before sending TUNNEL_RESUME_REQUEST;
an ACK must match generation AND exact object identity AND id, and
consumes the token. Contract details [R9-5, R10-3], folded into issue
#28: the endpoint-session generation is MONOTONIC, and invalidation is
ONE shared operation [R13-1] — `invalidate_resume_session()`: bump the
generation + erase all outstanding tokens + cancel the deadline timer,
all in the token serialization domain — invoked BEFORE every
session-abandon teardown: disconnect/reconnect, active-endpoint switch,
keepalive-death close_all (tunnel_client.cpp:873/887), and stop()
(tunnel_client.cpp:423), always before teardown/id reuse. SOURCE-SESSION
PROVENANCE [R14-1, R14-2]: every posted event that can later touch
session state carries the {friend_number, generation} key of the session
that ORIGINATED it, captured at event origin — never re-read at
dispatch. Concretely: (a) the reconnect callback posts
`send_resume_requests(expected_session)`; before EACH token publication,
under `endpoints_mutex_`, the producer requires expected_session ==
current session AND the endpoint still active+online AND
!stop_started_, and aborts the remainder of a multi-tunnel batch on the
first mismatch — a delayed post can therefore never repopulate an
invalidated session or force-close a tunnel meant to survive until
reconnect; (b) the keepalive peer-dead event carries its originating
session key and revalidates it before marking the endpoint offline,
invalidating tokens, or calling close_all() — a stale peer-dead from
the old endpoint, queued behind a switch on the multi-threaded pool,
becomes a no-op instead of killing the successor; the switch also
retires and re-arms keepalive ownership. Regressions: post-vs-
disconnect, post-vs-switch, post-vs-stop, mid-batch invalidation, and
the barrier case (old peer-dead queued → switch → new token/tunnel →
release → successor untouched); the request path atomically snapshots
{friend_number, generation} under endpoints_mutex_, publishes the token
for that snapshot, and binds the send to that same friend; ingress
captures the generation during validation (under endpoints_mutex_) and
carries it inside the posted event — never re-read at dispatch; token
publication, lookup, match, consumption and invalidation share one lock;
a mismatched ACK does NOT consume the current token; outbound failure is
TYPED — SendqFull retries under token ownership on the SENDQ cadence,
PermanentFail ERASES the token FIRST and then force-settles the tunnel
(force_close can synchronously release/reuse the id, so the token must
already be gone) [R11-3b]; a duplicate request in one session is
suppressed, never replacing the outstanding token; at most one token per
tunnel object per session. ATOMICITY [R11-3a]: token publication happens
INSIDE the same `endpoints_mutex_` critical section that snapshots
{friend_number, generation} — not merely "under the same lock sometime
later" — so an endpoint switch that bumps the generation and invalidates
tokens can never interleave between snapshot and publication; the switch
invalidates before its unlocked teardown begins. LOST-ACK DISPOSITION
[R11-4, R12-2 — the full mechanism]: the token stores the serialized
request bytes, the retry attempt counter, and a deadline stamped AT
PUBLICATION (inside the snapshot critical section):
`now + max(5s, 8 × sendq_retry_delay(0))`. One dedicated
`asio::steady_timer` per client (`resume_deadline_timer_`) implements an
earliest-deadline MULTI-TOKEN state machine [R13-2], every timer
operation (arm, rearm, cancel, expiry-handler body) inside the token
serialization domain — asio timer objects are not thread-safe, so the
token lock is the single domain: armed/epoch/current-earliest are owned
there; publish-then-arm with the guarded helper; whenever the earliest
token is consumed or invalidated the timer rearms for the next
outstanding deadline (or cancels when none remain); the expiry handler
processes ALL due tokens in one pass, then rearms; a throw while
rearming for the next of several tokens settles THAT token permanently
(erase + force-settle its tunnel, after unlock) and continues with the
remainder — the per-action isolation rule; `invalidate_resume_session()`
cancels the timer and clears every token. Per-token arm failure at
publication erases that token and force-settles immediately. SendqFull on the request retries FROM THE TOKEN'S retained
bytes on the SENDQ cadence under token ownership; every asynchronous
handler — retry or deadline — first revalidates
{generation == token.generation && weak_ptr.lock() == token object}
before acting, so a stale generation-G handler can never erase
generation-G+2's token or force-close the current tunnel; the erase
happens under `endpoints_mutex_`, the `force_close()` call after
unlocking. Expiry removes the token and force-settles that exact tunnel
object — covering both a request whose ACK hit the server's SENDQ and a
lost decline, without touching the server's untyped ACK path in this
series. Deterministic regressions [R12-4, sharpened R13-4], one per
contract: stale ACK vs reused id (barrier after ingress validation,
switch endpoint + reuse id, release; assert the replacement is
untouched AND the mismatched ACK did NOT consume the current token);
snapshot/publication atomicity (barrier between a would-be split
snapshot and publication while a switch runs — must be unobservable);
erase-before-synchronous-id-reuse on PermanentFail; SendqFull retry
ownership (request re-sent from token bytes, attempt advances, AND a
second producer call neither creates a duplicate NOR replaces the
retained bytes/attempt/deadline); deadline expiry force-settles the
exact object; resume-deadline PHYSICAL-ARM failure (injected) settles
per contract; two-token rearm (consuming the earliest rearms for the
next deadline, which then fires); stale deadline/retry handler
suppression across disconnect/reconnect (generation+object
revalidation).

Adjacent debt, explicitly OUT OF SCOPE here: the OPEN retry's own
publish-armed-then-physical-arm window (tunnel.cpp:633) predates this
slice; the new guarded-arm helper is written so the OPEN path can adopt it
in a follow-up.

### DATA-throw completes to terminal, not just a seal [R7-1, R7-2 root cause]

Round 7 showed that leaving a tunnel `Connected + Abort seal` with no
terminal owner strands it at every state-sampled dispatch site
(`close_tunnel_if`, the client's direct close dispatches, resume
eligibility) — `close()` no-ops on the seal, nothing fires `on_close`,
nothing removes the tunnel. Patching each site would chase symptoms. v8
removes the state itself: the driver's per-kind DATA catch, after the
Abort/driver-repair critical section, invokes the internal terminal-ERROR
path — exactly `send_error(code, "outbound transport failure")`'s
machinery: fence-consulting claim (claim-without-deposit if shutdown
already won), deposit, terminal transition loop to Error, producer-party
arrival, close notification — and then rethrows the original exception.
The deposited ERROR is unselected at that moment (we are still the
driver); the unwind guard's recovery arms its retry timer, and the retry
either delivers it or settles permanently through the same throwing
callback (per-attempt catch → permanent settlement). Net effect:
`Connected + seal + no terminal owner` exists only transiently on the
throwing thread's own stack, never as a state any other dispatch can
sample and mishandle. `close_tunnel_if()`, client disconnect routing and
the resume paths therefore see an ordinary Error-state tunnel, which
every existing flow already handles (send_error fires notify_close_once,
the manager's close callback removes it).

Hardening on top (cheap, closes the transient-sample races):
- `abort_teardown_required()` stays in `close_all()` and
  `remove_tunnel_impl()` as specified [R6-2].
- Resume eligibility [R7-2]: both sides exclude sealed-or-terminal
  tunnels via an `outbound_aborted()` accessor — the client skips them
  when building TUNNEL_RESUME_REQUESTs and force-settles instead; the
  server declines and `remove_tunnel_if()`s a sealed held tunnel; both
  REVALIDATE after RESUME_ACK, because a seal can race the
  request/response. Regressions: the `outbound_aborted()` primitive these
  checks read is unit-tested (tunnel_coalesce_test.cpp); the end-to-end
  client-aborted / server-aborted / seal-during-resume behaviors need a
  client/server + tox-adapter harness (integration scope) and are RESCOPED
  and tracked as https://github.com/agentx-icu/tox-tcp-tunnel/issues/31.

### Throwing DATA attempt = Abort, not retry [R5-2, R5-3]

v5's delayed-retry policy for a throwing DATA send is WITHDRAWN. The send
callback is an unrestricted std::function with no "a throw implies the
transport did not accept the frame" contract, so a retry can duplicate
stream bytes — and the lossless guarantee forbids both loss and
duplication. An escaping DATA-callback exception is therefore treated as
PermanentFail at the tunnel level: the driver's unwind guard publishes
Abort (`publish_abort_locked` — seal + abandon the FIFO and deferred-close
bookkeeping) in its coalesce critical section, and no DATA recovery timer
exists at all — which also disposes of R5-3's objection that the coalesce
timer (legal delay 0, weak-ref, unguarded arm) is unfit as a recovery
channel. `total_bytes_emitted_` is NOT rolled back (the commit point is
unknown; post-Abort the counter only bounds ACK clamping on a dead
tunnel — documented at the field). The exception itself continues to
propagate to the caller exactly as today — the guard is RAII state repair,
not a swallow — so no behavioural contract changes for embedders whose
callbacks throw. Terminal-state cleanup does NOT wait for later teardown
paths: the per-kind DATA catch completes to terminal immediately (see
"DATA-throw completes to terminal" above) [holistic fix — the earlier
ride-the-reaper wording was stale].

## CLOSE request semantics [R3-5]

Request success is the atomic transition, under `close_frame_mutex_`:

```
!close_emit_requested_ && !close_retry_armed_
  && state ∈ {NotOwed, Owed}
  && !close_retry_cancelled_ && !terminal_error_claimed_
      → state=Owed, close_emit_requested_=true, return true
```

Anything else returns false: a second racing producer, a request during the
SendqFull backoff (`close_retry_armed_`), during InFlight, or after
resolution — so the metric call sites cannot double-book and no producer can
bypass the backoff by relatching. Timer ownership is published IN the
SendqFull verdict commit itself: the commit sets `close_retry_armed_=true`
(+ epoch/attempt) in the same critical section that records Owed and clears
the request flag; the physical `expires_after`/`async_wait` runs after
release under a re-taken lock validating the epoch. The timer handler is the
only relatcher (clears armed, sets requested, kicks with FlushAll).

## Everything else

Selection order, the commit-side supersession fence
(`terminal_error_claimed_` checked in the CLOSE verdict), the dedicated
error timer, the two-party finalizer (noexcept, per-action isolation:
lower `terminal_error_in_flight_`, cancel_close_retry, notify_close_once),
producer-local bookkeeping for send_error vs close_for_timeout, the driver
exit protocol, FlushAll on CLOSE kicks, `force_close()`'s post-abort kick,
and the staged implementation order (manager routing flip LAST, after
retry/shutdown/selected-attempt/exception/lifetime tests pass [R3-Q5])
are all as specified in v3 and confirmed by round-3.

## New regressions (running list, incl. round-6 additions)

ERROR SendqFull retry until Sent; retry + close_all(stopped io) settlement;
selected-ERROR vs force_close AND vs close_outbound_gate re-park fence;
shutdown/gate/force_close wins BEFORE the claim (claim-without-deposit);
claim-after-sample during live failover (id reserved, PermanentFail
settles, nothing emitted after settlement); close_all(Error) and
remove_tunnel_if(Error) and remove_tunnel_if(sealed-but-Connected) dispatch
(socket released, single close callback); reaper convergence after a
throwing DATA callback; DATA callback re-enters send_error then throws
(ERROR recovery still arms/settles); DATA callback requests CLOSE then
throws (request→timer conversion settles); ERROR PermanentFail and
gate-closed-Sent commits (not only SendqFull→Sent); serialization-failure
claim with an older unselected CLOSE present; physical timer-arm exception
for both timers + cancellation between ownership publication and physical
arm; destructor backstop for a genuinely surviving parked ERROR; throwing
DATA asserts propagation + Abort seal + no coalesce retry + driver
inactive + FIFO abandoned + no total_bytes_emitted_ rollback; throwing
CLOSE/ERROR selected attempts assert their propagation contracts; CLOSE
request refused during backoff; driver CLOSE,ERROR wire order under
reentrant send_error; timeout-vs-send_error claim competition.

Round-8 additions [R8-6]: the existing reentrant-close regression
(tunnel_coalesce_test.cpp:840) is KEPT as behavioural coverage but gains a
discriminating sibling — a barrier immediately after Abort publication and
before the Error transition, close() called from another thread, asserting
no CLOSE (the seal, not the terminal state, is what suppresses); DATA-send
exception + throwing terminal state callback (cleanup completes, the
original DATA exception wins); worker-boundary death/diagnostic test (a
throwing handler produces the logged type+what() before abort — death
test or log assertion, platform permitting) [holistic fix — replaces the
obsolete "nothing escapes run_one" line]; throwing DATA during
force_close (socket released,
single notification, batch teardown continues); on_close re-entering the
manager during close_all_local; stale RESUME_ACK vs reused id
(companion).

## Questions for the reviewer

1. The scope split: is the CORE list complete and genuinely free of
   dependence on the provenance companions (i.e. no core mechanism
   requires a session generation to be correct)?
2. R15-1/R15-2/R15-5 as folded into Companion A, and R15-3/R15-4 as
   Companion B with the corrected drop disposition — accurately
   captured?
3. Given the split, is the CORE implementable as specified TODAY —
   please answer this separately from the companions.
4. For the companions, is anything in the round-15 contracts still
   under-specified enough to block THEIR later implementation?
5. Final verdict on the split: APPROVE (core implementation may start,
   companions proceed as tracked issues) or NEEDS-CHANGES (name what
   blocks the CORE specifically).
