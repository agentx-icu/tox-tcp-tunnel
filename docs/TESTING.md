# Testing ToxTunnel

Four layers, from fastest to slowest. Every layer catches bugs the ones above
it cannot — most field bugs so far were invisible to the unit and integration
suites and only appeared between live daemons.

| Layer | Where | Runs | What it proves |
|---|---|---|---|
| Unit / integration | `tests/unit`, `tests/integration` (`ctest -L unit`, `-L integration`) | CI on six platforms | component logic, frame-level protocol, error paths |
| Live smoke | `tests/live/live_smoke.py` | CI (`live-smoke`) | real daemons talk: data, resets, timeouts, failover |
| Mixed versions | the same harness, one side a released binary | CI (`mixed-version`) | wire compatibility with released peers |
| Source archive | CI (`source-archive`) | CI | a tree without `.git` reports and packages the right version |
| Four-platform rig | manual, before a release | Linux x86_64, macOS arm64, Linux arm64, Windows arm64 | real networks, NAT, sleep/suspend, service managers |

## Live smoke (`tests/live/live_smoke.py`)

Starts real `toxtunnel` processes on loopback (`bootstrap_mode: lan`, each
daemon pinned to the other's DHT key read through `inspect status`; no internet
needed), wires their identities and rules automatically, and runs:

| Scenario | Checks |
|---|---|
| `echo` | data both ways; a complete 32 MiB download (loopback throughput) |
| `bulk_open_latency` | open + first echo of a new tunnel stays under `--bulk-open-bound-ms` (default 3000) while a download is shown to be moving on the same friend before and during every probe |
| `rst_target_to_app` | the target resets *this* connection (correlated by a per-connection token) and the application sees `ECONNRESET` within seconds (#35) |
| `rst_app_to_target` | an application resets an *established* connection and the target sees a reset on that same connection (#44) |
| `half_close` | the specific tunnel the test half-closed (its target never closes back) goes `Disconnecting` and is removed no earlier than `tunnel.half_close_timeout_seconds`; the cap's log line is recorded when the build has it |
| `keepalive_recovery` | with an established connection, a frozen (`SIGSTOP`) server is judged dead and that connection is reset promptly (#41); the client logs recovery when the server answers, and new tunnels work |
| `failover` | two servers: with an established connection on A, A freezes → that connection is reset and the client switches to B (by Tox ID) and carries data; A recovers → the client switches back to A (#43) and carries data |
| `client_first` | a connection accepted while the server is not up yet is held and carried, on the same socket, once the server appears (`tunnel.offline_open_wait_seconds`) |

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel
python3 tests/live/live_smoke.py --server-bin build/toxtunnel --client-bin build/toxtunnel \
    --out live-smoke.json
# a subset:            --only echo,failover
# leave something out: --skip client_first
# keep the logs:       --keep   (always kept on failure; the path is printed)
```

Linux only (it reads CPU time from `/proc`); Python 3 standard library only.
It exits non-zero when any selected scenario fails.

### Performance record

The JSON document's `perf` section is the per-run baseline: idle open + echo
latency, open + echo latency under bulk, loopback download throughput, the time
a client-first start takes to carry data, CPU seconds per daemon, and each
daemon's RTT, send-window and bandwidth summaries (count / sum / max) scraped
from `/metrics`. CI keeps
it as the `live-smoke` artifact; for a release, save the tag's artifact next to
the release notes so the next release can be compared against it. Loopback
numbers measure ToxTunnel's own overhead, not a network — slow-path behaviour
(the 6–16 kB/s regime where control-frame latency matters most) is measured on
the netem lab described below.

## Mixed versions

The same harness with `--server-bin` and `--client-bin` from different
releases. CI runs this build against the latest v0.5 and v0.4 releases in both
directions. Each combination skips only what the older side cannot do:

| Older side | Skipped | Why |
|---|---|---|
| v0.5.x client | `rst_app_to_target`, `keepalive_recovery`, `failover` | no client-side reset on an application RST / abandon (#41, #44), no standby probing (#43) |
| v0.5.x server | `rst_app_to_target` | does not reset the target on a client `TUNNEL_ERROR` (#44) |
| v0.4.x server | also `rst_target_to_app`, `keepalive_recovery`, `failover` | predates `TUNNEL_ERROR` code 4 (#35); stops answering a client once its own keepalive tore that client's manager down (#36) |
| v0.4.x client | `rst_target_to_app`, `client_first`, plus the v0.5.x client list | does not reset on code 4; drops a connection accepted while offline (held since v0.5.0) |

A scenario that starts failing for a combination it used to pass is a
compatibility regression.

## Source archive

`source-archive` exports the tree with `git ls-files --recurse-submodules`
(no `.git`), builds it, packages a DEB, and requires `toxtunnel --version`, the
package file name and the package's `Version` field to equal the
`project(... VERSION)` in `CMakeLists.txt`.

## Slow-path lab (netem)

Loopback is too fast to show head-of-line blocking. For flow-control and
latency changes, run the same pair behind `tc netem` on its Tox UDP ports only
(never a bare netem on `lo` — anything else using loopback suffers too), e.g.
160 ms each way and 800 kbit/s, where toxcore delivers roughly 6–16 kB/s, and
compare the old and new builds in alternating rounds on the same host. Live
slow-path numbers drift run to run, so do not compare across days.

## Before a release: the four-platform rig

Run the release candidate on Linux x86_64, macOS arm64, Linux arm64 and
Windows arm64 against each other, with real networks between them (direct UDP,
TCP relay, NAT), installed as services. Things only this finds: transport
changes and reconnects, host sleep / VM suspend vs the watchdog, service-manager
restarts, platform socket semantics (RST vs FIN), proxies. QA installers for
any branch: `gh workflow run ci.yml -f packages=true`.
