#!/usr/bin/env python3
"""Live two-daemon smoke test (issue #46).

Every bug fixed in the qa5 cross-platform round was invisible to the unit and
integration suites and only showed up between live daemons. This harness runs
real toxtunnel processes on loopback (bootstrap_mode: lan, pinned to each
other, no internet) and checks the behaviours those bugs broke:

  echo                 a forward carries data both ways (and loopback throughput)
  bulk_open_latency    a new tunnel's open + first echo while a bulk download
                       is demonstrably flowing on the same friend
  rst_target_to_app    the target resets THIS connection -> the application
                       sees ECONNRESET
  rst_app_to_target    the application resets an established connection -> the
                       target sees a reset on that same connection
  half_close           a specific tunnel left half-closed (its target never
                       closes) is reaped by the half-close cap, not earlier
  keepalive_recovery   the server freezes -> an established connection is reset
                       promptly; the client recovers when the server answers
  failover             two servers: the active one freezes -> an established
                       connection is reset and the client fails over to B;
                       A recovers -> prefer-primary switches back to A
  client_first         a connection accepted while the server is not up yet is
                       held and carried once the server appears

It prints one JSON document (also written to --out): per-scenario pass/fail
and measurements, plus a performance record (loopback throughput, open
latency, CPU seconds per daemon, RTT / send-window / bandwidth summaries
scraped from /metrics) for release-to-release baselines.

The server and client binaries may differ (mixed-version runs, issue #46
item 2). Scenarios that need behaviour an older peer lacks are selected out
with --skip (see docs/TESTING.md for the table).

Usage:
  live_smoke.py --server-bin build/toxtunnel --client-bin build/toxtunnel \\
                [--out live-smoke.json] [--only a,b] [--skip a,b] [--keep]
Exit status: 0 when every selected scenario passed, 1 otherwise.
"""

import argparse
import glob
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ALL_SCENARIOS = [
    "echo",
    "bulk_open_latency",
    "rst_target_to_app",
    "rst_app_to_target",
    "half_close",
    "keepalive_recovery",
    "failover",
    "client_first",
]

KEEPALIVE_S = 1
HALF_CLOSE_S = 4
FAILOVER_TIMEOUT_S = 3
FAILOVER_GRACE_S = 5
OFFLINE_WAIT_S = 120


def stamp():
    """Local time in the daemons' log format, to the millisecond."""
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t * 1000) % 1000:03d}"


# ---------------------------------------------------------------------------
# Targets: one TCP service, the first line decides the behaviour:
#   "<VERB> <token>[ <arg>]\n"  with VERB in ECHO | RST | SINK | DOWN.
# Every connection carries a unique token, so an outcome is attributed to the
# connection that produced it, never to an older one.
# ---------------------------------------------------------------------------

class Targets:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.events = {}  # token -> list of outcomes
        self.cond = threading.Condition()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            # Daemon threads: a SINK that holds its socket does not keep the
            # harness alive.
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _note(self, token, how):
        with self.cond:
            self.events.setdefault(token, []).append(how)
            self.cond.notify_all()

    def wait(self, token, how, timeout):
        """True once `how` was recorded for `token`."""
        end = time.time() + timeout
        with self.cond:
            while how not in self.events.get(token, []):
                left = end - time.time()
                if left <= 0:
                    return False
                self.cond.wait(left)
            return True

    def outcomes(self, token):
        with self.cond:
            return list(self.events.get(token, []))

    def _serve(self, c):
        token = "?"
        try:
            # The command line straight off the socket: a buffered reader would
            # swallow the bytes that follow it.
            buf = b""
            while b"\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            line, _, rest = buf.partition(b"\n")
            parts = line.decode(errors="replace").split()
            verb, token = parts[0], parts[1]
            self._note(token, "accepted")
            if verb == "ECHO":
                if rest:
                    c.sendall(rest)
                while True:
                    d = c.recv(65536)
                    if not d:
                        self._note(token, "eof")
                        break
                    c.sendall(d)
            elif verb == "RST":
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self._note(token, "sent-rst")
            elif verb == "SINK":
                # Read and discard; after the peer's FIN keep the socket open
                # and silent, so only the half-close cap can end the tunnel.
                while c.recv(65536):
                    pass
                self._note(token, "eof")
                time.sleep(3600)
            elif verb == "DOWN":
                left = int(parts[2])
                chunk = b"d" * 65536
                while left > 0:
                    left -= c.send(chunk[: min(left, len(chunk))])
                self._note(token, "done")
        except ConnectionResetError:
            self._note(token, "reset")
        except (OSError, IndexError, ValueError) as e:
            self._note(token, f"error:{e!r}")
        finally:
            try:
                c.close()
            except OSError:
                pass


def new_token():
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

class PortPool:
    """Distinct free ports for one rig: every probe socket stays bound until
    the whole set is chosen, so the kernel cannot hand out a port twice."""

    def __init__(self):
        self.held = []

    def take(self, kind):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        self.held.append(s)
        return s.getsockname()[1]

    def release(self):
        for s in self.held:
            s.close()
        self.held = []


# ---------------------------------------------------------------------------
# Daemons
# ---------------------------------------------------------------------------

class Daemon:
    def __init__(self, name, binary, workdir):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(workdir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.config = os.path.join(self.dir, "config.yaml")
        self.log = os.path.join(self.dir, "daemon.log")
        self.proc = None
        self.paused = False
        self.metrics_port = None

    def write(self, text):
        with open(self.config, "w") as f:
            f.write(text)

    def start(self):
        out = open(os.path.join(self.dir, "stdout.log"), "a")
        self.proc = subprocess.Popen([self.binary, "-c", self.config], stdout=out,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     cwd=self.dir, start_new_session=True)
        self.paused = False

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.alive():
            if self.paused:
                self.resume()
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def pause(self):
        os.kill(self.proc.pid, signal.SIGSTOP)
        self.paused = True

    def resume(self):
        if self.alive():
            os.kill(self.proc.pid, signal.SIGCONT)
        self.paused = False

    def cpu_seconds(self):
        try:
            with open(f"/proc/{self.proc.pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
        except (OSError, IndexError, ValueError, AttributeError):
            return None

    def lines_since(self, since):
        """Log lines stamped at or after `since`, across rotated files too."""
        out = []
        for path in sorted(glob.glob(os.path.join(self.dir, "daemon*.log"))):
            try:
                with open(path, errors="replace") as f:
                    out.extend(l for l in f if l[1:24] >= since)
            except OSError:
                pass
        out.sort(key=lambda l: l[1:24])
        return out

    def wait_log(self, needle, timeout, since="0"):
        """The first line containing `needle` stamped at/after `since`, or None."""
        end = time.time() + timeout
        while time.time() < end:
            for line in self.lines_since(since):
                if needle in line:
                    return line.strip()
            if self.proc is not None and not self.alive():
                return None
            time.sleep(0.2)
        return None

    def tox_id(self, timeout=30):
        line = self.wait_log("Tox ID:", timeout)
        if line is None:
            raise RuntimeError(f"{self.name}: no Tox ID in its log")
        return line.rsplit("Tox ID:", 1)[1].split()[0]

    def inspect(self, what="status"):
        try:
            r = subprocess.run([self.binary, "inspect", what, "--json", "-c", self.config],
                               capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            return None
        if r.returncode != 0 or not r.stdout.strip():
            return None
        try:
            return json.loads(r.stdout)
        except ValueError:
            return None

    def tunnels(self):
        """{id: tunnel} from a successful inspect, or None if inspect failed —
        never an empty map that would read as "every tunnel is gone"."""
        doc = self.inspect("tunnels")
        if not doc or "tunnels" not in doc:
            return None
        return {t["id"]: t for t in doc["tunnels"]}

    def reload(self):
        subprocess.run([self.binary, "reload", "-c", self.config], capture_output=True, timeout=10)

    def metrics(self):
        """Selected /metrics series (summary count/sum/max), or {}."""
        if not self.metrics_port:
            return {}
        try:
            body = urllib.request.urlopen(f"http://127.0.0.1:{self.metrics_port}/metrics",
                                          timeout=5).read().decode()
        except OSError:
            return {}
        keep = ("toxtunnel_tunnel_rtt_microseconds", "toxtunnel_tunnel_send_window_bytes",
                "toxtunnel_tunnel_bandwidth_bytes_per_second", "toxtunnel_tox_iterate_lag",
                "toxtunnel_bytes_in_total", "toxtunnel_bytes_out_total")
        out = {}
        for line in body.splitlines():
            if line.startswith("#") or " " not in line:
                continue
            name, value = line.rsplit(" ", 1)
            if name.startswith(keep):
                try:
                    out[name] = float(value)
                except ValueError:
                    pass
        return out


def common_tunnel_yaml():
    return f"""tunnel:
  keepalive_interval_seconds: {KEEPALIVE_S}
  half_close_timeout_seconds: {HALF_CLOSE_S}
  reaper_tick_seconds: 1
  offline_open_wait_seconds: {OFFLINE_WAIT_S}
inspect:
  enabled: true
"""


def node_yaml(nodes):
    if not nodes:
        return ""
    return "  bootstrap_nodes:\n" + "\n".join(
        f'    - {{address: "127.0.0.1", port: {p}, public_key: "{k}"}}' for p, k in nodes) + "\n"


def server_yaml(d, udp, tcp, metrics, rules, nodes=()):
    return f"""mode: server
data_dir: {d.dir}/data
logging:
  level: info
  file: {d.log}
tox:
  udp_enabled: true
  udp_port: {udp}
  tcp_port: {tcp}
  bootstrap_mode: lan
{node_yaml(nodes)}server:
  rules_file: {rules}
metrics:
  enabled: true
  listen: "127.0.0.1:{metrics}"
""" + common_tunnel_yaml()


def client_yaml(d, udp, metrics, servers, nodes, forward_port, target_port):
    ids = ", ".join(f'"{s}"' for s in servers)
    node_block = node_yaml(nodes)
    return f"""mode: client
data_dir: {d.dir}/data
logging:
  level: info
  file: {d.log}
tox:
  udp_enabled: true
  udp_port: {udp}
  bootstrap_mode: lan
{node_block}client:
  server_id: [{ids}]
  failover:
    timeout_seconds: {FAILOVER_TIMEOUT_S}
    prefer_primary_grace_seconds: {FAILOVER_GRACE_S}
  forwards:
    - {{local_port: {forward_port}, local_address: 127.0.0.1, remote_host: 127.0.0.1, remote_port: {target_port}}}
metrics:
  enabled: true
  listen: "127.0.0.1:{metrics}"
""" + common_tunnel_yaml()


class Rig:
    """Servers A (and B for failover) and one client, wired to each other."""

    def __init__(self, args, workdir, n_servers):
        self.args = args
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.targets = Targets()
        self.rules = os.path.join(workdir, "rules.yaml")
        with open(self.rules, "w") as f:
            f.write("rules: []\n")
        self.servers = [Daemon("server" + "AB"[i], args.server_bin, workdir)
                        for i in range(n_servers)]
        self.client = Daemon("client", args.client_bin, workdir)

    def daemons(self):
        return self.servers + [self.client]

    def up(self):
        pool = PortPool()
        self.forward_port = pool.take("tcp")
        for s in self.servers:
            s.udp, s.tcp, s.metrics_port = pool.take("udp"), pool.take("tcp"), pool.take("tcp")
        self.client.udp, self.client.metrics_port = pool.take("udp"), pool.take("tcp")
        pool.release()
        for s in self.servers:
            s.write(server_yaml(s, s.udp, s.tcp, s.metrics_port, self.rules))
            s.start()
        ids, nodes = [], []
        for s in self.servers:
            s.id = s.tox_id()
            st = None
            deadline = time.time() + 5
            while time.time() < deadline:
                st = s.inspect()
                if st and st.get("dht_public_key"):
                    break
                time.sleep(0.3)
            ids.append(s.id)
            if st and st.get("dht_public_key"):
                nodes.append((s.udp, st["dht_public_key"]))
            # A server older than v0.5.0 does not report its DHT key; the
            # client then finds it through LAN discovery alone.
        self.client.write(client_yaml(self.client, self.client.udp, self.client.metrics_port, ids,
                                      nodes, self.forward_port, self.targets.port))
        self.client.start()
        client_id = self.client.tox_id()
        with open(self.rules, "w") as f:
            f.write(f"""rules:
  - friend: "{client_id[:64]}"
    allow:
      - host: "127.0.0.1"
        ports: [{self.targets.port}]
""")
        for s in self.servers:
            s.reload()
        # Ready = data flows; which server got there first does not matter.
        if not wait_echo(self, 120):
            raise RuntimeError("no echo through the tunnel after setup")
        if len(self.servers) > 1:
            # A multi-server client may have started on B (A connected later);
            # prefer-primary then moves it to A after the grace. Scenarios
            # assume A is active, so wait until the current route is A and
            # has stayed A past the grace.
            a = self.servers[0].id[:12]
            deadline = time.time() + FAILOVER_GRACE_S + 60
            settled_since = None
            while time.time() < deadline:
                switches = active_switches(self, "0")
                on_a = not switches or switches[-1] == a
                settled_since = (settled_since or time.time()) if on_a else None
                if settled_since and time.time() - settled_since > FAILOVER_GRACE_S + 2:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("multi-server client did not settle on the primary")
            if not wait_echo(self, 30):
                raise RuntimeError("no echo through the primary after settling")

    def down(self):
        for d in self.daemons():
            d.stop()


def bring_up(args, workdir, n_servers, attempts=3):
    """A rig; retried on a fresh port set if a daemon could not bind."""
    last = None
    for i in range(attempts):
        rig = Rig(args, os.path.join(workdir, f"try{i}"), n_servers)
        try:
            rig.up()
            return rig
        except Exception as e:  # noqa: BLE001 - reported below
            last = e
            rig.down()
    raise RuntimeError(f"rig setup failed {attempts} times: {last!r}")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def connect(rig, timeout=20):
    s = socket.create_connection(("127.0.0.1", rig.forward_port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def echo_on(s, payload=b"ping", timeout=20):
    """Send and read back `payload` on an open ECHO connection."""
    s.settimeout(timeout)
    s.sendall(payload)
    got = b""
    while len(got) < len(payload):
        d = s.recv(len(payload) - len(got))
        if not d:
            return False
        got += d
    return got == payload


def open_echo(rig, timeout=20):
    """A fresh, verified ECHO connection (socket, token), or (None, token)."""
    token = new_token()
    try:
        s = connect(rig, timeout)
        s.sendall(f"ECHO {token}\n".encode())
        if echo_on(s, b"x", timeout):
            return s, token
        s.close()
    except OSError:
        pass
    return None, token


def open_echo_ms(rig, timeout=20):
    t0 = time.time()
    s, _ = open_echo(rig, timeout)
    if s is None:
        return None
    s.close()
    return round((time.time() - t0) * 1000)


def wait_echo(rig, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if open_echo_ms(rig, 5) is not None:
            return True
        time.sleep(0.5)
    return False


class Download(threading.Thread):
    """A DOWN transfer whose progress the test can watch."""

    def __init__(self, rig, n):
        super().__init__(daemon=True)
        self.rig, self.n = rig, n
        self.got = 0
        self.error = None
        self.seconds = None
        self.sock = None

    def run(self):
        try:
            self.sock = connect(self.rig, 120)
            self.sock.sendall(f"DOWN {new_token()} {self.n}\n".encode())
            t0 = time.time()
            while self.got < self.n:
                d = self.sock.recv(262144)
                if not d:
                    break
                self.got += len(d)
            self.seconds = time.time() - t0
        except OSError as e:
            self.error = repr(e)
        finally:
            if self.sock:
                self.sock.close()

    def cancel(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def read_outcome(s, timeout):
    """'reset' | 'eof' | 'timeout' | 'data' for the next read on `s`."""
    s.settimeout(timeout)
    try:
        d = s.recv(100)
        return "eof" if d == b"" else "data"
    except ConnectionResetError:
        return "reset"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return f"error:{e.errno}"


def active_switches(rig, since):
    """The '-> <prefix>' targets of every failover switch logged since `since`."""
    out = []
    for line in rig.client.lines_since(since):
        if "Failover: switching active server" in line and "-> " in line:
            out.append(line.split("-> ", 1)[1].split("...")[0])
    return out


# ---------------------------------------------------------------------------
# Scenarios. Each returns (passed, details).
# ---------------------------------------------------------------------------

def sc_echo(rig, perf):
    ms = [open_echo_ms(rig) for _ in range(5)]
    perf["idle_open_echo_ms"] = ms
    dl = Download(rig, 32 << 20)
    dl.start()
    dl.join(180)
    if dl.seconds:
        perf["loopback_download_MBps"] = round(dl.got / dl.seconds / 1e6, 2)
    ok = all(m is not None for m in ms) and dl.got == dl.n and not dl.is_alive()
    return ok, {"open_echo_ms": ms, "downloaded": dl.got, "error": dl.error}


def sc_bulk_open_latency(rig, perf, bound_ms):
    dl = Download(rig, 512 << 20)
    dl.start()
    samples, flowing = [], []
    try:
        # The bulk transfer must be moving before and during every probe.
        deadline = time.time() + 30
        while dl.got < (4 << 20) and dl.is_alive() and time.time() < deadline:
            time.sleep(0.1)
        for _ in range(5):
            before = dl.got
            samples.append(open_echo_ms(rig, 30))
            time.sleep(0.3)
            flowing.append(dl.got > before)
    finally:
        dl.cancel()
        dl.join(30)
    perf["bulk_open_echo_ms"] = samples
    ok = (len(samples) == 5 and all(flowing) and
          all(m is not None and m <= bound_ms for m in samples))
    return ok, {"open_echo_ms": samples, "bound_ms": bound_ms, "bulk_flowing": flowing,
                "bulk_bytes": dl.got}


def sc_rst_target_to_app(rig, perf):
    token = new_token()
    s = connect(rig)
    s.sendall(f"RST {token}\n".encode())
    target_reset = rig.targets.wait(token, "sent-rst", 15)
    outcome = read_outcome(s, 5)  # promptly, not via some later teardown
    s.close()
    return target_reset and outcome == "reset", {"target_sent_rst": target_reset,
                                                 "application_saw": outcome}


def sc_rst_app_to_target(rig, perf):
    s, token = open_echo(rig)
    if s is None:
        return False, {"established": False}
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    reset = rig.targets.wait(token, "reset", 10)
    return reset, {"established": True, "target_saw": rig.targets.outcomes(token)}


def sc_half_close(rig, perf):
    snap = rig.client.tunnels()
    if snap is None:
        return False, {"inspect": "failed"}
    before = set(snap)
    token = new_token()
    s = connect(rig)
    s.sendall(f"SINK {token}\n".encode())
    if not rig.targets.wait(token, "accepted", 15):
        s.close()
        return False, {"target_accepted": False}
    snap = rig.client.tunnels()
    new_ids = set(snap) - before if snap is not None else set()
    if len(new_ids) != 1:
        s.close()
        return False, {"new_tunnels": sorted(new_ids)}
    tid = new_ids.pop()
    since = stamp()
    s.shutdown(socket.SHUT_WR)  # one-sided close; the target never closes back
    t0 = time.time()
    state_after_fin = None
    reaped = None
    while time.time() - t0 < HALF_CLOSE_S + 15:
        snap = rig.client.tunnels()
        if snap is None:
            time.sleep(0.25)  # a failed inspect proves nothing either way
            continue
        t = snap.get(tid)
        if t is None:
            reaped = round(time.time() - t0, 1)
            break
        if t.get("state") == "Disconnecting":
            state_after_fin = "Disconnecting"
        time.sleep(0.25)
    capped = rig.client.wait_log(f"Tunnel {tid} force-closed after half-close linger timeout", 2,
                                 since)
    s.close()
    ok = reaped is not None and reaped >= HALF_CLOSE_S - 1 and state_after_fin == "Disconnecting"
    # Builds that predate the log line still have to satisfy the timing.
    return ok, {"tunnel": tid, "state_after_fin": state_after_fin, "reaped_after_s": reaped,
                "cap_s": HALF_CLOSE_S, "cap_logged": capped is not None,
                "target_saw": rig.targets.outcomes(token)}


def sc_keepalive_recovery(rig, perf):
    a = rig.servers[0]
    s, _ = open_echo(rig)  # an established tunnel: an idle manager is never judged dead
    if s is None:
        return False, {"established": False}
    since = stamp()
    t0 = time.time()
    a.pause()
    try:
        outcome = read_outcome(s, 3 * KEEPALIVE_S + 15)
        reset_after = round(time.time() - t0, 1)
    finally:
        s.close()
        a.resume()
    recovered = rig.client.wait_log("responsive again", 30, since) is not None
    ok_after = wait_echo(rig, 30)
    return (outcome == "reset" and recovered and ok_after,
            {"application_saw": outcome, "after_s": reset_after, "client_recovered": recovered,
             "echo_after_recovery": ok_after})


def sc_failover(rig, perf):
    a, b = rig.servers
    s, _ = open_echo(rig)  # established on A
    if s is None:
        return False, {"established": False}
    since = stamp()
    a.pause()
    try:
        outcome = read_outcome(s, 3 * KEEPALIVE_S + FAILOVER_TIMEOUT_S + 20)
        deadline = time.time() + 20
        while time.time() < deadline and b.id[:12] not in active_switches(rig, since):
            time.sleep(0.25)
        via_b = wait_echo(rig, 20)
    finally:
        s.close()
        a.resume()
    since2 = stamp()
    deadline = time.time() + FAILOVER_GRACE_S + 30
    while time.time() < deadline and a.id[:12] not in active_switches(rig, since2):
        time.sleep(0.25)
    via_a = wait_echo(rig, 20)
    to_b = b.id[:12] in active_switches(rig, since)
    back_to_a = a.id[:12] in active_switches(rig, since2)
    return (outcome == "reset" and to_b and via_b and back_to_a and via_a,
            {"connection_on_A_saw": outcome, "failed_over_to_B": to_b, "echo_via_B": via_b,
             "switched_back_to_A": back_to_a, "echo_via_A": via_a})


def sc_client_first(rig, perf):
    for d in rig.daemons():
        d.stop()
    since = stamp()
    rig.client.start()
    if rig.client.wait_log("Tox ID:", 30, since) is None:
        return False, {"client_started": False}
    # A restarted server has a fresh DHT key, so the client's pinned nodes
    # are stale and LAN discovery is not reliable on CI runners: pin the
    # servers to the client's (current) DHT key instead.
    key = None
    deadline = time.time() + 10
    while key is None and time.time() < deadline:
        st = rig.client.inspect()
        key = st.get("dht_public_key") if st else None
        if key is None:
            time.sleep(0.3)
    if key:
        for srv in rig.servers:
            srv.write(server_yaml(srv, srv.udp, srv.tcp, srv.metrics_port, rig.rules,
                                  [(rig.client.udp, key)]))
    time.sleep(2)
    # Accepted while no server is up: the client must hold it, not drop it.
    token = new_token()
    s = connect(rig)
    s.sendall(f"ECHO {token}\n".encode())
    time.sleep(2)
    t0 = time.time()
    for srv in rig.servers:
        srv.start()
    try:
        carried = echo_on(s, b"held", OFFLINE_WAIT_S - 10)
    except OSError:
        carried = False
    took = round(time.time() - t0, 1)
    s.close()
    perf["client_first_echo_s"] = took
    return carried, {"held_connection_carried": carried, "after_server_start_s": took,
                     "servers_pinned_to_client": bool(key)}


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--client-bin", required=True)
    ap.add_argument("--out")
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    ap.add_argument("--bulk-open-bound-ms", type=int, default=3000,
                    help="open + first echo bound while a bulk download runs (loopback)")
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    args = ap.parse_args()
    # The daemons run with their own working directories.
    args.server_bin = os.path.abspath(args.server_bin)
    args.client_bin = os.path.abspath(args.client_bin)

    selected = [s for s in ALL_SCENARIOS if (not args.only or s in args.only.split(","))
                and s not in args.skip.split(",")]
    workdir = tempfile.mkdtemp(prefix="tt-live-")
    result = {"server_bin": args.server_bin, "client_bin": args.client_bin, "scenarios": {},
              "perf": {}}
    for b in ("server_bin", "client_bin"):
        try:
            result[b.replace("_bin", "_version")] = subprocess.run(
                [getattr(args, b), "--version"], capture_output=True, text=True,
                timeout=10).stdout.strip()
        except OSError as e:
            result[b.replace("_bin", "_version")] = f"error: {e}"

    # Single-server scenarios share one rig; failover needs two servers;
    # client_first restarts everything, so it runs last on its own rig.
    single = [s for s in selected if s not in ("failover", "client_first")]
    order = [("single", single, 1), ("dual", [s for s in selected if s == "failover"], 2),
             ("first", [s for s in selected if s == "client_first"], 1)]
    perf = result["perf"]
    all_ok = True
    for kind, names, n_servers in order:
        if not names:
            continue
        rig = None
        try:
            rig = bring_up(args, os.path.join(workdir, kind), n_servers)
            for name in names:
                t0 = time.time()
                try:
                    fn = globals()["sc_" + name]
                    if name == "bulk_open_latency":
                        ok, details = fn(rig, perf, args.bulk_open_bound_ms)
                    else:
                        ok, details = fn(rig, perf)
                except Exception as e:  # noqa: BLE001 - a crashed scenario failed
                    ok, details = False, {"exception": repr(e)}
                details["seconds"] = round(time.time() - t0, 1)
                result["scenarios"][name] = {"passed": ok, **details}
                all_ok &= ok
                print(f"{'PASS' if ok else 'FAIL'} {name} {json.dumps(details)}", flush=True)
            perf[f"{kind}_cpu_seconds"] = {d.name: d.cpu_seconds() for d in rig.daemons()}
            perf[f"{kind}_metrics"] = {d.name: d.metrics() for d in rig.daemons()}
        except Exception as e:  # noqa: BLE001
            all_ok = False
            for name in names:
                result["scenarios"].setdefault(name, {"passed": False, "setup_error": repr(e)})
            print(f"FAIL setup({kind}) {e!r}", flush=True)
        finally:
            if rig is not None:
                rig.down()

    result["passed"] = all_ok
    doc = json.dumps(result, indent=2)
    print(doc)
    if args.out:
        with open(args.out, "w") as f:
            f.write(doc + "\n")
    if args.keep or not all_ok:
        print(f"work directory kept: {workdir}", file=sys.stderr)
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
