#!/usr/bin/env python3
"""Live two-daemon smoke test (issue #46).

Every bug fixed in the qa5 cross-platform round was invisible to the unit and
integration suites and only showed up between live daemons. This harness runs
real toxtunnel processes on loopback (bootstrap_mode: lan, pinned to each
other, no internet) and checks the behaviours those bugs broke:

  echo                 a forward carries data both ways
  bulk_open_latency    a new tunnel's open + first echo while a bulk download
                       runs on the same friend (control frames behind DATA)
  rst_target_to_app    a target reset reaches the application as ECONNRESET
  rst_app_to_target    an application reset reaches the target as a reset
  half_close           a tunnel left half-closed is reaped by the half-close cap
  keepalive_recovery   a wedged server is judged dead (application reset fast)
                       and the client recovers when it answers again
  failover             with two servers: the active one wedges -> failover;
                       it recovers -> prefer-primary switches back
  client_first         the client starts before its server

It prints one JSON document (also written to --out): per-scenario pass/fail
and measurements, plus a performance record (loopback throughput, open
latency, CPU seconds per daemon) for release-to-release baselines.

The server and client binaries may differ (mixed-version runs, issue #46
item 2). Scenarios that need behaviour an older peer lacks are selected out
with --skip.

Usage:
  live_smoke.py --server-bin build/toxtunnel --client-bin build/toxtunnel \\
                [--out live-smoke.json] [--only a,b] [--skip a,b] [--keep]
Exit status: 0 when every selected scenario passed, 1 otherwise.
"""

import argparse
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


# ---------------------------------------------------------------------------
# Targets: one TCP service, the verb on the first line decides the behaviour.
# ---------------------------------------------------------------------------

class Targets:
    """ECHO | RST | SINK | DOWN <n>.  Records how each connection ended.

    Each connection is served on a daemon thread, so a SINK that holds its
    socket open does not keep the harness alive."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.ended = []  # (verb, how)
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _note(self, verb, how):
        with self.lock:
            self.ended.append((verb, how))

    def _serve(self, c):
        verb = "?"
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
            verb, _, arg = line.decode(errors="replace").strip().partition(" ")
            if verb == "ECHO":
                if rest:
                    c.sendall(rest)
                while True:
                    d = c.recv(65536)
                    if not d:
                        self._note(verb, "eof")
                        break
                    c.sendall(d)
            elif verb == "RST":
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self._note(verb, "sent-rst")
            elif verb == "SINK":
                # Read and discard; after the peer's FIN keep the socket open
                # and silent, so only the half-close cap can end the tunnel.
                while c.recv(65536):
                    pass
                self._note(verb, "eof")
                time.sleep(3600)
            elif verb == "DOWN":
                left = int(arg)
                chunk = b"d" * 65536
                while left > 0:
                    n = c.send(chunk[: min(left, len(chunk))])
                    left -= n
                self._note(verb, "done")
        except ConnectionResetError:
            self._note(verb, "reset")
        except OSError as e:
            self._note(verb, f"error:{e.errno}")
        finally:
            try:
                c.close()
            except OSError:
                pass

    def last(self, verb, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for v, how in reversed(self.ended):
                    if v == verb:
                        return how
            time.sleep(0.05)
        return None

    def clear(self):
        with self.lock:
            self.ended.clear()


# ---------------------------------------------------------------------------
# Daemons
# ---------------------------------------------------------------------------

def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def free_tcp_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Daemon:
    def __init__(self, name, binary, workdir):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(workdir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.config = os.path.join(self.dir, "config.yaml")
        self.log = os.path.join(self.dir, "daemon.log")
        self.proc = None
        self.stopped = False

    def write(self, text):
        with open(self.config, "w") as f:
            f.write(text)

    def start(self):
        out = open(os.path.join(self.dir, "stdout.log"), "a")
        self.proc = subprocess.Popen([self.binary, "-c", self.config], stdout=out,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     cwd=self.dir, start_new_session=True)
        self.stopped = False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            if self.stopped:
                self.resume()
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def pause(self):
        os.kill(self.proc.pid, signal.SIGSTOP)
        self.stopped = True

    def resume(self):
        os.kill(self.proc.pid, signal.SIGCONT)
        self.stopped = False

    def cpu_seconds(self):
        try:
            with open(f"/proc/{self.proc.pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
        except (OSError, IndexError, ValueError):
            return None

    def lines(self):
        try:
            with open(self.log, errors="replace") as f:
                return f.readlines()
        except OSError:
            return []

    def wait_log(self, needle, timeout, after=0):
        """Wait for `needle` in a log line past line index `after`; return the index."""
        end = time.time() + timeout
        while time.time() < end:
            ls = self.lines()
            for i in range(after, len(ls)):
                if needle in ls[i]:
                    return i
            if self.proc and self.proc.poll() is not None:
                return None
            time.sleep(0.2)
        return None

    def tox_id(self, timeout=30):
        i = self.wait_log("Tox ID:", timeout)
        if i is None:
            raise RuntimeError(f"{self.name}: no Tox ID in its log")
        return self.lines()[i].rsplit("Tox ID:", 1)[1].split()[0]

    def inspect(self, what="status"):
        r = subprocess.run([self.binary, "inspect", what, "--json", "-c", self.config],
                           capture_output=True, text=True, timeout=10)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None

    def reload(self):
        subprocess.run([self.binary, "reload", "-c", self.config], capture_output=True, timeout=10)


def server_yaml(d, udp, tcp, rules):
    return f"""mode: server
data_dir: {d.dir}/data
logging:
  level: debug
  file: {d.log}
tox:
  udp_enabled: true
  udp_port: {udp}
  tcp_port: {tcp}
  bootstrap_mode: lan
server:
  rules_file: {rules}
tunnel:
  keepalive_interval_seconds: {KEEPALIVE_S}
  half_close_timeout_seconds: {HALF_CLOSE_S}
  reaper_tick_seconds: 1
inspect:
  enabled: true
"""


def client_yaml(d, udp, servers, nodes, forward_port, target_port):
    ids = ", ".join(f'"{s}"' for s in servers)
    node_lines = "\n".join(
        f'    - {{address: "127.0.0.1", port: {p}, public_key: "{k}"}}' for p, k in nodes or [])
    node_block = f"  bootstrap_nodes:\n{node_lines}\n" if nodes else ""

    return f"""mode: client
data_dir: {d.dir}/data
logging:
  level: debug
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
tunnel:
  keepalive_interval_seconds: {KEEPALIVE_S}
  half_close_timeout_seconds: {HALF_CLOSE_S}
  reaper_tick_seconds: 1
inspect:
  enabled: true
"""


class Rig:
    """Servers A (and B with --servers 2) and one client, wired to each other."""

    def __init__(self, args, workdir, n_servers):
        self.args = args
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.targets = Targets()
        self.forward_port = free_tcp_port()
        self.rules = os.path.join(workdir, "rules.yaml")
        with open(self.rules, "w") as f:
            f.write("rules: []\n")
        self.servers = []
        for i in range(n_servers):
            s = Daemon("server" + "AB"[i], args.server_bin, workdir)
            s.udp = free_udp_port()
            s.write(server_yaml(s, s.udp, free_tcp_port(), self.rules))
            self.servers.append(s)
        self.client = Daemon("client", args.client_bin, workdir)
        self.client.udp = free_udp_port()

    def up(self):
        for s in self.servers:
            s.start()
        ids, nodes = [], []
        for s in self.servers:
            s.id = s.tox_id()
            deadline = time.time() + 5
            st = None
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
        if not nodes:
            nodes = None
        self.client.write(client_yaml(self.client, self.client.udp, ids, nodes, self.forward_port,
                                      self.targets.port))
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
        if self.client.wait_log("Server friend 0 is now online", 120) is None:
            raise RuntimeError("client never saw its primary online")
        # Let a multi-server client settle on the primary before scenarios run.
        if len(self.servers) > 1:
            time.sleep(FAILOVER_GRACE_S + 2)
        if not wait_echo(self.forward_port, 30):
            raise RuntimeError("no echo through the tunnel after setup")

    def down(self):
        self.client.stop()
        for s in self.servers:
            s.stop()


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def connect(port, timeout=20):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def open_echo_ms(port, timeout=20):
    """Open a tunnel and get one byte echoed; ms, or None on failure."""
    t0 = time.time()
    try:
        s = connect(port, timeout)
        s.sendall(b"ECHO\nx")
        s.settimeout(timeout)
        ok = s.recv(1) == b"x"
        s.close()
        return round((time.time() - t0) * 1000) if ok else None
    except OSError:
        return None


def wait_echo(port, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if open_echo_ms(port, 5) is not None:
            return True
        time.sleep(0.5)
    return False


def download(port, n, out):
    try:
        s = connect(port, 120)
        s.sendall(f"DOWN {n}\n".encode())
        t0, got = time.time(), 0
        while got < n:
            d = s.recv(262144)
            if not d:
                break
            got += len(d)
        out["bytes"] = got
        out["seconds"] = time.time() - t0
        s.close()
    except OSError as e:
        out["error"] = str(e)


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


# ---------------------------------------------------------------------------
# Scenarios. Each returns (passed, details).
# ---------------------------------------------------------------------------

def sc_echo(rig, perf):
    ms = [open_echo_ms(rig.forward_port) for _ in range(5)]
    perf["idle_open_echo_ms"] = ms
    big = {}
    download(rig.forward_port, 32 << 20, big)
    if big.get("seconds"):
        perf["loopback_download_MBps"] = round(big["bytes"] / big["seconds"] / 1e6, 2)
    return all(m is not None for m in ms) and big.get("bytes") == 32 << 20, {"open_echo_ms": ms,
                                                                            "download": big}


def sc_bulk_open_latency(rig, perf, bound_ms):
    bulk = {}
    th = threading.Thread(target=download, args=(rig.forward_port, 256 << 20, bulk), daemon=True)
    th.start()
    time.sleep(2)
    samples = []
    for _ in range(5):
        if not th.is_alive():
            break
        samples.append(open_echo_ms(rig.forward_port, 30))
        time.sleep(0.3)
    th.join(300)
    perf["bulk_open_echo_ms"] = samples
    ok = bool(samples) and all(m is not None and m <= bound_ms for m in samples)
    return ok, {"open_echo_ms": samples, "bound_ms": bound_ms, "bulk": bulk}


def sc_rst_target_to_app(rig, perf):
    s = connect(rig.forward_port)
    s.sendall(b"RST\n")
    outcome = read_outcome(s, 15)
    s.close()
    return outcome == "reset", {"application_saw": outcome}


def sc_rst_app_to_target(rig, perf):
    rig.targets.clear()
    s = connect(rig.forward_port)
    s.sendall(b"ECHO\nhello")
    s.settimeout(10)
    s.recv(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    how = rig.targets.last("ECHO", 15)
    return how == "reset", {"target_saw": how}


def sc_half_close(rig, perf):
    before = len(rig.client.inspect("tunnels")["tunnels"])
    s = connect(rig.forward_port)
    s.sendall(b"SINK\n")
    time.sleep(1)
    s.shutdown(socket.SHUT_WR)  # one-sided close, then leave the socket open
    t0 = time.time()
    reaped = None
    while time.time() - t0 < HALF_CLOSE_S + 15:
        if len(rig.client.inspect("tunnels")["tunnels"]) <= before:
            reaped = round(time.time() - t0, 1)
            break
        time.sleep(0.5)
    s.close()
    # Reaped by the cap, not by an ordinary close: not before the cap expired.
    ok = reaped is not None and reaped >= HALF_CLOSE_S - 1
    return ok, {"reaped_after_s": reaped, "cap_s": HALF_CLOSE_S}


def sc_keepalive_recovery(rig, perf):
    a = rig.servers[0]
    s = connect(rig.forward_port)
    s.sendall(b"ECHO\nx")
    s.settimeout(10)
    s.recv(1)
    mark = len(rig.client.lines())
    t0 = time.time()
    a.pause()
    outcome = read_outcome(s, 3 * KEEPALIVE_S + 15)
    reset_after = round(time.time() - t0, 1)
    s.close()
    a.resume()
    recovered = rig.client.wait_log("responsive again", 30, mark) is not None
    ok_after = wait_echo(rig.forward_port, 30)
    return (outcome == "reset" and recovered and ok_after,
            {"application_saw": outcome, "after_s": reset_after, "client_recovered": recovered,
             "echo_after_recovery": ok_after})


def sc_failover(rig, perf):
    a = rig.servers[0]
    mark = len(rig.client.lines())
    a.pause()
    switched = rig.client.wait_log("Failover: switching active server", 3 * KEEPALIVE_S +
                                   FAILOVER_TIMEOUT_S + 20, mark)
    via_b = wait_echo(rig.forward_port, 20)
    mark2 = len(rig.client.lines())
    a.resume()
    back = rig.client.wait_log("Failover: switching active server", FAILOVER_GRACE_S + 30, mark2)
    via_a = wait_echo(rig.forward_port, 20)
    return (switched is not None and via_b and back is not None and via_a,
            {"failed_over": switched is not None, "echo_via_fallback": via_b,
             "switched_back": back is not None, "echo_after_switch_back": via_a})


def sc_client_first(rig, perf):
    rig.client.stop()
    for s in rig.servers:
        s.stop()
    rig.client.start()
    time.sleep(3)
    t0 = time.time()
    for s in rig.servers:
        s.start()
    ok = wait_echo(rig.forward_port, 90)
    took = round(time.time() - t0, 1)
    perf["client_first_echo_s"] = took
    return ok, {"echo_after_server_start_s": took}


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
        except OSError:
            pass

    # Single-server scenarios share one rig; failover needs two servers.
    single = [s for s in selected if s not in ("failover", "client_first")]
    order = [("single", single), ("dual", [s for s in selected if s == "failover"]),
             ("first", [s for s in selected if s == "client_first"])]
    perf = result["perf"]
    all_ok = True
    for kind, names in order:
        if not names:
            continue
        rig = Rig(args, os.path.join(workdir, kind), 2 if kind == "dual" else 1)
        try:
            rig.up()
            for name in names:
                t0 = time.time()
                try:
                    fn = globals()["sc_" + name]
                    if name == "bulk_open_latency":
                        ok, details = fn(rig, perf, args.bulk_open_bound_ms)
                    else:
                        ok, details = fn(rig, perf)
                except Exception as e:  # a crashed scenario is a failed scenario
                    ok, details = False, {"exception": repr(e)}
                details["seconds"] = round(time.time() - t0, 1)
                result["scenarios"][name] = {"passed": ok, **details}
                all_ok &= ok
                print(f"{'PASS' if ok else 'FAIL'} {name} {json.dumps(details)}", flush=True)
            perf[f"{kind}_cpu_seconds"] = {d.name: d.cpu_seconds()
                                           for d in rig.servers + [rig.client]}
        except Exception as e:
            all_ok = False
            for name in names:
                result["scenarios"].setdefault(name, {"passed": False, "setup_error": repr(e)})
            print(f"FAIL setup({kind}) {e!r}", flush=True)
        finally:
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
