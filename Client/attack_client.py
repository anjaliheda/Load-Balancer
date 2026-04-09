"""
attack_client.py — Phase 4: Attack Simulation Client
=====================================================
Four controlled attack modes used for Phase 6 experimental evaluation.
Each mode targets a specific detection layer in the IDMS pipeline.

Modes
-----
  flood      Burst >200 req/10s → trips rule_engine rate_limit (Phase 1)
  slow_rate  Warmup at slow rate, then accelerate below the rate-limit
             ceiling → trips anomaly_engine (Phase 2)
  sqli       SQL/NoSQL injection payloads → trips sqli rule → honeypot
  mixed      Concurrent legitimate + flood traffic → measures collateral
             impact on clean users during an active attack
  legit      Clean legitimate traffic only → baseline latency (S1/S2) and
             false-positive rate measurement (S3/S4)
  all        Run flood → sqli → slow_rate → mixed in sequence

Design notes
------------
  All attack modes spoof a fixed X-Forwarded-For IP so the attack
  traffic never blocks the legitimate client or the dashboard's
  auto-baseline thread.  IPs are in the 192.168.100.x range, distinct
  from dashboard demo IPs (10.10.0.1–4).

  Each request is recorded in a thread-safe store and flushed to a
  timestamped CSV on completion.  A summary table is printed after
  each mode and a cross-mode comparison is printed after 'all'.

Usage (inside Docker network)
-----------------------------
  python attack_client.py --mode flood
  python attack_client.py --mode slow_rate --warmup-duration 20 --duration 30
  python attack_client.py --mode sqli --count 30
  python attack_client.py --mode mixed --rate 40 --duration 20
  python attack_client.py --mode all --output results/run1.csv
  python attack_client.py --mode legit --rate 15 --duration 60
  python attack_client.py --mode legit --idms-url http://localhost:5000 --rate 15 --duration 60

Usage (from host, system running)
----------------------------------
  python attack_client.py --mode flood --idms-url http://localhost:5001
"""

import argparse
import csv
import json
import os
import random
import statistics
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

import requests as http
from requests.exceptions import ConnectionError as ReqConnError
from requests.exceptions import Timeout as ReqTimeout

# ── Constants ──────────────────────────────────────────────────────────────────

VALID_API_KEY = "0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c"

# Dedicated attacker IPs — X-Forwarded-For spoofing
# Must not overlap with dashboard demo IPs (10.10.0.1–4)
ATTACK_IPS = {
    "flood":       "192.168.100.10",
    "slow_rate":   "192.168.100.20",
    "sqli":        "192.168.100.30",
    "mixed_atk":   "192.168.100.40",
    "mixed_legit": "192.168.100.50",
    "ramp":        "192.168.100.60",
    "legit":       "192.168.100.70",
}

CSV_HEADER = [
    "timestamp_unix", "mode", "phase", "ip", "request_id",
    "task_type", "payload_bytes", "status_code",
    "response_ms", "outcome", "error",
]

# SQLi payloads — each one matches at least one compiled pattern in rule_engine.py
SQLI_PAYLOADS = [
    "1 OR 1=1 --",
    "1'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "1 UNION SELECT null,null,null --",
    "admin' --",
    "' OR 1=1 /*",
    '{"$where": "sleep(100)"}',
    '{"$ne": null}',
    '{"$gt": ""}',
    "1; EXEC xp_cmdshell('whoami') --",
    "1 WAITFOR DELAY '0:0:5' --",
    "'; DELETE FROM users WHERE '1'='1",
    "1; INSERT INTO admin VALUES('hacked','hacked') --",
    "1 OR 1=1 #",
]


# ── Thread-safe result store ───────────────────────────────────────────────────

class ResultStore:
    """Collects one row per request from concurrent threads."""

    def __init__(self):
        self._rows: list = []
        self._lock = threading.Lock()
        self._counters: dict = defaultdict(int)  # outcome → count

    def record(
        self,
        ts: float,
        mode: str,
        phase: str,
        ip: str,
        req_id: int,
        task_type: str,
        payload_bytes: int,
        status_code: int,
        response_ms: float,
        outcome: str,
        error: str = "",
    ) -> None:
        row = [
            f"{ts:.3f}", mode, phase, ip, req_id, task_type,
            payload_bytes, status_code, f"{response_ms:.1f}",
            outcome, error,
        ]
        with self._lock:
            self._rows.append(row)
            self._counters[outcome] += 1

    def counters(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def rows(self) -> list:
        with self._lock:
            return list(self._rows)

    def response_times_ms(self, mode: str = None, phase: str = None) -> list:
        """Return response times (ms) for rows matching optional filters."""
        with self._lock:
            out = []
            for row in self._rows:
                # row layout: ts,mode,phase,ip,req_id,task_type,
                #             payload_bytes,status_code,response_ms,outcome,error
                if mode and row[1] != mode:
                    continue
                if phase and row[2] != phase:
                    continue
                try:
                    out.append(float(row[8]))
                except (ValueError, IndexError):
                    pass
            return out


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _infer_outcome(status_code: int, body: dict) -> str:
    """
    Derive an outcome label from the HTTP response.

    Honeypot detection: the honeypot always returns
        {"status": "ok", "result": null}
    A real backend returns {"task": "...", "result": <non-null>, ...}.
    """
    if status_code == 403:
        return "blocked"
    if status_code == 502:
        return "upstream_error"
    if status_code == 504:
        return "upstream_timeout"
    if status_code == 503:
        return "overloaded"
    if status_code != 200:
        return f"http_{status_code}"
    # Distinguish honeypot from real server response
    if isinstance(body, dict) and body.get("status") == "ok" and body.get("result") is None:
        return "honeypot"
    return "allowed"


def _send(
    idms_url: str,
    task: dict,
    ip: str,
    mode: str,
    phase: str,
    req_id: int,
    store: ResultStore,
    api_key: str = VALID_API_KEY,
) -> str:
    """
    Send one request to the IDMS and record the result.
    Returns the outcome string.  Always succeeds — errors are captured, not raised.
    """
    headers = {
        "X-API-Key":       api_key,
        "X-Forwarded-For": ip,
        "Content-Type":    "application/json",
    }
    payload_bytes = len(json.dumps(task).encode())
    ts = time.time()
    t0 = time.perf_counter()
    status_code = 0
    body = {}
    error = ""

    try:
        resp = http.post(
            f"{idms_url}/request",
            json=task,
            headers=headers,
            timeout=8,
        )
        status_code = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {}
    except ReqTimeout:
        error = "timeout"
    except ReqConnError:
        error = "connection_refused"
    except Exception as e:
        error = str(e)[:80]

    response_ms = (time.perf_counter() - t0) * 1000
    outcome = error if error else _infer_outcome(status_code, body)

    store.record(ts, mode, phase, ip, req_id, task.get("task_type", "?"),
                 payload_bytes, status_code, response_ms, outcome, error)
    return outcome


# ── Task generators ────────────────────────────────────────────────────────────

def _legit_task() -> dict:
    """Random legitimate task — covers light, medium, and heavy types."""
    return random.choice([
        {"task_type": "addition",
         "num1": random.randint(1, 100), "num2": random.randint(1, 100)},
        {"task_type": "string_length",
         "text": "loadbalancer" * random.randint(1, 4)},
        {"task_type": "multiplication",
         "num1": random.randint(1, 50),  "num2": random.randint(1, 50)},
        {"task_type": "find_vowels",
         "text": "The quick brown fox " * random.randint(1, 3)},
        {"task_type": "factorial",
         "num": random.randint(1, 7)},
    ])


def _sqli_task() -> dict:
    """Task carrying a SQL/NoSQL injection payload in a numeric field."""
    return {
        "task_type": "addition",
        "num1": random.choice(SQLI_PAYLOADS),
        "num2": 1,
    }


# ── IDMS helpers ───────────────────────────────────────────────────────────────

def _wait_for_idms(idms_url: str, timeout: int = 60) -> bool:
    """Poll IDMS /health until it responds or timeout expires."""
    print("Waiting for IDMS...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = http.get(f"{idms_url}/health", timeout=2)
            if r.status_code == 200:
                print(" ready.")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print(" timed out.")
    return False


def _unblock_ip(idms_url: str, ip: str) -> None:
    """Unblock an IP before a new attack run to prevent state leakage."""
    try:
        http.post(f"{idms_url}/idms/unblock/{ip}", timeout=5)
    except Exception:
        pass


def _fetch_idms_detections(idms_url: str, ip: str, since_ts: float) -> list:
    """
    Query /idms/attack_log for detections from `ip` at or after `since_ts`.
    Used to show the IDMS-side breakdown after each mode (rule_name, action).
    Returns an empty list on any error.
    """
    try:
        r = http.get(f"{idms_url}/idms/attack_log?limit=1000", timeout=5)
        if r.status_code != 200:
            return []
        return [
            e for e in r.json()
            if e.get("ip") == ip and e.get("ts", 0) >= since_ts
        ]
    except Exception:
        return []


# ── Output helpers ─────────────────────────────────────────────────────────────

def _divider(title: str = "", width: int = 62) -> None:
    if title:
        pad = width - len(title) - 2
        print(f"\n{'─' * (pad // 2)} {title} {'─' * (pad - pad // 2)}")
    else:
        print("─" * width)


def _detection_rates(mode_rows: list, idms_detections: list, total: int) -> tuple:
    """
    Compute two detection rate figures.

    Client-visible rate: requests the attacker knows were stopped
      = (blocked 403 + honeypotted) / total
      Deprioritised requests return 200 with real data — attacker can't
      tell they were flagged, so they are NOT counted as client-visible.

    IDMS true rate: everything the system flagged, including deprioritise
      = IDMS detection_log events for this IP / total requests sent
      More accurate but only available from the server side.

    Returns (client_rate_pct, idms_rate_pct, idms_event_count)
    """
    if total == 0:
        return 0.0, 0.0, 0

    client_caught = sum(
        1 for r in mode_rows if r[9] in ("blocked", "honeypot")
    )
    idms_caught = len(idms_detections)

    client_rate = client_caught / total * 100
    idms_rate   = min(idms_caught / total * 100, 100.0)   # cap at 100% (log may include block-skipped rows)
    return client_rate, idms_rate, idms_caught


def _print_summary(mode: str, store: ResultStore, since_ts: float,
                   idms_url: str, attack_ip: str, phase: str = "attack") -> None:
    """
    Print a per-mode summary: client-side outcome counts, detection rates,
    response time stats, and the IDMS-side rule breakdown from attack_log.
    """
    _divider(f"{mode.upper()} — Summary")

    all_rows = store.rows()
    mode_rows = [r for r in all_rows if r[1] == mode and r[2] == phase]

    if not mode_rows:
        print("  No attack-phase results recorded.")
        return

    total = len(mode_rows)
    outcome_counts: dict = defaultdict(int)
    for row in mode_rows:
        outcome_counts[row[9]] += 1

    print(f"  Requests sent  : {total}")
    for outcome, count in sorted(outcome_counts.items(), key=lambda x: -x[1]):
        pct = count / total * 100
        print(f"  {outcome:<22}: {count:4d}  ({pct:.1f}%)")

    # ── Detection rates ───────────────────────────────────────────────────────
    detections = _fetch_idms_detections(idms_url, attack_ip, since_ts)
    client_rate, idms_rate, idms_count = _detection_rates(mode_rows, detections, total)

    print(f"\n  Detection rate")
    print(f"    client-visible : {client_rate:.1f}%  "
          f"(attacker receives 403 / honeypot — knows they were stopped)")
    # For flood: once the IP is blocked, all subsequent requests short-circuit
    # at _is_blocked() and never reach the detection engines — they get 403
    # instantly but are NOT written to detection_log (no detection ran).
    # detection_log only holds the single rate_limit trigger event.
    # Client-visible is therefore the accurate detection figure for flood.
    if mode == "flood":
        blocked_count = sum(1 for r in mode_rows if r[9] == "blocked")
        print(f"    IDMS log events: {idms_count}  "
              f"(only the initial trigger — {blocked_count} "
              f"subsequent 403s are short-circuit IP-cache blocks, not logged by design)")
    else:
        print(f"    IDMS true rate : {idms_rate:.1f}%  "
              f"({idms_count} events in detection_log — includes silent deprioritise)")

    # ── Response times ────────────────────────────────────────────────────────
    times_ms = store.response_times_ms(mode=mode, phase=phase)
    if times_ms:
        print(f"\n  Response time (ms)")
        print(f"    mean   : {statistics.mean(times_ms):.1f}")
        print(f"    median : {statistics.median(times_ms):.1f}")
        print(f"    min    : {min(times_ms):.1f}")
        print(f"    max    : {max(times_ms):.1f}")
        if len(times_ms) > 1:
            print(f"    stdev  : {statistics.stdev(times_ms):.1f}")

    # ── IDMS rule breakdown ───────────────────────────────────────────────────
    if detections:
        print(f"\n  IDMS rule breakdown ({idms_count} events for {attack_ip})")
        rule_counts: dict = defaultdict(int)
        action_counts: dict = defaultdict(int)
        for d in detections:
            rule_counts[d.get("rule_name", "?")] += 1
            action_counts[d.get("action", "?")] += 1
        print(f"  {'Rule':<22} {'Count':>6}")
        _divider(width=32)
        for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"  {rule:<22} {cnt:>6}")
        print(f"\n  {'Action':<22} {'Count':>6}")
        _divider(width=32)
        for action, cnt in sorted(action_counts.items(), key=lambda x: -x[1]):
            print(f"  {action:<22} {cnt:>6}")
    else:
        print(f"\n  IDMS detections: none in attack_log for {attack_ip} "
              f"(anomaly deprioritise events are only in the metrics ring — "
              f"check /api/detections on the dashboard)")


def write_csv(store: ResultStore, path: str) -> None:
    """Write all collected results to a CSV file."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_HEADER)
        w.writerows(store.rows())
    print(f"\nResults saved to: {path}  ({len(store.rows())} rows)")


# ── Attack modes ───────────────────────────────────────────────────────────────

def run_flood(idms_url: str, rate: float, duration: float,
              store: ResultStore) -> None:
    """
    Send requests at `rate` req/s for `duration` seconds using one thread
    per request with a fixed inter-launch interval.

    Expected outcome: the first 200 requests in any 10-second window are
    allowed; subsequent requests from the same IP are blocked by rate_limit
    until the block expires (300s for high-severity by default).

    rate=50, duration=15 → 750 total requests; first ~200 pass, rest blocked.
    """
    ip = ATTACK_IPS["flood"]
    mode = "flood"
    total = int(rate * duration)
    interval = 1.0 / rate

    _divider(f"MODE: FLOOD")
    print(f"  Target IP : {ip}")
    print(f"  Rate      : {rate:.0f} req/s  →  {total} requests over {duration:.0f}s")
    print(f"  Ceiling   : 200 req / 10s (rate_limit rule)")
    print(f"  Expected  : first ~200 allowed → blocked for 300s")

    _unblock_ip(idms_url, ip)
    since_ts = time.time()

    threads = []
    for i in range(total):
        t = threading.Thread(
            target=_send,
            args=(idms_url, _legit_task(), ip, mode, "attack", i + 1, store),
            daemon=True,
        )
        threads.append(t)
        t.start()
        time.sleep(interval)

    for t in threads:
        t.join(timeout=15)

    _print_summary(mode, store, since_ts, idms_url, ip)


def run_slow_rate(idms_url: str, warmup_duration: float,
                  duration: float, store: ResultStore) -> None:
    """
    Two-phase evasion attack:

    Phase A — Warmup: send at ~10 req/s sequentially to build a stable
      anomaly baseline.  At 10 req/s for warmup_duration seconds, 150+
      samples are established before the attack begins.

    Phase B — Attack: send in concurrent micro-bursts to collapse the IAT.
      Each burst fires `BURST_SIZE` requests simultaneously, then sleeps
      `BURST_INTERVAL` seconds.  This keeps the sustained rate well under
      the 200/10s rate-limit ceiling while driving the per-request IAT from
      ~100ms (baseline) down to ~1ms (concurrent arrivals).

      Why micro-bursts instead of simply raising rate:
        Docker Desktop on Windows adds 20–80ms of variable latency to every
        request.  This widens the baseline MAD to ~40ms.  At 18 req/s the
        inter-arrival time is 56ms, giving a Z-score of only ~0.6 — not
        enough to cross threshold=1.5.  Concurrent arrivals have IAT ~1ms,
        giving Z ≈ 1.65, which reliably fires the anomaly engine regardless
        of Docker jitter.

    After 8 deprioritise strikes within 120s the mitigation controller
    escalates to a 30s block.
    """
    BURST_SIZE     = 8      # concurrent requests per burst
    BURST_INTERVAL = 0.8    # seconds between bursts → ~10 req/s sustained (80/10s << 200/10s)

    ip = ATTACK_IPS["slow_rate"]
    mode = "slow_rate"
    warmup_rate = 10.0
    warmup_interval = 1.0 / warmup_rate
    warmup_total = int(warmup_rate * warmup_duration)
    n_bursts = max(1, int(duration / BURST_INTERVAL))
    req_id = 0

    _divider("MODE: SLOW RATE")
    print(f"  Target IP      : {ip}")
    print(f"  Phase A warmup : {warmup_total} req at {warmup_rate:.0f}/s "
          f"over {warmup_duration:.0f}s  (builds anomaly baseline)")
    print(f"  Phase B attack : {n_bursts} micro-bursts × {BURST_SIZE} concurrent "
          f"= {n_bursts * BURST_SIZE} req over {duration:.0f}s "
          f"(~{BURST_SIZE / BURST_INTERVAL:.0f} req/s, well under 200/10s limit)")
    print(f"  Expected       : concurrent IAT ~1ms vs ~100ms baseline "
          f"→ Z-score > 1.5 → deprioritise → escalation block at 8 strikes")

    _unblock_ip(idms_url, ip)

    # ── Phase A: warmup (sequential — establishes consistent ~100ms IAT) ─────
    print(f"\n  [A] Warmup — {warmup_total} requests at {warmup_rate:.0f}/s...")
    since_ts = time.time()

    for i in range(warmup_total):
        req_id += 1
        _send(idms_url, _legit_task(), ip, mode, "warmup", req_id, store)
        time.sleep(warmup_interval)

    warmup_blocked = sum(
        1 for r in store.rows()
        if r[1] == mode and r[2] == "warmup" and r[9] == "blocked"
    )
    if warmup_blocked > 0:
        print(f"  [!] WARNING: {warmup_blocked} warmup requests were blocked — "
              f"baseline may be incomplete. Check IDMS thresholds.")
    else:
        print(f"  [A] Warmup complete — {warmup_total} samples, none blocked.")

    # Brief pause to let the last baseline IAT register before the burst
    time.sleep(0.3)

    # ── Phase B: micro-burst attack ───────────────────────────────────────────
    # Each burst sends BURST_SIZE requests with ~0ms IAT between them.
    # The anomaly engine sees the IAT drop from ~100ms to ~1ms → Z fires.
    # 8 flagged requests in one burst = exactly the escalation threshold.
    print(f"  [B] Attack phase — {n_bursts} bursts of {BURST_SIZE} concurrent requests...")
    attack_since_ts = time.time()

    for burst_num in range(n_bursts):
        burst_threads = []
        for j in range(BURST_SIZE):
            req_id += 1
            t = threading.Thread(
                target=_send,
                args=(idms_url, _legit_task(), ip, mode, "attack", req_id, store),
                daemon=True,
            )
            burst_threads.append(t)

        for t in burst_threads:
            t.start()
        for t in burst_threads:
            t.join(timeout=10)

        # Check if IP was escalation-blocked mid-run
        recent = [r for r in store.rows()
                  if r[1] == mode and r[2] == "attack"]
        last_outcome = recent[-1][9] if recent else "unknown"
        if last_outcome == "blocked":
            blocked_total = sum(1 for r in recent if r[9] == "blocked")
            print(f"  [B] Escalation block fired after burst {burst_num + 1} "
                  f"({blocked_total} requests blocked). Stopping attack phase.")
            break

        time.sleep(BURST_INTERVAL)

    _print_summary(mode, store, attack_since_ts, idms_url, ip)


def run_sqli(idms_url: str, count: int, store: ResultStore) -> None:
    """
    Send `count` SQL/NoSQL injection requests using a valid API key.

    Auth passes (valid key) but the injection scanner fires → honeypot.
    The attacker receives a convincing 200 OK with a fake server response,
    not a 403, so they continue sending payloads we can analyse.

    Sends sequentially with a 50ms gap so the requests appear in the IDMS
    detection log in a readable order.
    """
    ip = ATTACK_IPS["sqli"]
    mode = "sqli"

    _divider("MODE: SQL INJECTION")
    print(f"  Target IP : {ip}")
    print(f"  Requests  : {count} injection payloads (valid API key)")
    print(f"  Expected  : sqli rule fires → honeypot (200 fake OK, never 403)")

    _unblock_ip(idms_url, ip)
    since_ts = time.time()

    for i in range(count):
        _send(idms_url, _sqli_task(), ip, mode, "attack", i + 1, store)
        time.sleep(0.05)   # 50ms gap — keeps requests distinct in the log

    _print_summary(mode, store, since_ts, idms_url, ip)


def run_mixed(idms_url: str, atk_rate: float, legit_rate: float,
              duration: float, store: ResultStore) -> None:
    """
    Concurrent legitimate and attack traffic running for `duration` seconds.

    Attacker stream:   high rate (default 40 req/s) → triggers rate_limit
      within the first ~5s → blocked for 300s → rest of traffic is 403.
    Legitimate stream: low rate (default 8 req/s) → stays well under any
      threshold → all requests allowed.

    The two streams use distinct IPs so the attacker block never affects
    legitimate users.  This directly answers "does the IDMS protect clean
    users during an active attack?"

    Why separate rates rather than a single --rate + --malicious-ratio:
      The original single-rate design combined both streams at 15 req/s each
      (30 total), which overloaded the backend servers (503) before the IDMS
      could even demonstrate its rate-limit block — the server's own
      OVERLOAD_THRESHOLD (8) fired first.  Decoupled rates fix this: the
      attacker fires hard and fast (triggers IDMS), the legitimate client is
      gentle enough that the 4 servers never get overwhelmed (8 req/s ÷ 4
      servers = 2 req/server — well under overload threshold of 8).
    """
    legit_ip = ATTACK_IPS["mixed_legit"]
    atk_ip   = ATTACK_IPS["mixed_atk"]
    mode     = "mixed"

    legit_interval = 1.0 / legit_rate
    atk_interval   = 1.0 / atk_rate

    _divider("MODE: MIXED")
    print(f"  Legitimate IP : {legit_ip}  ({legit_rate:.0f} req/s for {duration:.0f}s)")
    print(f"  Attacker IP   : {atk_ip}   ({atk_rate:.0f} req/s for {duration:.0f}s)")
    print(f"  Expected      : attacker blocked after ~{200 / atk_rate:.0f}s "
          f"(200 req rate-limit); legitimate stream unaffected throughout")

    _unblock_ip(idms_url, legit_ip)
    _unblock_ip(idms_url, atk_ip)
    since_ts = time.time()

    stop_event  = threading.Event()
    all_threads = []
    _threads_lock = threading.Lock()

    def _stream(ip, task_fn, interval, label, start_id):
        req_id = start_id
        while not stop_event.is_set():
            t = threading.Thread(
                target=_send,
                args=(idms_url, task_fn(), ip, mode, label, req_id, store),
                daemon=True,
            )
            with _threads_lock:
                all_threads.append(t)
            t.start()
            req_id += 1
            time.sleep(interval)

    legit_thread = threading.Thread(
        target=_stream,
        args=(legit_ip, _legit_task, legit_interval, "legitimate", 1),
        daemon=True,
    )
    atk_thread = threading.Thread(
        target=_stream,
        args=(atk_ip, _legit_task, atk_interval, "attack", 1),
        daemon=True,
    )

    legit_thread.start()
    atk_thread.start()

    time.sleep(duration)
    stop_event.set()

    # Give launched request threads time to complete
    with _threads_lock:
        snapshot = list(all_threads)
    for t in snapshot:
        t.join(timeout=10)

    # Print separate summaries for legitimate and attack streams
    _divider("mixed — Legitimate traffic (should be unaffected)")
    legit_rows = [r for r in store.rows() if r[1] == mode and r[2] == "legitimate"]
    if legit_rows:
        outcomes: dict = defaultdict(int)
        for r in legit_rows:
            outcomes[r[9]] += 1
        total = len(legit_rows)
        print(f"  Total requests : {total}")
        for outcome, count in sorted(outcomes.items(), key=lambda x: -x[1]):
            print(f"  {outcome:<22}: {count:4d}  ({count/total*100:.1f}%)")
        times = [float(r[8]) for r in legit_rows]
        if times:
            allowed_pct = outcomes.get("allowed", 0) / total * 100
            print(f"\n  Response time (ms)")
            print(f"    mean   : {statistics.mean(times):.1f}")
            print(f"    median : {statistics.median(times):.1f}")
            print(f"    max    : {max(times):.1f}")
            print(f"\n  Collateral impact : "
                  f"{'none — {:.0f}% allowed cleanly'.format(allowed_pct) if allowed_pct >= 95 else '{:.1f}% allowed (some degradation)'.format(allowed_pct)}")
    else:
        print("  No legitimate requests recorded.")

    _divider("mixed — Attack traffic (should be blocked)")
    _print_summary(mode, store, since_ts, idms_url, atk_ip, phase="attack")


def run_stress(idms_url: str, start_rate: float, max_rate: float,
               step: float, step_duration: float, store: ResultStore) -> None:
    """
    Ramp flood rate from start_rate to max_rate in increments of `step` req/s.

    Each rate level uses a distinct fresh IP (192.168.100.101, .102, ...) so
    a block on one step never carries over to the next.  This isolates each
    measurement point and gives clean per-step detection figures.

    At each step the function records:
      - Requests sent
      - Client-visible caught (403 blocked)
      - Requests allowed through
      - Average response time (ms)
      - Detection rate % (client-visible, from this client's perspective)

    The final table directly answers "how much can you handle?":
      - Below the rate limit: detection rate 0%, system handles traffic normally
      - At the threshold: first blocked events appear, latency may climb
      - Above the threshold: detection rate climbs toward 100% as blocks dominate
      - Very high rate: avg response drops (blocked responses are instant 403s)

    IDMS true detection rate is NOT computed per step here because it would
    require a separate attack_log query per IP per step (expensive and slow).
    Run individual modes for full IDMS-side breakdowns.
    """
    # Build rate steps
    rate_steps = []
    r = start_rate
    while r <= max_rate + 1e-9:
        rate_steps.append(round(r, 1))
        r += step

    total_time = len(rate_steps) * step_duration
    _divider("MODE: STRESS TEST")
    print(f"  Rate range : {start_rate:.0f} → {max_rate:.0f} req/s "
          f"in steps of {step:.0f}")
    print(f"  Step dur.  : {step_duration:.0f}s per step  "
          f"({len(rate_steps)} steps, ~{total_time:.0f}s total)")
    print(f"  Rate limit : 200 req / 10s  "
          f"(threshold at {200 / 10:.0f} req/s sustained)")
    print(f"  Each step uses a fresh IP — no block carryover between steps")

    step_results = []   # (rate, sent, blocked, allowed, other, det_pct, avg_ms)

    for i, rate in enumerate(rate_steps):
        ip = f"192.168.100.{101 + i}"
        total    = int(rate * step_duration)
        interval = 1.0 / rate if rate > 0 else 1.0
        phase    = f"stress_{int(rate)}"

        _unblock_ip(idms_url, ip)   # belt-and-suspenders: IP is fresh but unblock anyway

        threads = []
        for j in range(total):
            t = threading.Thread(
                target=_send,
                args=(idms_url, _legit_task(), ip, "stress", phase, j + 1, store),
                daemon=True,
            )
            threads.append(t)
            t.start()
            time.sleep(interval)

        for t in threads:
            t.join(timeout=15)

        step_rows = [r for r in store.rows()
                     if r[1] == "stress" and r[2] == phase]
        sent    = len(step_rows)
        blocked = sum(1 for r in step_rows if r[9] == "blocked")
        allowed = sum(1 for r in step_rows if r[9] == "allowed")
        times   = [float(r[8]) for r in step_rows]
        avg_ms  = statistics.mean(times) if times else 0.0
        det_pct = blocked / sent * 100 if sent else 0.0

        other = sent - blocked - allowed   # overloaded (503) + timeout + errors
        step_results.append((rate, sent, blocked, allowed, other, det_pct, avg_ms))
        print(f"  {rate:>6.0f} req/s | sent={sent:>4}  blocked={blocked:>4}  "
              f"allowed={allowed:>4}  other={other:>3}  det={det_pct:>5.1f}%  avg={avg_ms:>6.1f}ms")

    # ── Results table ─────────────────────────────────────────────────────────
    _divider("STRESS TEST — Capacity Table")
    print(f"{'Rate/s':>7} {'Sent':>6} {'Blocked':>8} {'Allowed':>8} "
          f"{'Other':>7} {'Det%':>6} {'Avg ms':>8}  Verdict")
    print(f"{'':>7} {'':>6} {'':>8} {'':>8} "
          f"{'(503/to)':>7} {'':>6} {'':>8}")
    _divider(width=70)

    for rate, sent, blocked, allowed, other, det_pct, avg_ms in step_results:
        if det_pct == 0:
            verdict = "under limit — all through"
        elif det_pct < 50:
            verdict = "partial detection"
        elif det_pct < 95:
            verdict = "mostly blocked"
        else:
            verdict = "fully saturated"

        print(f"{rate:>7.0f} {sent:>6} {blocked:>8} {allowed:>8} "
              f"{other:>7} {det_pct:>5.1f}% {avg_ms:>8.1f}  {verdict}")

    # ── Key finding ───────────────────────────────────────────────────────────
    # Find the first step where detection rate crosses 50% (breaking point)
    breakpoint_rate = None
    for rate, _, _, _, _, det_pct, _ in step_results:
        if det_pct >= 50:
            breakpoint_rate = rate
            break

    onset_rate = next(
        (r for r, _, _, _, _, d, _ in step_results if d > 0), None
    )
    if onset_rate:
        print(f"\n  Detection onset   : ~{onset_rate:.0f} req/s  "
              f"(first requests blocked — rate-limit window exceeded)")
    if breakpoint_rate:
        print(f"  Breaking point    : ~{breakpoint_rate:.0f} req/s  "
              f"(>50% of requests blocked here)")
        last = step_results[-1]
        theoretical_max = (last[1] - 200) / last[1] * 100 if last[1] > 200 else 0
        print(f"  Detection ceiling : ~{last[5]:.0f}%  "
              f"(first 200 req always pass before block fires — "
              f"theoretical max at {last[0]:.0f} req/s = {theoretical_max:.0f}%)")
    else:
        print(f"\n  System handled all tested rates without triggering "
              f">50% detection — raise --max-rate to find the breaking point")


def run_ramp(idms_url: str, store: ResultStore) -> None:
    """
    Gradual rate escalation attack — the evasion test for the anomaly engine.

    Sends requests starting at 5 req/s and stepping up by 3 req/s every 25 seconds,
    reaching 17 req/s at the final step.  Every step stays well under the 200/10s
    rate-limit ceiling (17 × 10 = 170 < 200), so the rule engine never fires.

    Research question: does the anomaly engine catch gradual acceleration, or does its
    rolling 30-second baseline adapt with the attacker?

    Expected result: probably partial / no detection.  The baseline median updates
    continuously — by the time the rate reaches 17 req/s, recent history at 14 req/s
    has already shifted the median downward, so the Z-score of the final step may stay
    below threshold=1.5.  This is an honest finding: slow ramp is the gap case for
    statistical IAT detection with a short window.

    Steps: 5 → 8 → 11 → 14 → 17 req/s  (5 steps × 25s = 125s total, ~1375 requests)
    """
    STEPS          = [5, 8, 11, 14, 17]   # req/s per step — all below 20 req/s rate limit
    STEP_DURATION  = 25.0                  # seconds per step
    # Each step uses its own IP so rate-limit state never carries over between steps.
    # This isolates the anomaly engine as the only possible detection mechanism.
    STEP_IPS       = [f"192.168.100.{60 + i}" for i in range(len(STEPS))]

    mode = "ramp"

    _divider("MODE: RAMP (EVASION TEST)")
    print(f"  Steps      : {' → '.join(str(r) for r in STEPS)} req/s  "
          f"({STEP_DURATION:.0f}s each, {len(STEPS) * STEP_DURATION:.0f}s total)")
    print(f"  IPs        : {STEP_IPS[0]} … {STEP_IPS[-1]}  (fresh IP per step — isolates anomaly engine)")
    print(f"  Rate limit : 200 req/10s  (max step {max(STEPS)} × 10 = {max(STEPS)*10} — never triggers)")
    print(f"  Research Q : does the anomaly engine detect gradual acceleration,")
    print(f"               or does its 30s rolling baseline adapt with the attacker?")

    since_ts = time.time()
    req_id   = 0

    for step_num, (rate, ip) in enumerate(zip(STEPS, STEP_IPS)):
        _unblock_ip(idms_url, ip)
        interval = 1.0 / rate
        n        = int(rate * STEP_DURATION)
        phase    = f"step_{rate}"

        print(f"\n  [Step {step_num + 1}/{len(STEPS)}] {rate} req/s  ip={ip}  ({n} requests over {STEP_DURATION:.0f}s)...")

        threads = []
        for j in range(n):
            req_id += 1
            t = threading.Thread(
                target=_send,
                args=(idms_url, _legit_task(), ip, mode, phase, req_id, store),
                daemon=True,
            )
            threads.append(t)
            t.start()
            time.sleep(interval)

        for t in threads:
            t.join(timeout=15)

        step_rows = [r for r in store.rows() if r[1] == mode and r[2] == phase]
        dep  = sum(1 for r in step_rows if r[9] == "deprioritise")
        blk  = sum(1 for r in step_rows if r[9] == "blocked")
        sent = len(step_rows)
        print(f"  → sent={sent}  deprioritised={dep}  blocked={blk}  "
              f"detected={dep+blk}  ({(dep+blk)/sent*100:.1f}%)")

    # ── Summary ───────────────────────────────────────────────────────────────
    _divider("RAMP — Summary")
    all_ramp = [r for r in store.rows() if r[1] == mode]
    total    = len(all_ramp)
    dep_tot  = sum(1 for r in all_ramp if r[9] == "deprioritise")
    blk_tot  = sum(1 for r in all_ramp if r[9] == "blocked")
    allow    = sum(1 for r in all_ramp if r[9] == "allowed")
    det_pct  = (dep_tot + blk_tot) / total * 100 if total else 0

    print(f"  Total requests : {total}")
    print(f"  Allowed        : {allow}  ({allow/total*100:.1f}%)")
    print(f"  Deprioritised  : {dep_tot}  ({dep_tot/total*100:.1f}%)")
    print(f"  Blocked        : {blk_tot}  ({blk_tot/total*100:.1f}%)")
    print(f"\n  Detection rate : {det_pct:.1f}%")

    if det_pct < 10:
        print(f"  Verdict        : ramp EVADES detection — baseline adapts with attacker")
        print(f"                   (expected: this is the known gap case for short-window IAT scoring)")
    elif det_pct < 50:
        print(f"  Verdict        : partial detection — anomaly engine caught late-stage acceleration")
    else:
        print(f"  Verdict        : ramp detected — anomaly baseline did not fully adapt")

    all_detections = []
    for ip in STEP_IPS:
        all_detections.extend(_fetch_idms_detections(idms_url, ip, since_ts))
    if all_detections:
        print(f"\n  IDMS detection log: {len(all_detections)} events across all step IPs")
        by_action: dict = defaultdict(int)
        for d in all_detections:
            by_action[d.get("action", "?")] += 1
        for action, cnt in sorted(by_action.items(), key=lambda x: -x[1]):
            print(f"    {action:<20} : {cnt}")


def run_legit(idms_url: str, rate: float, duration: float,
              store: ResultStore) -> None:
    """
    Send clean legitimate traffic at `rate` req/s for `duration` seconds.

    Used for three research measurements:
      S1 baseline  — direct to LB (--idms-url http://localhost:5000),
                     no IDMS overhead, measures raw server latency.
      S3/S4 legit  — through IDMS, measures inspection overhead and FPR.
      FPR run      — feed results to results_analyzer.py --fpr to count
                     any false-positive blocks on clean traffic.

    Traffic is sequential (one request at a time) so the inter-arrival time
    is stable and the anomaly engine is never accidentally triggered by
    concurrency.  Rate is kept at ≤15 req/s — well under the 200/10s
    rate-limit ceiling — so the rule engine never fires on this IP.
    """
    ip   = ATTACK_IPS["legit"]
    mode = "legit"
    total = int(rate * duration)
    interval = 1.0 / rate

    _divider("MODE: LEGIT TRAFFIC")
    print(f"  IP       : {ip}")
    print(f"  Rate     : {rate:.1f} req/s  →  {total} requests over {duration:.0f}s")
    print(f"  Purpose  : baseline latency + FPR measurement (no attacks, no blocks expected)")

    _unblock_ip(idms_url, ip)
    since_ts = time.time()

    for i in range(total):
        _send(idms_url, _legit_task(), ip, mode, "traffic", i + 1, store)
        time.sleep(interval)

    # ── Summary ───────────────────────────────────────────────────────────────
    _divider("LEGIT — Summary")
    rows = [r for r in store.rows() if r[1] == mode and r[2] == "traffic"]
    if not rows:
        print("  No results recorded.")
        return

    outcomes: dict = defaultdict(int)
    for r in rows:
        outcomes[r[9]] += 1

    total_recorded = len(rows)
    print(f"  Requests sent  : {total_recorded}")
    for outcome, count in sorted(outcomes.items(), key=lambda x: -x[1]):
        pct = count / total_recorded * 100
        print(f"  {outcome:<22}: {count:4d}  ({pct:.1f}%)")

    times_ms = store.response_times_ms(mode=mode, phase="traffic")
    if times_ms:
        print(f"\n  Response time (ms)")
        print(f"    mean   : {statistics.mean(times_ms):.1f}")
        print(f"    median : {statistics.median(times_ms):.1f}")
        print(f"    min    : {min(times_ms):.1f}")
        print(f"    max    : {max(times_ms):.1f}")
        if len(times_ms) > 1:
            print(f"    stdev  : {statistics.stdev(times_ms):.1f}")

    fp_count = sum(1 for r in rows if r[9] in ("blocked", "deprioritise"))
    fpr = fp_count / total_recorded * 100 if total_recorded else 0
    print(f"\n  False positives: {fp_count}  (FPR = {fpr:.2f}%)")
    if fp_count == 0:
        print(f"  FPR verdict    : 0% — IDMS passed all clean traffic without false blocks")
    else:
        print(f"  FPR verdict    : {fpr:.2f}% — investigate via results_analyzer.py --fpr")


# ── CSV and reporting ──────────────────────────────────────────────────────────

def _print_cross_mode_table(store: ResultStore) -> None:
    """Print a comparison table across all modes (used after 'all')."""
    _divider("CROSS-MODE COMPARISON")
    print(f"{'Mode':<12} {'Sent':>6} {'Allowed':>9} {'Blocked':>9} "
          f"{'Honeypot':>10} {'Client Det%':>12} {'Avg ms':>8}")
    _divider(width=72)

    modes = ["flood", "slow_rate", "sqli", "mixed"]
    for mode in modes:
        rows = [r for r in store.rows()
                if r[1] == mode and r[2] == "attack"]
        if not rows:
            continue
        total    = len(rows)
        allowed  = sum(1 for r in rows if r[9] == "allowed")
        blocked  = sum(1 for r in rows if r[9] == "blocked")
        honeypot = sum(1 for r in rows if r[9] == "honeypot")
        client_det = (blocked + honeypot) / total * 100 if total else 0
        times    = [float(r[8]) for r in rows]
        avg_ms   = f"{statistics.mean(times):.1f}" if times else "—"
        print(f"{mode:<12} {total:>6} {allowed:>9} {blocked:>9} "
              f"{honeypot:>10} {client_det:>11.1f}% {avg_ms:>8}")


# ── Argument parser ────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--mode",
        choices=["flood", "slow_rate", "sqli", "mixed", "all", "stress", "ramp", "legit"],
        required=True,
        help="Attack mode to run.",
    )
    p.add_argument(
        "--idms-url",
        default=os.environ.get("IDMS_URL", "http://idms:5001"),
        help="Base URL of the IDMS proxy (default: %(default)s).",
    )
    p.add_argument(
        "--output",
        default=None,
        help=(
            "CSV output path. Defaults to "
            "results/attack_<mode>_<timestamp>.csv"
        ),
    )
    p.add_argument(
        "--no-wait",
        action="store_true",
        help="Skip the IDMS readiness poll on startup.",
    )

    # flood / mixed
    p.add_argument(
        "--rate",
        type=float,
        default=None,
        help=(
            "Request rate (req/s). "
            "flood default=50, mixed default=30, legit default=15."
        ),
    )
    p.add_argument(
        "--duration",
        type=float,
        default=None,
        help=(
            "Attack/traffic duration in seconds. "
            "flood default=15, slow_rate default=30, mixed default=20, legit default=60."
        ),
    )

    # slow_rate
    p.add_argument(
        "--warmup-duration",
        type=float,
        default=20.0,
        help="slow_rate: warmup phase length in seconds (default: %(default)s).",
    )

    # sqli
    p.add_argument(
        "--count",
        type=int,
        default=20,
        help="sqli: total injection requests to send (default: %(default)s).",
    )

    # mixed
    p.add_argument(
        "--atk-rate",
        type=float,
        default=40.0,
        help=(
            "mixed: attacker req/s (default: %(default)s). "
            "High enough to trigger rate_limit (>20 req/s sustained)."
        ),
    )
    p.add_argument(
        "--legit-rate",
        type=float,
        default=8.0,
        help=(
            "mixed: legitimate user req/s (default: %(default)s). "
            "Kept low so backend servers are not overwhelmed."
        ),
    )
    # kept for backwards compatibility but no longer used internally
    p.add_argument(
        "--malicious-ratio",
        type=float,
        default=0.5,
        help=argparse.SUPPRESS,
    )

    # stress
    p.add_argument(
        "--start-rate",
        type=float,
        default=5.0,
        help="stress: starting req/s (default: %(default)s).",
    )
    p.add_argument(
        "--max-rate",
        type=float,
        default=60.0,
        help="stress: maximum req/s (default: %(default)s).",
    )
    p.add_argument(
        "--step",
        type=float,
        default=5.0,
        help="stress: req/s increment per step (default: %(default)s).",
    )
    p.add_argument(
        "--step-duration",
        type=float,
        default=12.0,
        help="stress: seconds to run at each rate level (default: %(default)s). "
             "Must be >10s to exceed the 200/10s rate-limit window at low rates.",
    )
    return p


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Validate args early
    if args.mode == "mixed":
        if args.atk_rate <= 0 or args.legit_rate <= 0:
            parser.error("--atk-rate and --legit-rate must be > 0")
        if args.legit_rate > 15:
            parser.error("--legit-rate above 15 req/s risks overloading backend servers")
    if args.mode == "stress":
        if args.step <= 0:
            parser.error("--step must be > 0")
        if args.start_rate > args.max_rate:
            parser.error("--start-rate must be <= --max-rate")
        if args.step_duration < 1:
            parser.error("--step-duration must be >= 1s")

    idms_url = args.idms_url.rstrip("/")

    # Default CSV path
    if args.output is None:
        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join("results", f"attack_{args.mode}_{ts_str}.csv")

    # IDMS readiness
    if not args.no_wait:
        if not _wait_for_idms(idms_url):
            print("ERROR: IDMS not reachable. Use --no-wait to skip this check.")
            sys.exit(1)

    store = ResultStore()

    _divider("ATTACK SIMULATION CLIENT")
    print(f"  IDMS URL : {idms_url}")
    print(f"  Mode     : {args.mode}")
    print(f"  Output   : {args.output}")
    print(f"  Started  : {datetime.now().strftime('%H:%M:%S')}")

    try:
        if args.mode == "flood":
            run_flood(
                idms_url,
                rate=args.rate or 50.0,
                duration=args.duration or 15.0,
                store=store,
            )

        elif args.mode == "slow_rate":
            run_slow_rate(
                idms_url,
                warmup_duration=args.warmup_duration,
                duration=args.duration or 30.0,
                store=store,
            )

        elif args.mode == "sqli":
            run_sqli(
                idms_url,
                count=args.count,
                store=store,
            )

        elif args.mode == "mixed":
            run_mixed(
                idms_url,
                atk_rate=args.atk_rate,
                legit_rate=args.legit_rate,
                duration=args.duration or 20.0,
                store=store,
            )

        elif args.mode == "all":
            # Unblock all attack IPs first to ensure clean starting state
            for ip in ATTACK_IPS.values():
                _unblock_ip(idms_url, ip)

            run_flood(
                idms_url,
                rate=args.rate or 50.0,
                duration=args.duration or 15.0,
                store=store,
            )
            time.sleep(3)

            run_sqli(
                idms_url,
                count=args.count,
                store=store,
            )
            time.sleep(3)

            run_slow_rate(
                idms_url,
                warmup_duration=args.warmup_duration,
                duration=args.duration or 30.0,
                store=store,
            )
            time.sleep(3)

            run_mixed(
                idms_url,
                atk_rate=args.atk_rate,
                legit_rate=args.legit_rate,
                duration=args.duration or 20.0,
                store=store,
            )

            _print_cross_mode_table(store)

        elif args.mode == "stress":
            run_stress(
                idms_url,
                start_rate=args.start_rate,
                max_rate=args.max_rate,
                step=args.step,
                step_duration=args.step_duration,
                store=store,
            )

        elif args.mode == "ramp":
            run_ramp(idms_url, store=store)

        elif args.mode == "legit":
            run_legit(
                idms_url,
                rate=args.rate or 15.0,
                duration=args.duration or 60.0,
                store=store,
            )

    except KeyboardInterrupt:
        print("\n[interrupted] Writing partial results...")

    write_csv(store, args.output)
    _divider()
    print(f"  Finished : {datetime.now().strftime('%H:%M:%S')}")
    print(f"  Total requests recorded : {len(store.rows())}")


if __name__ == "__main__":
    main()
