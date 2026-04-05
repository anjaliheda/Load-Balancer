"""
mitigation_controller.py — Phase 3: Mitigation Controller
==========================================================
Orchestrates the full per-request pipeline: block check → detection → action.

Responsibilities:
  1. Short-circuit blocked IPs before wasting detection cycles
  2. Run rule_engine and anomaly_engine in sequence
  3. Execute the verdict: block / honeypot / deprioritise / allow
  4. Escalation: repeated deprioritise strikes auto-escalate to a timed block
  5. SQLite-backed IP reputation store (timed blocks, detection log)
  6. In-memory metrics ring for the dashboard

The proxy (idms_proxy.py) is detection-agnostic: it parses the HTTP request
and delegates entirely to controller.process().  All policy lives here.
"""

import os
import time
import logging
import threading
import sqlite3
from collections import defaultdict, deque

import requests as http
from flask import jsonify

from rule_engine import inspect as rule_inspect, get_current_rates, RULE_CONFIG
from rule_engine import reset_state_for_ip as rule_reset, reset_all as rule_reset_all
from anomaly_engine import score as anomaly_score, get_anomaly_snapshot, ANOMALY_CONFIG
from anomaly_engine import reset_state_for_ip as anomaly_reset, reset_all as anomaly_reset_all

logger = logging.getLogger("mitigation_controller")


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

MITIGATION_CONFIG: dict = {
    # Block durations in seconds, keyed by severity
    "block_duration_medium":    60,
    "block_duration_high":     300,
    "block_duration_critical": 900,

    # Escalation: N deprioritise strikes within T seconds → timed block
    # Threshold is 8: provides a small buffer against occasional jitter false positives
    # while still firing reliably when 50 concurrent burst requests arrive.
    # Block duration is short (30s) so the demo can be repeated without a long wait.
    "escalation_strikes":        8,
    "escalation_window_seconds": 120,
    "escalation_block_duration": 30,
}


# ─────────────────────────────────────────────
# Module-level shared state
# ─────────────────────────────────────────────

# Per-IP deprioritise strike timestamps (sliding window for escalation)
_strike_windows: dict = defaultdict(deque)
_strike_lock = threading.Lock()

# In-memory metrics ring — last 500 events, served to the dashboard
_metrics_ring: deque = deque(maxlen=500)
_metrics_lock = threading.Lock()
_counters: dict = defaultdict(int)   # outcome → total count

_db_lock = threading.Lock()


# ─────────────────────────────────────────────
# Controller
# ─────────────────────────────────────────────

class MitigationController:
    """
    Single instance created at proxy startup.
    All request policy and state live here; idms_proxy.py is routing-only.
    """

    def __init__(self, lb_url: str, honeypot_url: str, db_path: str):
        self.lb_url       = lb_url
        self.honeypot_url = honeypot_url
        self.db_path      = db_path
        self._persistent_conn = None
        self._init_db()

    # ── Full request pipeline ─────────────────────────────────────────────────

    def process(
        self,
        client_ip: str,
        path: str,
        headers: dict,
        raw_body: bytes,
        body: dict,
    ):
        """
        Entry point for every intercepted request.
        Returns a Flask (jsonify(...), status_code) tuple.

        Pipeline:
          1. Already blocked?  → 403 immediately, no detection
          2. Rule-based check  → DetectionResult
          3. Anomaly scoring   → DetectionResult (only when rules pass)
          4. Act on verdict    → block / honeypot / deprioritise / allow
        """
        t0 = time.perf_counter()

        # ── Step 1: Short-circuit blocked IPs ────────────────────────────────
        if self._is_blocked(client_ip):
            total_ms = (time.perf_counter() - t0) * 1000
            self._record_metric("block", client_ip, "ip_blocked", "high", 0.0, total_ms, path)
            return jsonify({
                "error":  "Request blocked by IDMS",
                "reason": "IP is currently blocked",
            }), 403

        # ── Step 2: Rule-based detection ──────────────────────────────────────
        verdict = rule_inspect(
            client_ip=client_ip,
            path=path,
            headers=headers,
            body=body,
            raw_body_bytes=len(raw_body),
        )

        # ── Step 3: Statistical anomaly scoring (only when rules pass) ────────
        # Keeps detection layers independent: each flagged event is attributed
        # to exactly one source, which matters for Phase 6 false-positive metrics.
        if not verdict.flagged:
            verdict = anomaly_score(
                client_ip=client_ip,
                payload_bytes=len(raw_body),
                ts=time.time(),
            )

        total_ms = (time.perf_counter() - t0) * 1000

        # ── Step 4: Act on verdict ────────────────────────────────────────────
        return self._act(client_ip, verdict, body, headers, path, total_ms)

    # ── Verdict execution ─────────────────────────────────────────────────────

    def _act(self, client_ip, verdict, body, headers, path, total_ms):
        if not verdict.flagged:
            self._record_metric("allow", client_ip, None, None,
                                verdict.inspection_ms, total_ms, path)
            data, status = self._forward(self.lb_url, path, headers, body)
            return jsonify(data), status

        # Log every flagged event to SQLite
        self._log_detection(
            ts=time.time(), ip=client_ip, path=path,
            rule_name=verdict.rule_name, severity=verdict.severity,
            action=verdict.recommended, detail=verdict.detail,
            inspect_ms=verdict.inspection_ms, total_ms=total_ms,
        )

        if verdict.recommended == "block":
            duration = self._block_duration(verdict.severity)
            self._block_ip(client_ip, duration, verdict.rule_name)
            self._record_metric("block", client_ip, verdict.rule_name, verdict.severity,
                                verdict.inspection_ms, total_ms, path)
            return jsonify({
                "error":  "Request blocked by IDMS",
                "reason": verdict.detail,
            }), 403

        if verdict.recommended == "honeypot":
            self._record_metric("honeypot", client_ip, verdict.rule_name, verdict.severity,
                                verdict.inspection_ms, total_ms, path)
            data, status = self._forward(self.honeypot_url, path, headers, body, tag="honeypot")
            return jsonify(data), status

        if verdict.recommended == "deprioritise":
            # Check escalation before forwarding
            if self._record_strike(client_ip):
                duration = MITIGATION_CONFIG["escalation_block_duration"]
                self._block_ip(client_ip, duration, "escalation")
                self._record_metric("block", client_ip, "escalation", "high",
                                    verdict.inspection_ms, total_ms, path)
                logger.warning(
                    "ESCALATION | ip=%-15s auto-blocked after %d strikes in %ds → %ds block",
                    client_ip,
                    MITIGATION_CONFIG["escalation_strikes"],
                    MITIGATION_CONFIG["escalation_window_seconds"],
                    duration,
                )
                return jsonify({
                    "error":  "Request blocked by IDMS",
                    "reason": "Repeated anomalous behaviour",
                }), 403

            self._record_metric("deprioritise", client_ip, verdict.rule_name, verdict.severity,
                                verdict.inspection_ms, total_ms, path)
            data, status = self._forward(self.lb_url, path, headers, body, tag="deprioritised")
            return jsonify(data), status

        # Unknown recommendation — treat as allow (log a warning)
        logger.warning("MITIGATION | unknown recommendation=%r for ip=%s — allowing",
                       verdict.recommended, client_ip)
        self._record_metric("allow", client_ip, None, None,
                            verdict.inspection_ms, total_ms, path)
        data, status = self._forward(self.lb_url, path, headers, body)
        return jsonify(data), status

    # ── Escalation ────────────────────────────────────────────────────────────

    def _record_strike(self, client_ip: str) -> bool:
        """
        Append a deprioritise strike for client_ip.
        Returns True when the sliding-window strike count hits the threshold
        (caller should immediately block the IP).
        """
        cfg    = MITIGATION_CONFIG
        now    = time.time()
        cutoff = now - cfg["escalation_window_seconds"]

        with _strike_lock:
            dq = _strike_windows[client_ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(now)
            count = len(dq)

        return count >= cfg["escalation_strikes"]

    # ── Block management ──────────────────────────────────────────────────────

    def _block_duration(self, severity: str) -> int:
        return {
            "medium":   MITIGATION_CONFIG["block_duration_medium"],
            "high":     MITIGATION_CONFIG["block_duration_high"],
            "critical": MITIGATION_CONFIG["block_duration_critical"],
        }.get(severity or "medium", MITIGATION_CONFIG["block_duration_medium"])

    def _block_ip(self, ip: str, duration_seconds: int, rule_name: str = None):
        now = time.time()
        with _db_lock:
            conn = self._db()
            conn.execute(
                """INSERT INTO ip_reputation
                       (ip, status, rule_name, blocked_at, unblock_at, hit_count, last_seen)
                   VALUES (?, 'blocked', ?, ?, ?, 1, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     status     = 'blocked',
                     rule_name  = excluded.rule_name,
                     blocked_at = excluded.blocked_at,
                     unblock_at = excluded.unblock_at,
                     hit_count  = hit_count + 1,
                     last_seen  = excluded.last_seen""",
                (ip, rule_name, now, now + duration_seconds, now),
            )
            conn.commit()
        logger.warning("BLOCKED ip=%s for %ds reason=%s", ip, duration_seconds, rule_name)

    def _is_blocked(self, ip: str) -> bool:
        """Check block status; auto-expires stale blocks."""
        now = time.time()
        with _db_lock:
            conn = self._db()
            row = conn.execute(
                "SELECT status, unblock_at FROM ip_reputation WHERE ip=?", (ip,)
            ).fetchone()

        if row is None or row["status"] != "blocked":
            return False
        if row["unblock_at"] and now > row["unblock_at"]:
            self._unblock_ip(ip)
            return False
        return True

    def unblock(self, ip: str):
        """Public — called by the admin endpoint and auto-expiry."""
        self._unblock_ip(ip)

    def _unblock_ip(self, ip: str):
        with _db_lock:
            conn = self._db()
            conn.execute(
                "UPDATE ip_reputation SET status='clean', blocked_at=NULL, unblock_at=NULL WHERE ip=?",
                (ip,),
            )
            conn.commit()
        rule_reset(ip)
        anomaly_reset(ip)
        with _strike_lock:
            _strike_windows.pop(ip, None)
        logger.info("UNBLOCKED ip=%s", ip)

    # ── HTTP forwarding ───────────────────────────────────────────────────────

    def _forward(self, target_base: str, path: str, headers: dict, body: dict, tag: str = None):
        fwd_headers = dict(headers)
        fwd_headers["X-Forwarded-By"] = "idms"
        if tag:
            fwd_headers["X-IDMS-Tag"] = tag
        try:
            resp = http.post(
                f"{target_base}{path}",
                json=body,
                headers=fwd_headers,
                timeout=15,
            )
            try:
                return resp.json(), resp.status_code
            except Exception:
                return {"raw": resp.text}, resp.status_code
        except http.exceptions.Timeout:
            return {"error": "upstream timeout"}, 504
        except http.exceptions.ConnectionError as e:
            return {"error": f"upstream unreachable: {e}"}, 502

    # ── Metrics ───────────────────────────────────────────────────────────────

    def _record_metric(self, outcome, ip, rule_name, severity, inspect_ms, total_ms, path):
        event = {
            "ts":         time.time(),
            "outcome":    outcome,
            "ip":         ip,
            "rule_name":  rule_name,
            "severity":   severity,
            "inspect_ms": round(inspect_ms, 3),
            "total_ms":   round(total_ms, 3),
            "path":       path,
        }
        with _metrics_lock:
            _metrics_ring.append(event)
            _counters[outcome] += 1

    def get_metrics(self, n: int = 100) -> dict:
        n = min(n, 500)
        with _metrics_lock:
            events = list(_metrics_ring)[-n:]
        return {
            "counters": dict(_counters),
            "events":   events,
            "rates":    get_current_rates(),
            "anomaly":  get_anomaly_snapshot(),
        }

    def get_blocked(self) -> list:
        with _db_lock:
            conn = self._db()
            rows = conn.execute(
                "SELECT ip, rule_name, blocked_at, unblock_at, hit_count "
                "FROM ip_reputation WHERE status='blocked' ORDER BY blocked_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_attack_log(self, limit: int = 200) -> list:
        limit = min(limit, 1000)
        with _db_lock:
            conn = self._db()
            rows = conn.execute(
                "SELECT * FROM detection_log ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_log(self) -> dict:
        """Wipe the detection log and reset ALL state. Called by the demo Reset button."""
        with _db_lock:
            conn = self._db()
            conn.execute("DELETE FROM detection_log")
            conn.execute("UPDATE ip_reputation SET status='clean', blocked_at=NULL, unblock_at=NULL "
                         "WHERE status IN ('blocked','flagged')")
            conn.commit()
        with _metrics_lock:
            _metrics_ring.clear()
            _counters.clear()
        with _strike_lock:
            _strike_windows.clear()
        # Reset per-IP state inside detection engines so repeat demos start clean
        rule_reset_all()
        anomaly_reset_all()
        logger.info("CLEAR_LOG | detection log, metrics, and engine state wiped")
        return {"cleared": True}

    def get_config(self) -> dict:
        return {
            "rules":      RULE_CONFIG,
            "anomaly":    ANOMALY_CONFIG,
            "mitigation": MITIGATION_CONFIG,
        }

    def update_config(self, updates: dict) -> dict:
        rule_allowed = {
            "rate_limit_window_seconds", "rate_limit_max_requests",
            "max_payload_bytes", "max_list_items",
            "endpoint_scan_window_seconds", "endpoint_scan_max_distinct",
        }
        anomaly_allowed = {
            "window_seconds", "min_baseline_samples",
            "zscore_threshold", "zscore_high_multiplier",
            "payload_zscore_weight", "iat_zscore_weight",
        }
        mitigation_allowed = {
            "block_duration_medium", "block_duration_high", "block_duration_critical",
            "escalation_strikes", "escalation_window_seconds", "escalation_block_duration",
        }
        changed = {}
        for k, v in updates.items():
            if k in rule_allowed:
                RULE_CONFIG[k] = v
                changed[k] = v
            elif k in anomaly_allowed:
                ANOMALY_CONFIG[k] = v
                changed[k] = v
            elif k in mitigation_allowed:
                MITIGATION_CONFIG[k] = v
                changed[k] = v
        return changed

    # ── SQLite ────────────────────────────────────────────────────────────────

    def _db(self):
        """Return a persistent connection (reused across calls, protected by _db_lock)."""
        if self._persistent_conn is None:
            self._persistent_conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._persistent_conn.row_factory = sqlite3.Row
            self._persistent_conn.execute("PRAGMA journal_mode=WAL")
        return self._persistent_conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip          TEXT PRIMARY KEY,
                status      TEXT NOT NULL DEFAULT 'clean',
                rule_name   TEXT,
                blocked_at  REAL,
                unblock_at  REAL,
                hit_count   INTEGER DEFAULT 0,
                last_seen   REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL,
                ip          TEXT,
                path        TEXT,
                rule_name   TEXT,
                severity    TEXT,
                action      TEXT,
                detail      TEXT,
                inspect_ms  REAL,
                total_ms    REAL
            )
        """)
        conn.commit()
        logger.info("SQLite DB initialised at %s", self.db_path)

    def _log_detection(self, ts, ip, path, rule_name, severity, action, detail, inspect_ms, total_ms):
        with _db_lock:
            conn = self._db()
            conn.execute(
                "INSERT INTO detection_log "
                "(ts,ip,path,rule_name,severity,action,detail,inspect_ms,total_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, ip, path, rule_name, severity, action, detail, inspect_ms, total_ms),
            )
            conn.execute(
                """INSERT INTO ip_reputation (ip, status, rule_name, hit_count, last_seen)
                   VALUES (?, 'flagged', ?, 1, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     hit_count = hit_count + 1,
                     rule_name = excluded.rule_name,
                     last_seen = excluded.last_seen,
                     status    = CASE WHEN status='blocked' THEN 'blocked' ELSE 'flagged' END""",
                (ip, rule_name, ts),
            )
            conn.commit()
