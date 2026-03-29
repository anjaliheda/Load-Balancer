"""
idms_proxy.py — Traffic Interception Proxy (Phase 1 skeleton)
=============================================================
Sits upstream of the load balancer on port 5001.
All client traffic flows through here before reaching the LB.

Request lifecycle:
  Client → IDMS:5001/request
              │
              ├─ rule_engine.inspect()       ← Phase 1 (this PR)
              ├─ anomaly_engine.score()      ← Phase 2 (next)
              │
              ├─ MitigationController        ← Phase 3 (next)
              │     ├─ BLOCK  → 403 response
              │     ├─ DEPRIORITISE → forward with tag
              │     └─ HONEYPOT → forward to honeypot:5002
              │
              └─ forward → loadbalancer:5000/request → servers

Metrics collected per-request (for dashboard and Phase 7 eval):
  - inspection_ms  (rule engine latency)
  - total_proxy_ms (end-to-end through IDMS)
  - outcome        (allow | block | deprioritise | honeypot)
  - rule_triggered (which rule fired, if any)
"""

import os
import time
import json
import logging
import threading
import sqlite3
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, request, jsonify, Response
import requests as http

from rule_engine import inspect as rule_inspect, get_current_rates, RULE_CONFIG, reset_state_for_ip

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("idms_proxy")

# ─────────────────────────────────────────────
# Configuration from environment / defaults
# ─────────────────────────────────────────────

LOAD_BALANCER_URL = os.environ.get("LOAD_BALANCER_URL", "http://loadbalancer:5000")
HONEYPOT_URL      = os.environ.get("HONEYPOT_URL",      "http://honeypot:5002")
DB_PATH           = os.environ.get("SQLITE_PATH",        "/data/idms.db")
VALID_API_KEY     = os.environ.get(
    "API_KEY",
    "0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c"
)

# ─────────────────────────────────────────────
# SQLite — IP reputation store
# ─────────────────────────────────────────────

def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
    conn.close()
    logger.info("SQLite DB initialised at %s", DB_PATH)


def _get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_db_lock = threading.Lock()

def _log_detection(ts, ip, path, rule_name, severity, action, detail, inspect_ms, total_ms):
    with _db_lock:
        conn = _get_db()
        conn.execute(
            "INSERT INTO detection_log "
            "(ts,ip,path,rule_name,severity,action,detail,inspect_ms,total_ms) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ip, path, rule_name, severity, action, detail, inspect_ms, total_ms)
        )
        conn.execute(
            """INSERT INTO ip_reputation (ip, status, rule_name, hit_count, last_seen)
               VALUES (?, 'flagged', ?, 1, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 hit_count = hit_count + 1,
                 rule_name = excluded.rule_name,
                 last_seen = excluded.last_seen,
                 status    = CASE WHEN status='blocked' THEN 'blocked' ELSE 'flagged' END
            """,
            (ip, rule_name, ts)
        )
        conn.commit()
        conn.close()


def _block_ip(ip, duration_seconds=60, rule_name=None):
    now = time.time()
    with _db_lock:
        conn = _get_db()
        conn.execute(
            """INSERT INTO ip_reputation (ip, status, rule_name, blocked_at, unblock_at, hit_count, last_seen)
               VALUES (?, 'blocked', ?, ?, ?, 1, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 status     = 'blocked',
                 rule_name  = excluded.rule_name,
                 blocked_at = excluded.blocked_at,
                 unblock_at = excluded.unblock_at,
                 hit_count  = hit_count + 1,
                 last_seen  = excluded.last_seen
            """,
            (ip, rule_name, now, now + duration_seconds, now)
        )
        conn.commit()
        conn.close()
    logger.warning("BLOCKED ip=%s for %ds reason=%s", ip, duration_seconds, rule_name)


def _is_blocked(ip) -> bool:
    """Check if IP is currently in a timed block. Auto-expires stale blocks."""
    now = time.time()
    with _db_lock:
        conn = _get_db()
        row = conn.execute(
            "SELECT status, unblock_at FROM ip_reputation WHERE ip=?", (ip,)
        ).fetchone()
        conn.close()

    if row is None:
        return False
    if row["status"] != "blocked":
        return False
    if row["unblock_at"] and now > row["unblock_at"]:
        # Block expired — reset to clean
        _unblock_ip(ip)
        return False
    return True


def _unblock_ip(ip):
    with _db_lock:
        conn = _get_db()
        conn.execute(
            "UPDATE ip_reputation SET status='clean', blocked_at=NULL, unblock_at=NULL WHERE ip=?",
            (ip,)
        )
        conn.commit()
        conn.close()
    reset_state_for_ip(ip)  # also clear in-memory sliding-window counters
    logger.info("UNBLOCKED ip=%s", ip)

# ─────────────────────────────────────────────
# In-memory metrics ring (last 500 events)
# ─────────────────────────────────────────────

_metrics_ring: deque = deque(maxlen=500)
_metrics_lock = threading.Lock()
_counters = defaultdict(int)   # outcome → count


def _record_metric(outcome, ip, rule_name, severity, inspect_ms, total_ms, path):
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


# ─────────────────────────────────────────────
# Flask app
# ─────────────────────────────────────────────

app = Flask(__name__)


def _client_ip() -> str:
    """Resolve real client IP, respecting X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _forward_to(target_base: str, path: str, headers: dict, body: dict, tag: str = None):
    """
    Forward the request to target_base + path.
    Optionally inject X-IDMS-Tag header for deprioritised requests.
    Returns (response_json, status_code).
    """
    fwd_headers = {k: v for k, v in headers.items()}
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


# ─── Main request interception point ──────────────────────────────────────────

@app.route("/request", methods=["POST"])
def intercept_request():
    t_proxy_start = time.perf_counter()
    client_ip = _client_ip()
    path = "/request"

    # ── 0. Check existing block ──────────────────────────────────────────────
    if _is_blocked(client_ip):
        total_ms = (time.perf_counter() - t_proxy_start) * 1000
        _record_metric("block", client_ip, "ip_blocked", "high", 0, total_ms, path)
        return jsonify({
            "error": "Request blocked by IDMS",
            "reason": "IP is currently blocked"
        }), 403

    # ── 1. Parse body ────────────────────────────────────────────────────────
    raw_body = request.get_data()
    raw_body_bytes = len(raw_body)
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {}

    # ── 2. Rule-based inspection (Phase 1) ──────────────────────────────────
    result = rule_inspect(
        client_ip=client_ip,
        path=path,
        headers=dict(request.headers),
        body=body,
        raw_body_bytes=raw_body_bytes,
    )

    total_ms = (time.perf_counter() - t_proxy_start) * 1000

    # ── 3. Act on verdict ────────────────────────────────────────────────────
    if result.flagged:
        _log_detection(
            ts=time.time(), ip=client_ip, path=path,
            rule_name=result.rule_name, severity=result.severity,
            action=result.recommended, detail=result.detail,
            inspect_ms=result.inspection_ms, total_ms=total_ms,
        )

        if result.recommended == "block":
            _block_ip(client_ip, duration_seconds=60, rule_name=result.rule_name)
            _record_metric("block", client_ip, result.rule_name, result.severity,
                           result.inspection_ms, total_ms, path)
            return jsonify({
                "error": "Request blocked by IDMS",
                "reason": result.detail,
            }), 403

        if result.recommended == "honeypot":
            _record_metric("honeypot", client_ip, result.rule_name, result.severity,
                           result.inspection_ms, total_ms, path)
            data, status = _forward_to(
                HONEYPOT_URL, path,
                dict(request.headers), body,
                tag="honeypot"
            )
            return jsonify(data), status

        if result.recommended == "deprioritise":
            _record_metric("deprioritise", client_ip, result.rule_name, result.severity,
                           result.inspection_ms, total_ms, path)
            data, status = _forward_to(
                LOAD_BALANCER_URL, path,
                dict(request.headers), body,
                tag="deprioritised"
            )
            return jsonify(data), status

    # ── 4. Clean request — forward to load balancer ──────────────────────────
    _record_metric("allow", client_ip, None, None,
                   result.inspection_ms, total_ms, path)
    data, status = _forward_to(
        LOAD_BALANCER_URL, path,
        dict(request.headers), body,
    )
    return jsonify(data), status


# ─── Pass-through routes (algorithm config, health, etc.) ─────────────────────

@app.route("/set_algorithm", methods=["POST"])
def proxy_set_algorithm():
    """Transparently proxy algorithm config calls to the load balancer."""
    try:
        resp = http.post(
            f"{LOAD_BALANCER_URL}/set_algorithm",
            json=request.get_json(),
            timeout=5,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/health", methods=["GET"])
def health():
    """IDMS health — also polls load balancer health downstream."""
    try:
        lb = http.get(f"{LOAD_BALANCER_URL}/health", timeout=3).json()
    except Exception:
        lb = {"status": "unreachable"}
    return jsonify({
        "idms": "healthy",
        "load_balancer": lb,
        "counters": dict(_counters),
    })


# ─── Dashboard / metrics API ──────────────────────────────────────────────────

@app.route("/idms/metrics", methods=["GET"])
def idms_metrics():
    """
    Return the last N events from the in-memory ring + aggregate counters.
    Query param: ?n=100  (default 100)
    """
    n = min(int(request.args.get("n", 100)), 500)
    with _metrics_lock:
        events = list(_metrics_ring)[-n:]
    return jsonify({
        "counters": dict(_counters),
        "events":   events,
        "rates":    get_current_rates(),
    })


@app.route("/idms/blocked", methods=["GET"])
def idms_blocked():
    """List currently blocked IPs from SQLite."""
    with _db_lock:
        conn = _get_db()
        rows = conn.execute(
            "SELECT ip, rule_name, blocked_at, unblock_at, hit_count "
            "FROM ip_reputation WHERE status='blocked' ORDER BY blocked_at DESC"
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/idms/unblock/<ip>", methods=["POST"])
def manual_unblock(ip):
    """Admin endpoint: manually unblock an IP."""
    _unblock_ip(ip)
    return jsonify({"message": f"{ip} unblocked"})


@app.route("/idms/attack_log", methods=["GET"])
def attack_log():
    """Recent detections from SQLite for the dashboard timeline."""
    limit = min(int(request.args.get("limit", 200)), 1000)
    with _db_lock:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM detection_log ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/idms/config", methods=["GET"])
def idms_config():
    """Expose current rule thresholds for the dashboard."""
    return jsonify(RULE_CONFIG)


@app.route("/idms/config", methods=["POST"])
def update_config():
    """
    Runtime threshold update — no restart needed.
    Only whitelisted keys can be changed.
    """
    allowed = {
        "rate_limit_window_seconds", "rate_limit_max_requests",
        "max_payload_bytes", "max_list_items",
        "endpoint_scan_window_seconds", "endpoint_scan_max_distinct",
    }
    updates = request.get_json() or {}
    changed = {}
    for k, v in updates.items():
        if k in allowed:
            RULE_CONFIG[k] = v
            changed[k] = v
    return jsonify({"updated": changed})


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    _init_db()
    logger.info("IDMS proxy starting on port 5001")
    logger.info("Load balancer: %s", LOAD_BALANCER_URL)
    logger.info("Honeypot:      %s", HONEYPOT_URL)
    app.run(host="0.0.0.0", port=5001, threaded=True)