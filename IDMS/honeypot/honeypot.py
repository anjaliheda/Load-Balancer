"""
honeypot.py — Honeypot Server (Phase 3 component, scaffolded in Phase 1)
========================================================================
Accepts redirected suspicious traffic, logs everything, returns a
convincing fake 200 response so the attacker believes they succeeded.

Stores all captures in SQLite for dashboard display and post-experiment
forensic analysis.
"""

import os
import time
import json
import sqlite3
import logging
import threading
from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s honeypot | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("honeypot")

DB_PATH = os.environ.get("HONEYPOT_DB_PATH", "/data/honeypot.db")
_db_lock = threading.Lock()


def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL NOT NULL,
            source_ip   TEXT,
            path        TEXT,
            method      TEXT,
            headers     TEXT,
            payload     TEXT,
            payload_size INTEGER,
            idms_tag    TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Honeypot DB initialised at %s", DB_PATH)


def _get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


app = Flask(__name__)


@app.route("/request", methods=["POST"])
def capture():
    """
    Accept and log any request forwarded by the IDMS.
    Returns a fake success response so the attacker is not alerted.
    """
    ts = time.time()
    source_ip = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        .split(",")[0].strip()
    )
    raw_body = request.get_data()
    payload_str = raw_body.decode("utf-8", errors="replace")
    idms_tag = request.headers.get("X-IDMS-Tag", "")

    logger.warning(
        "CAPTURE ip=%-15s size=%dB tag=%s payload=%s",
        source_ip, len(raw_body), idms_tag, payload_str[:120]
    )

    with _db_lock:
        conn = _get_db()
        conn.execute(
            "INSERT INTO captures "
            "(ts, source_ip, path, method, headers, payload, payload_size, idms_tag) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                ts,
                source_ip,
                request.path,
                request.method,
                json.dumps(dict(request.headers)),
                payload_str,
                len(raw_body),
                idms_tag,
            )
        )
        conn.commit()
        conn.close()

    # Convincing fake response — mirrors real server output structure
    return jsonify({
        "status": "ok",
        "server": "server1",
        "result": None,
        "processing_time": 0.001,
        "load": 0,
    }), 200


@app.route("/captures", methods=["GET"])
def list_captures():
    """Return recent captures for the dashboard."""
    limit = min(int(request.args.get("limit", 100)), 500)
    with _db_lock:
        conn = _get_db()
        rows = conn.execute(
            "SELECT id, ts, source_ip, path, payload_size, idms_tag "
            "FROM captures ORDER BY ts DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "honeypot"})


if __name__ == "__main__":
    _init_db()
    logger.info("Honeypot server starting on port 5002")
    app.run(host="0.0.0.0", port=5002, threaded=True)