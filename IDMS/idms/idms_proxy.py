"""
idms_proxy.py — Traffic Interception Proxy
==========================================
Sits upstream of the load balancer on port 5001.
All client traffic flows through here before reaching the LB.

Request lifecycle:
  Client → IDMS:5001/request
              │
              └─ MitigationController.process()
                    ├─ block check            (short-circuit if already blocked)
                    ├─ rule_engine.inspect()  (Phase 1)
                    ├─ anomaly_engine.score() (Phase 2)
                    └─ act on verdict         (Phase 3)
                          ├─ BLOCK        → 403
                          ├─ HONEYPOT     → forward to honeypot:5002
                          ├─ DEPRIORITISE → forward with X-IDMS-Tag header
                          │                 (escalate → block after N strikes)
                          └─ ALLOW        → forward to loadbalancer:5000

This file owns: HTTP parsing, Flask routing, pass-through proxying to the LB
for non-request routes (algorithm config, health), and the dashboard API.

All detection and mitigation logic lives in mitigation_controller.py.
"""

import os
import logging

import requests as http
from flask import Flask, request, jsonify

from mitigation_controller import MitigationController, MITIGATION_CONFIG
from rule_engine import RULE_CONFIG
from anomaly_engine import ANOMALY_CONFIG

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
# Configuration
# ─────────────────────────────────────────────

LOAD_BALANCER_URL = os.environ.get("LOAD_BALANCER_URL", "http://loadbalancer:5000")
HONEYPOT_URL      = os.environ.get("HONEYPOT_URL",      "http://honeypot:5002")
DB_PATH           = os.environ.get("SQLITE_PATH",        "/data/idms.db")

# ─────────────────────────────────────────────
# Flask + controller
# ─────────────────────────────────────────────

app = Flask(__name__)
controller = MitigationController(LOAD_BALANCER_URL, HONEYPOT_URL, DB_PATH)


def _client_ip() -> str:
    """Resolve real client IP, respecting X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ─── Main request interception ────────────────────────────────────────────────

@app.route("/request", methods=["POST"])
def intercept_request():
    raw_body = request.get_data()
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {}

    return controller.process(
        client_ip=_client_ip(),
        path="/request",
        headers=dict(request.headers),
        raw_body=raw_body,
        body=body,
    )


# ─── Pass-through routes ──────────────────────────────────────────────────────

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
        "idms":          "healthy",
        "load_balancer": lb,
        "counters":      controller.get_metrics()["counters"],
    })


# ─── Dashboard / metrics API ──────────────────────────────────────────────────

@app.route("/idms/metrics", methods=["GET"])
def idms_metrics():
    n = min(int(request.args.get("n", 100)), 500)
    return jsonify(controller.get_metrics(n))


@app.route("/idms/blocked", methods=["GET"])
def idms_blocked():
    return jsonify(controller.get_blocked())


@app.route("/idms/unblock/<ip>", methods=["POST"])
def manual_unblock(ip):
    controller.unblock(ip)
    return jsonify({"message": f"{ip} unblocked"})


@app.route("/idms/attack_log", methods=["GET"])
def attack_log():
    limit = min(int(request.args.get("limit", 200)), 1000)
    return jsonify(controller.get_attack_log(limit))


@app.route("/idms/clear_log", methods=["POST"])
def clear_log():
    return jsonify(controller.clear_log())


@app.route("/idms/config", methods=["GET"])
def idms_config():
    return jsonify(controller.get_config())


@app.route("/idms/config", methods=["POST"])
def update_config():
    updates = request.get_json() or {}
    changed = controller.update_config(updates)
    return jsonify({"updated": changed})


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("IDMS proxy starting on port 5001")
    logger.info("Load balancer: %s", LOAD_BALANCER_URL)
    logger.info("Honeypot:      %s", HONEYPOT_URL)
    app.run(host="0.0.0.0", port=5001, threaded=True)
