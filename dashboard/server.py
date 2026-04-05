import os
import time
import threading
from flask import Flask, jsonify, request, render_template
import requests as http

app = Flask(__name__)

IDMS_URL = os.environ.get("IDMS_URL", "http://idms:5001")
SERVER_URLS = [
    ("server1", "http://server1:5000"),
    ("server2", "http://server2:5000"),
    ("server3", "http://server3:5000"),
    ("server4", "http://server4:5000"),
]

VALID_API_KEY = "0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c"

# Fixed demo IPs — each scenario uses a distinct fake IP via X-Forwarded-For
# so the dashboard container itself is never blocked and IPs never collide.
DEMO_IPS = {
    "wrong_key": "10.10.0.1",
    "sqli":      "10.10.0.2",
    "flood":     "10.10.0.3",
    "anomaly":   "10.10.0.4",   # used for both auto-baseline and burst
}

# Background baseline traffic control
_baseline_stop = threading.Event()   # set = stopped


# ── Auto-baseline: starts on dashboard startup ────────────────────────────────
# Sends steady traffic from the anomaly demo IP as soon as the IDMS is reachable.
# This ensures the anomaly engine has a warm, stable baseline before Phase 2 is
# demonstrated — no warmup button needed.

def _run_baseline():
    """Steady ~10 req/s from the anomaly IP, runs until _baseline_stop is set.
    Rate is kept well under the 200/10s rate limit so burst requests (50 extra)
    don't trigger rate_limit instead of anomaly detection.
    Backs off automatically when the IP is blocked (e.g. after escalation)
    so blocked events don't flood the dashboard during the demo."""
    headers = {
        "X-API-Key":       VALID_API_KEY,
        "X-Forwarded-For": DEMO_IPS["anomaly"],
    }
    task = {"task_type": "addition", "num1": 1, "num2": 1}
    while not _baseline_stop.is_set():
        try:
            r = http.post(f"{IDMS_URL}/request", json=task, headers=headers, timeout=5)
            if r.status_code == 403:
                # IP is blocked (escalation fired) — wait quietly for the block to expire
                _baseline_stop.wait(timeout=5)
                continue
        except Exception:
            pass
        _baseline_stop.wait(timeout=0.10)   # 100ms → ~10 req/s (stays under 200/10s rate limit)


def _auto_start_baseline():
    """Wait for the IDMS to be ready, then start baseline traffic."""
    # Poll until IDMS responds (up to 60s after dashboard starts)
    for _ in range(60):
        try:
            r = http.get(f"{IDMS_URL}/health", timeout=2)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1)

    _baseline_stop.clear()
    threading.Thread(target=_run_baseline, daemon=True).start()


# Start the auto-baseline in a background thread at import time
threading.Thread(target=_auto_start_baseline, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", active_page="live")


@app.route("/loadbalancer")
def page_loadbalancer():
    return render_template("loadbalancer.html", active_page="lb")


@app.route("/rules")
def page_rules():
    return render_template("rules.html", active_page="rules")


@app.route("/anomaly")
def page_anomaly():
    return render_template("anomaly.html", active_page="anomaly")


@app.route("/mitigation")
def page_mitigation():
    return render_template("mitigation.html", active_page="mitigation")


@app.route("/api/overview")
def api_overview():
    idms_healthy = False
    lb_healthy = False
    healthy_servers = 0
    algorithm = "unknown"
    counters = {}
    rates = {}
    events = []

    try:
        r = http.get(f"{IDMS_URL}/health", timeout=3)
        if r.status_code == 200:
            d = r.json()
            idms_healthy = True
            lb = d.get("load_balancer", {})
            lb_healthy = lb.get("status") == "healthy"
            healthy_servers = lb.get("healthy_servers", 0)
            algorithm = lb.get("algorithm", "unknown")
            counters = d.get("counters", {})
    except Exception:
        pass

    try:
        r = http.get(f"{IDMS_URL}/idms/metrics?n=500", timeout=3)
        if r.status_code == 200:
            d = r.json()
            events = d.get("events", [])
            rates = d.get("rates", {})
            if not counters:
                counters = d.get("counters", {})
    except Exception:
        pass

    now = time.time()
    bucket_map = {}
    for e in events:
        b = int(e["ts"])
        if now - b <= 60:
            bucket_map[b] = bucket_map.get(b, 0) + 1
    req_series = [
        {"t": int(now) - i, "count": bucket_map.get(int(now) - i, 0)}
        for i in range(59, -1, -1)
    ]

    latency_series = [
        {"t": e["ts"], "ms": round(e.get("inspect_ms", 0), 3)}
        for e in events[-100:]
    ]

    server_loads = []
    for name, url in SERVER_URLS:
        try:
            r = http.get(f"{url}/load", timeout=1)
            if r.status_code == 200:
                d = r.json()
                server_loads.append({
                    "name": name,
                    "load": d.get("load", 0),
                    "total_requests": d.get("total_requests", 0),
                })
            else:
                server_loads.append({"name": name, "load": 0, "total_requests": 0})
        except Exception:
            server_loads.append({"name": name, "load": -1, "total_requests": 0})

    return jsonify({
        "idms_healthy":    idms_healthy,
        "lb_healthy":      lb_healthy,
        "healthy_servers": healthy_servers,
        "algorithm":       algorithm,
        "counters":        counters,
        "rates":           rates,
        "req_series":      req_series,
        "latency_series":  latency_series,
        "server_loads":    server_loads,
    })


@app.route("/api/events")
def api_events():
    n = min(int(request.args.get("n", 30)), 200)
    try:
        r = http.get(f"{IDMS_URL}/idms/metrics?n={n}", timeout=3)
        if r.status_code == 200:
            d = r.json()
            return jsonify(list(reversed(d.get("events", []))))
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    return jsonify([])


@app.route("/api/blocked")
def api_blocked():
    try:
        r = http.get(f"{IDMS_URL}/idms/blocked", timeout=3)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/detections")
def api_detections():
    """Return recent detections from SQLite — persists across the in-memory ring."""
    limit = min(int(request.args.get("limit", 50)), 200)
    try:
        r = http.get(f"{IDMS_URL}/idms/attack_log?limit={limit}", timeout=3)
        if r.status_code == 200:
            return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    return jsonify([])


@app.route("/api/algorithm", methods=["POST"])
def api_set_algorithm():
    try:
        r = http.post(f"{IDMS_URL}/set_algorithm", json=request.get_json(), timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    try:
        r = http.post(f"{IDMS_URL}/idms/unblock/{ip}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/config", methods=["GET"])
def api_get_config():
    try:
        r = http.get(f"{IDMS_URL}/idms/config", timeout=3)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/config", methods=["POST"])
def api_update_config():
    try:
        r = http.post(f"{IDMS_URL}/idms/config", json=request.get_json(), timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Demo control ───────────────────────────────────────────────────────────────

@app.route("/api/demo", methods=["POST"])
def api_demo():
    scenario = (request.get_json() or {}).get("type")
    task = {"task_type": "addition", "num1": 1, "num2": 1}

    # ── Phase 1: wrong API key ────────────────────────────────────────────────
    if scenario == "wrong_key":
        headers = {
            "X-API-Key":       "wrong-key-abc",
            "X-Forwarded-For": DEMO_IPS["wrong_key"],
        }
        try:
            r = http.post(f"{IDMS_URL}/request", json=task, headers=headers, timeout=5)
            return jsonify({
                "message": f"Sent. IDMS returned {r.status_code}. "
                           "Look for 'Wrong API Key' in the Detections table — blocked instantly."
            })
        except Exception as e:
            return jsonify({"message": f"Error: {e}"}), 502

    # ── Phase 1: SQL injection ────────────────────────────────────────────────
    if scenario == "sqli":
        payload = {"task_type": "addition", "num1": "1 OR 1=1 --", "num2": 1}
        headers = {
            "X-API-Key":       VALID_API_KEY,
            "X-Forwarded-For": DEMO_IPS["sqli"],
        }
        try:
            r = http.post(f"{IDMS_URL}/request", json=payload, headers=headers, timeout=5)
            return jsonify({
                "message": f"Sent. IDMS returned {r.status_code}. "
                           "Look for 'SQL Injection' with outcome Honeypot — attacker got a fake success."
            })
        except Exception as e:
            return jsonify({"message": f"Error: {e}"}), 502

    # ── Phase 1: rate flood ───────────────────────────────────────────────────
    if scenario == "flood":
        headers = {
            "X-API-Key":       VALID_API_KEY,
            "X-Forwarded-For": DEMO_IPS["flood"],
        }
        def _flood():
            # Concurrent sends with a 10ms stagger so the counter visibly ramps
            # up over ~2.5s. All 250 land within one 10s rate-limit window.
            def _one():
                try:
                    http.post(f"{IDMS_URL}/request", json=task, headers=headers, timeout=5)
                except Exception:
                    pass
            threads = [threading.Thread(target=_one, daemon=True) for _ in range(250)]
            for t in threads:
                t.start()
                time.sleep(0.01)
            for t in threads:
                t.join(timeout=8)
        threading.Thread(target=_flood, daemon=True).start()
        return jsonify({
            "message": "Flooding: 250 requests over ~2.5s. "
                       "Allow counter climbs → rate limit fires at 200 req/10s → Block counter takes over."
        })

    # ── Phase 2: burst attack ─────────────────────────────────────────────────
    # The baseline is already running in the background (auto-started on boot).
    # Fire all burst requests concurrently — the IDMS receives them with ~1ms IAT
    # versus the ~50ms baseline IAT, producing a large Z-score.
    if scenario == "burst":
        headers = {
            "X-API-Key":       VALID_API_KEY,
            "X-Forwarded-For": DEMO_IPS["anomaly"],
        }
        def _burst():
            def _one():
                try:
                    http.post(f"{IDMS_URL}/request", json=task, headers=headers, timeout=5)
                except Exception:
                    pass
            threads = [threading.Thread(target=_one, daemon=True) for _ in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=8)
        threading.Thread(target=_burst, daemon=True).start()
        return jsonify({
            "message": "Burst sent: 50 concurrent requests from the same IP. "
                       "IAT drops from ~50ms baseline to ~1ms — watch for 'Burst Anomaly' in Detections."
        })

    # ── Reset: clear history + unblock all demo IPs ──────────────────────────
    if scenario == "reset":
        # 1. Wipe detection log, metrics ring, and all blocks in one call
        try:
            http.post(f"{IDMS_URL}/idms/clear_log", timeout=5)
        except Exception:
            pass
        # 2. Also reset anomaly/rule state for each demo IP individually
        for ip in DEMO_IPS.values():
            try:
                http.post(f"{IDMS_URL}/idms/unblock/{ip}", timeout=3)
            except Exception:
                pass
        return jsonify({
            "message": "Cleared all history and unblocked all demo IPs. "
                       "Baseline rebuilds in ~15s — then Phase 2 is ready again."
        })

    return jsonify({"message": "Unknown scenario."}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
