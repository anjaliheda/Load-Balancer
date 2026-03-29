import os
import time
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/overview")
def api_overview():
    idms_healthy = False
    lb_healthy = False
    healthy_servers = 0
    algorithm = "unknown"
    counters = {}
    rates = {}
    events = []

    # IDMS health + counters
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

    # Recent events for charts
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

    # Req/sec series: 60 one-second buckets with zero-fill
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

    # Latency series: last 100 events
    latency_series = [
        {"t": e["ts"], "ms": round(e.get("inspect_ms", 0), 3)}
        for e in events[-100:]
    ]

    # Per-server load + total_requests
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
        "idms_healthy": idms_healthy,
        "lb_healthy": lb_healthy,
        "healthy_servers": healthy_servers,
        "algorithm": algorithm,
        "counters": counters,
        "rates": rates,
        "req_series": req_series,
        "latency_series": latency_series,
        "server_loads": server_loads,
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
