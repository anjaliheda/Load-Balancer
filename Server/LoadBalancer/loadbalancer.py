from flask import Flask, request, jsonify
import requests
import itertools
import hashlib
import random
import time
import json
import threading

app = Flask(__name__)

# Server configuration
servers = ["http://server1:5000", "http://server2:5000", "http://server3:5000", "http://server4:5000"]
current_algorithm = "round_robin"

# Round robin iterator (protected by _rr_lock for thread safety)
server_pool = itertools.cycle(servers)
_rr_lock = threading.Lock()

# Thread-safe server state tracking
_state_lock = threading.Lock()
server_states = {
    server: {
        'healthy': True,
        'last_check': 0.0,
        'consecutive_failures': 0,
        'current_load': 0
    } for server in servers
}

# Cached health/load results from background thread
_HEALTH_CHECK_INTERVAL = 5  # seconds


def _background_health_checker():
    """Periodically check all servers and cache results. Runs every 5s."""
    while True:
        for server in servers:
            try:
                response = requests.get(f"{server}/health", timeout=2)
                with _state_lock:
                    server_states[server]['last_check'] = time.time()
                    if response.status_code == 200:
                        server_states[server]['healthy'] = True
                        server_states[server]['consecutive_failures'] = 0
                    elif response.status_code == 503:
                        server_states[server]['current_load'] = response.json().get('current_load', 999)
                        server_states[server]['consecutive_failures'] += 1
                        if server_states[server]['consecutive_failures'] > 3:
                            server_states[server]['healthy'] = False
                    else:
                        server_states[server]['consecutive_failures'] += 1
                        if server_states[server]['consecutive_failures'] > 3:
                            server_states[server]['healthy'] = False
            except Exception:
                with _state_lock:
                    server_states[server]['consecutive_failures'] += 1
                    if server_states[server]['consecutive_failures'] > 3:
                        server_states[server]['healthy'] = False
        time.sleep(_HEALTH_CHECK_INTERVAL)


# Start background health checker at import time
threading.Thread(target=_background_health_checker, daemon=True).start()


def is_server_healthy(server):
    """Return cached health status (updated by background thread)."""
    with _state_lock:
        return server_states[server]['healthy']


def choose_server_round_robin():
    """Round-robin server selection (thread-safe)."""
    for _ in range(len(servers)):
        with _rr_lock:
            server = next(server_pool)
        if is_server_healthy(server):
            return server
    return None


def choose_server_hash(request_data):
    task_type = str(request_data.get('task_type', ''))

    if task_type.startswith('db_'):
        if 'query' in request_data:
            query_str = json.dumps(request_data['query'], sort_keys=True)
            key = f"{task_type}:{query_str}"
        elif 'user_data' in request_data:
            username = request_data.get('user_data', {}).get('username', '')
            key = f"{task_type}:user:{username}"
        elif 'pipeline' in request_data:
            pipeline_str = json.dumps(request_data['pipeline'], sort_keys=True)
            key = f"{task_type}:{pipeline_str}"
        else:
            key = task_type
    else:
        if task_type in ['addition', 'multiplication']:
            nums = sorted([
                request_data.get('num1', 0),
                request_data.get('num2', 0)
            ])
            key = f"{task_type}:{nums[0]}:{nums[1]}"
        elif task_type == 'factorial':
            key = f"{task_type}:{request_data.get('num', 0)}"
        elif task_type == 'sort_large_list':
            list_len = len(request_data.get('numbers', []))
            key = f"{task_type}:len:{list_len}"
        elif 'text' in request_data:
            text = request_data.get('text', '')[:10]
            key = f"{task_type}:{text}"
        else:
            key = task_type
    time_bucket = int(time.time()) // 30
    key = f"{key}:{time_bucket}"

    # Use first 8 hex chars — faster than converting full 32-char digest
    hash_val = int(hashlib.md5(key.encode()).hexdigest()[:8], 16)
    start_idx = hash_val % len(servers)

    for i in range(len(servers)):
        idx = (start_idx + i) % len(servers)
        server = servers[idx]
        if is_server_healthy(server):
            return server
    return None


def choose_server_least_loaded():
    """Least-loaded server selection using cached load data."""
    healthy_servers = []

    for server in servers:
        if is_server_healthy(server):
            try:
                response = requests.get(f"{server}/load", timeout=1)
                if response.status_code == 200:
                    load = response.json().get('load', 0)
                    with _state_lock:
                        server_states[server]['current_load'] = load
                    healthy_servers.append((server, load))
                else:
                    with _state_lock:
                        healthy_servers.append((server, server_states[server]['current_load']))
            except Exception:
                with _state_lock:
                    healthy_servers.append((server, server_states[server]['current_load']))
    if not healthy_servers:
        return None

    healthy_servers.sort(key=lambda x: x[1] + random.uniform(0, 0.5))
    return healthy_servers[0][0]


@app.route('/set_algorithm', methods=['POST'])
def set_algorithm():
    global current_algorithm
    data = request.json
    algo = data.get('algorithm', 'round_robin')

    if algo in ["round_robin", "source_hashing", "least_loaded"]:
        current_algorithm = algo
        return jsonify({"message": f"Algorithm set to {algo}"})
    else:
        return jsonify({"error": "Invalid algorithm"}), 400


@app.route('/request', methods=['POST'])
def route_request():
    if current_algorithm == "round_robin":
        server = choose_server_round_robin()
    elif current_algorithm == "source_hashing":
        server = choose_server_hash(request.json)
    elif current_algorithm == "least_loaded":
        server = choose_server_least_loaded()
    else:
        server = choose_server_round_robin()

    if not server:
        return jsonify({"error": "No healthy servers available"}), 503

    try:
        response = requests.post(
            f"{server}/request",
            json=request.json,
            timeout=10
        )
        return response.json(), response.status_code
    except requests.exceptions.Timeout:
        with _state_lock:
            server_states[server]['consecutive_failures'] += 1
        return jsonify({"error": "Server timed out"}), 504
    except requests.exceptions.ConnectionError as e:
        with _state_lock:
            server_states[server]['consecutive_failures'] += 1
        return jsonify({"error": f"Server unreachable: {e}"}), 502
    except Exception as e:
        with _state_lock:
            server_states[server]['consecutive_failures'] += 1
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    with _state_lock:
        healthy_count = sum(1 for s in servers if server_states[s]['healthy'])
    return jsonify({
        "status": "healthy" if healthy_count > 0 else "critical",
        "healthy_servers": healthy_count,
        "algorithm": current_algorithm
    })


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
