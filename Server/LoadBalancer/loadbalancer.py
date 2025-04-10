from flask import Flask, request, jsonify
import requests
import itertools
import hashlib
import random
import time
import os
import json

VALID_API_KEY = '0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c'

app = Flask(__name__)

# Server configuration
servers = ["http://server1:5000", "http://server2:5000", "http://server3:5000", "http://server4:5000"]
current_algorithm = "round_robin"

# Round robin iterator
server_pool = itertools.cycle(servers)

# Server state tracking
server_states = {
    server: {
        'healthy': True,
        'last_check': time.time(),
        'consecutive_failures': 0,
        'current_load': 0
    } for server in servers
}

def is_server_healthy(server):
    """Check server health and update state"""
    try:
        response = requests.get(f"{server}/health", timeout=2)
        server_states[server]['last_check'] = time.time()
        
        if response.status_code == 200:
            server_states[server]['healthy'] = True
            server_states[server]['consecutive_failures'] = 0
            return True
        elif response.status_code == 503:  # Server reports it's overloaded
            server_states[server]['current_load'] = response.json().get('current_load', 999)
            return False
        else:
            server_states[server]['consecutive_failures'] += 1
            if server_states[server]['consecutive_failures'] > 3:
                server_states[server]['healthy'] = False
            return False
    except:
        server_states[server]['consecutive_failures'] += 1
        if server_states[server]['consecutive_failures'] > 0:
            backoff_time = min(30, 2 ** server_states[server]['consecutive_failures'])
            if time.time() - server_states[server]['last_check'] < backoff_time:
                return False  # Skip this server during its backoff period

def get_server_load(server):
    """Get current load of a server"""
    try:
        response = requests.get(f"{server}/load", timeout=1)
        if response.status_code == 200:
            load = response.json().get('load', 0)
            server_states[server]['current_load'] = load
            return load
    except:
        pass
    return server_states[server]['current_load']

def choose_server_round_robin():
    """Round-robin server selection"""
    for _ in range(len(servers)):
        server = next(server_pool)
        if is_server_healthy(server):
            return server
    return None

def choose_server_hash(request_data):
    task_type = str(request_data.get('task_type', ''))
    
    if task_type.startswith('db_'):
        # For database tasks, hash based on the operation type and query parameters
        if 'query' in request_data:
            query_str = json.dumps(request_data['query'], sort_keys=True)
            key = f"{task_type}:{query_str}"
        elif 'user_data' in request_data:
            # For user creation, hash on username to route similar usernames to same server
            username = request_data.get('user_data', {}).get('username', '')
            key = f"{task_type}:user:{username}"
        elif 'pipeline' in request_data:
            # For aggregation, hash on the aggregation pipeline
            pipeline_str = json.dumps(request_data['pipeline'], sort_keys=True)
            key = f"{task_type}:{pipeline_str}"
        else:
            key = task_type
    else:
        # For computation tasks, hash based on operation type and input parameters
        if task_type in ['addition', 'multiplication']:
            nums = sorted([
                request_data.get('num1', 0),
                request_data.get('num2', 0)
            ])
            key = f"{task_type}:{nums[0]}:{nums[1]}"
        elif task_type == 'factorial':
            # Factorial operations are computationally intensive, so hash on the number
            key = f"{task_type}:{request_data.get('num', 0)}"
        elif task_type == 'sort_large_list':
            # For sorting, hash on the length of the list
            list_len = len(request_data.get('numbers', []))
            key = f"{task_type}:len:{list_len}"
        elif 'text' in request_data:
            # For string operations, hash on first few chars of text
            text = request_data.get('text', '')[:10]  # First 10 chars
            key = f"{task_type}:{text}"
        else:
            
            key = task_type
    time_bucket = int(time.time()) // 30
    key = f"{key}:{time_bucket}"
    
    hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
    start_idx = hash_val % len(servers)
    
    for i in range(len(servers)):
        idx = (start_idx + i) % len(servers)
        server = servers[idx]
        if is_server_healthy(server):
            return server
    return None

def choose_server_least_loaded():
    """Least-loaded server selection with improvements"""
    # Update load information for all servers first
    healthy_servers = []
    
    for server in servers:
        if is_server_healthy(server):
            try:
                response = requests.get(f"{server}/load", timeout=1)
                if response.status_code == 200:
                    load = response.json().get('load', 0)
                    server_states[server]['current_load'] = load
                    healthy_servers.append((server, load))
                else:
                    server_states[server]['current_load'] += 1
                    healthy_servers.append((server, server_states[server]['current_load']))
            except:
                server_states[server]['current_load'] += 2
                healthy_servers.append((server, server_states[server]['current_load']))
    if not healthy_servers:
        return None
    
    healthy_servers.sort(key=lambda x: x[1] + random.uniform(0, 0.5))
    chosen_server = healthy_servers[0][0]
    server_states[chosen_server]['current_load'] += 1
    
    return chosen_server

def forward_request(server_url, data):
    try:
        # Get API key from environment (same key as other components)
        api_key = os.environ.get('API_KEY', 'default-key-replace-in-production')
        headers = {'X-API-Key': api_key}
        
        response = requests.post(
            f"{server_url}/process", 
            json=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        return response.json(), response.status_code
    except requests.RequestException as e:
        return {"error": str(e)}, 500

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
    
     # Validate API key
    api_key = request.headers.get('X-API-Key')
    if api_key != VALID_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
        
    if current_algorithm == "round_robin":
        server = choose_server_round_robin()
    elif current_algorithm == "source_hashing":
        server = choose_server_hash(request.json)
    elif current_algorithm == "least_loaded":
        server = choose_server_least_loaded()
        app.logger.info(f"Selected server {server} using least_loaded algorithm")
        loads = {s: server_states[s]['current_load'] for s in servers}
        app.logger.info(f"Current server loads: {loads}")
    else:
        server = choose_server_round_robin()
    
    if not server:
        return jsonify({"error": "No healthy servers available"}), 503
    
    try:
        # Forward the headers from the original request
        headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{server}/request",
            json=request.json,
            headers=headers,
            timeout=10
        )
        return response.json(), response.status_code
    except Exception as e:
        server_states[server]['consecutive_failures'] += 1
        return jsonify({"error": str(e)}), 500
    
@app.route('/health', methods=['GET'])
def health_check():
    healthy_servers = sum(1 for server in servers if is_server_healthy(server))
    return jsonify({
        "status": "healthy" if healthy_servers > 0 else "critical",
        "healthy_servers": healthy_servers,
        "algorithm": current_algorithm
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)