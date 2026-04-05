from flask import Flask, request, jsonify
import socket
import math
import time
import threading
import signal
import sys
import os
import atexit
from pymongo import MongoClient
from bson import ObjectId
import random
import string

app = Flask(__name__)

# Get container hostname and map it to a simple name
hostname = socket.gethostname()
server_mapping = {
    'server1': 'Server-1',
    'server2': 'Server-2',
    'server3': 'Server-3',
    'server4': 'Server-4'
}
server_name = server_mapping.get(os.environ.get('HOSTNAME', hostname), hostname)

# Database connection
DATABASE_URL = os.environ.get('DATABASE_URL', 'mongodb://database:27017/loadbalancer')
mongo_client = MongoClient(DATABASE_URL, serverSelectionTimeoutMS=5000)
db = mongo_client.get_database()
requests_collection = db.requests
data_collection = db.user_data


def _shutdown_mongo():
    """Close MongoDB connection on shutdown."""
    try:
        mongo_client.close()
    except Exception:
        pass

atexit.register(_shutdown_mongo)

# Server configuration
MAX_CONCURRENT = 5          # Maximum concurrent requests before overload
OVERLOAD_THRESHOLD = 8      # Threshold for server to start rejecting requests

# Server state
class ServerState:
    def __init__(self):
        self.request_count = 0          # Current number of active requests
        self.total_requests = 0         # Total requests handled
        self.request_lock = threading.Lock()
        self.last_request_time = time.time()

server_state = ServerState()

def get_current_load():
    """Calculate current server load"""
    with server_state.request_lock:
        return server_state.request_count

def update_load(delta):
    """Thread-safe update of server load"""
    with server_state.request_lock:
        server_state.request_count = max(0, server_state.request_count + delta)
        if delta > 0:
            server_state.total_requests += 1
        return server_state.request_count

def log_request_to_db(task_type, processing_time, result, status="success"):
    """Log request information to database"""
    try:
        requests_collection.insert_one({
            'server': server_name,
            'task_type': task_type,
            'processing_time': processing_time,
            'timestamp': time.time(),
            'status': status,
            'result': str(result)[:100]  # Truncate result if too long
        })
    except Exception as e:
        print(f"Error logging to database: {str(e)}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint that reports server status"""
    current_load = get_current_load()
    status = "healthy"
    code = 200

    if current_load > OVERLOAD_THRESHOLD:
        status = "overloaded"
        code = 503
    elif current_load > MAX_CONCURRENT:
        status = "heavy_load"

    return jsonify({
        "server": server_name,
        "status": status,
        "current_load": current_load,
        "total_requests": server_state.total_requests
    }), code

@app.route('/load', methods=['GET'])
def get_load():
    """Return current server load metrics"""
    current_load = get_current_load()
    return jsonify({
        "server": server_name,
        "load": current_load,
        "total_requests": server_state.total_requests
    })

@app.route('/request', methods=['POST'])
def handle_request():
    """Handle incoming task requests with load-based processing"""
    current_load = update_load(1)  # Increment load counter
    start_time = time.time()
    result = None
    task_type = "unknown"

    try:
        # Reject if server is severely overloaded
        if current_load > OVERLOAD_THRESHOLD:
            return jsonify({
                "error": "Server overloaded",
                "server": server_name,
                "current_load": current_load
            }), 503

        data = request.json
        task_type = data.get('task_type', 'addition')

        # Calculate base delay based on current load
        # Exponential backoff as load increases
        base_delay = 0.1 * (1.5 ** (current_load - 1))

        # Process different task types with varying complexity
        if task_type == 'addition':
            num1, num2 = data.get('num1', 0), data.get('num2', 0)
            time.sleep(base_delay)
            result = num1 + num2

        elif task_type == 'multiplication':
            num1, num2 = data.get('num1', 1), data.get('num2', 1)
            time.sleep(base_delay * 1.5)
            result = num1 * num2

        elif task_type == 'factorial':
            num = min(data.get('num', 1), 10)  # Limit for safety
            time.sleep(base_delay * 2)
            result = math.factorial(num)

        elif task_type == 'string_length':
            text = data.get('text', '')
            time.sleep(base_delay * 1.2)
            result = len(text)

        elif task_type == 'find_vowels':
            text = data.get('text', '')
            time.sleep(base_delay * 1.3)
            result = len([char for char in text if char.lower() in 'aeiou'])

        elif task_type == 'sort_large_list':
            lst = data.get('numbers', [])
            time.sleep(base_delay * 3)  # Heavier task
            result = sorted(lst)

        # Database operations (new complex tasks)
        elif task_type == 'db_create_user':
            user_data = data.get('user_data', {})
            user_data['created_at'] = time.time()
            time.sleep(base_delay * 2)
            result = data_collection.insert_one(user_data)
            result = str(result.inserted_id)

        elif task_type == 'db_find_users':
            query = data.get('query', {})
            limit = min(data.get('limit', 10), 100)
            time.sleep(base_delay * 2.5)
            result = list(data_collection.find(query, limit=limit))
            for doc in result:
                doc['_id'] = str(doc['_id'])

        elif task_type == 'db_update_user':
            user_id = data.get('user_id', '')
            update_data = data.get('update_data', {})
            update_data['updated_at'] = time.time()
            time.sleep(base_delay * 2.2)
            try:
                object_id = ObjectId(user_id)
            except Exception:
                return jsonify({"error": "Invalid user_id format"}), 400
            result = data_collection.update_one(
                {'_id': object_id},
                {'$set': update_data}
            )
            result = result.modified_count

        elif task_type == 'db_aggregate':
            pipeline = data.get('pipeline', [])
            time.sleep(base_delay * 3)
            result = list(data_collection.aggregate(pipeline))
            for doc in result:
                if '_id' in doc:
                    doc['_id'] = str(doc['_id'])

        elif task_type == 'db_generate_data':
            count = min(data.get('count', 10), 100)
            time.sleep(base_delay * 3.5)

            records = []
            for _ in range(count):
                user = {
                    'username': ''.join(random.choices(string.ascii_lowercase, k=8)),
                    'email': f"user_{random.randint(1000, 9999)}@example.com",
                    'age': random.randint(18, 80),
                    'active': random.choice([True, False]),
                    'created_at': time.time() - random.randint(0, 86400 * 30)
                }
                records.append(user)

            result = data_collection.insert_many(records)
            result = len(result.inserted_ids)

        else:
            log_request_to_db(task_type, 0, None, "invalid_task")
            return jsonify({"error": "Invalid task type"}), 400

        # Add additional delay if server is under heavy load
        if current_load > MAX_CONCURRENT:
            time.sleep(base_delay * 2)

        processing_time = time.time() - start_time
        response = {
            "server": server_name,
            "task": task_type,
            "result": result,
            "load": current_load,
            "processing_time": processing_time
        }

        log_request_to_db(task_type, processing_time, result)
        return jsonify(response)

    except Exception as e:
        processing_time = time.time() - start_time
        log_request_to_db(task_type, processing_time, str(e), "error")
        return jsonify({"error": str(e)}), 500

    finally:
        update_load(-1)  # Always decrement — guaranteed even on crash/early return

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)