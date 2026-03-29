import requests #used to send HTTP requests
import time #for time.time() time.sleep()
import threading #for concurrent execution of requests
import random #generates random values
import statistics #for mean, median, mode, standard deviation
from datetime import datetime #to track timestamps
from collections import defaultdict #initializes missing keys with default value
import string #for generating random user names
import json #encoding and decoding json data
import socket


# Configuration
LOAD_BALANCER_URL = "http://idms:5001/request"
SET_ALGO_URL      = "http://idms:5001/set_algorithm"
IDMS_URL          = "http://idms:5001"


def _wait_for_idms(timeout=60):
    """Poll IDMS /health until it responds, or timeout."""
    print("Waiting for IDMS to be ready...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{IDMS_URL}/health", timeout=2)
            if resp.status_code == 200:
                print(" ready.")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print(" timed out.")
    return False


def _self_unblock():
    """
    Unblock the client's own IP via the IDMS admin endpoint.
    Called before AND after test_authentication():
      - Before: clears stale blocks persisted in SQLite from previous runs.
      - After:  clears the block the no-API-key auth test triggers.
    """
    try:
        my_ip = socket.gethostbyname(socket.gethostname())
        resp = requests.post(f"{IDMS_URL}/idms/unblock/{my_ip}", timeout=5)
        if resp.status_code == 200:
            print(f"Unblocked client IP {my_ip}.")
    except Exception as e:
        print(f"Warning: could not self-unblock ({e}) — waiting 65s for block to expire...")
        time.sleep(65)

class PerformanceMetrics:
    """Track and analyze request performance metrics"""
    def __init__(self):
        self.response_times = [] #dictionary(stores key value pairs)
        self.failed_requests = []  
        self.total_requests = 0
        self.server_distribution = defaultdict(list)  # Store response times per server
        self.task_distribution = defaultdict(list)    # Store response times per task type
        self.start_time = None
        self.end_time = None
        self.error_distribution = defaultdict(int)    # Count different types of errors

    def record_request(self, server, task_type, response_time=None, error=None):
        """Record metrics for a single request"""
        if not self.start_time:
            self.start_time = datetime.now()
        
        self.total_requests += 1
        
        if response_time is not None:
            self.response_times.append(response_time)
            self.server_distribution[server].append(response_time)
            self.task_distribution[task_type].append(response_time)
        else:
            self.failed_requests.append({
                'server': server,
                'task_type': task_type,
                'error': error
            })
            self.error_distribution[str(error)] += 1
            
        self.end_time = datetime.now()

    def get_server_stats(self, server):
        """Calculate statistics for a specific server"""
        times = self.server_distribution[server]
        if not times:
            return None
        return {
            'count': len(times),
            'avg': statistics.mean(times),
            'min': min(times),
            'max': max(times),
            'std': statistics.stdev(times) if len(times) > 1 else 0
        }

    def print_summary(self, phase_name):
        """Print comprehensive performance summary"""
        print(f"\n{'='*20} {phase_name} Summary {'='*20}")
        duration = (self.end_time - self.start_time).total_seconds()
        print(f"Total Duration: {duration:.2f}s")
        print(f"Requests per second: {self.total_requests/duration:.1f}")

        print(f"\nRequest Statistics:")
        print(f"  Total Requests: {self.total_requests}")
        print(f"  Successful: {len(self.response_times)}")
        print(f"  Failed: {len(self.failed_requests)}")
        success_rate = (len(self.response_times)/self.total_requests*100)
        print(f"  Success Rate: {success_rate:.1f}%")

        if self.response_times:
            print(f"\nResponse Time Statistics:")
            print(f"  Average: {statistics.mean(self.response_times):.2f}s")
            print(f"  Median: {statistics.median(self.response_times):.2f}s")
            print(f"  Min: {min(self.response_times):.2f}s")
            print(f"  Max: {max(self.response_times):.2f}s")
            if len(self.response_times) > 1:
                print(f"  Std Dev: {statistics.stdev(self.response_times):.2f}s")

        if self.server_distribution:
            print(f"\nServer Distribution and Performance:")
            total_successful = len(self.response_times)
            for server in sorted(self.server_distribution.keys()):
                stats = self.get_server_stats(server)
                request_count = len(self.server_distribution[server])
                percentage = (request_count/total_successful*100)
                print(f"  {server}:")
                print(f"    Requests: {request_count} ({percentage:.1f}%)")
                print(f"    Avg Response: {stats['avg']:.2f}s")
                print(f"    Min/Max: {stats['min']:.2f}s / {stats['max']:.2f}s")

        if self.task_distribution:
            print(f"\nTask Type Performance:")
            for task_type, times in sorted(self.task_distribution.items()):
                print(f"  {task_type:15s}: {len(times):3d} requests, "
                      f"avg={statistics.mean(times):.2f}s, "
                      f"max={max(times):.2f}s")

        if self.error_distribution:
            print(f"\nError Distribution:")
            for error, count in self.error_distribution.items():
                print(f"  {error}: {count} occurrences")

        print("=" * 60)

def generate_basic_task():
    """Generate a random basic computation task"""
    tasks = [
        # Light tasks (30% probability)
        *([{
            "task_type": "addition",
            "num1": random.randint(1, 100),
            "num2": random.randint(1, 100)
        }] * 15),
        *([{
            "task_type": "string_length",
            "text": "Hello" * random.randint(1, 10)
        }] * 15),
        
        # Medium tasks (40% probability)
        *([{
            "task_type": "multiplication",
            "num1": random.randint(1, 100),
            "num2": random.randint(1, 100)
        }] * 20),
        *([{
            "task_type": "find_vowels",
            "text": "Hello World" * random.randint(1, 5)
        }] * 20),
        
        # Heavy tasks (30% probability)
        *([{
            "task_type": "factorial",
            "num": random.randint(1, 7)
        }] * 15),
        *([{
            "task_type": "sort_large_list",
            "numbers": [random.randint(1, 1000) for _ in range(100)]
        }] * 15)
    ]
    return random.choice(tasks)

def generate_db_task():
    """Generate a random database task"""
    
    # Generate a random user for create operations
    def generate_user():
        return {
            "username": ''.join(random.choices(string.ascii_lowercase, k=8)),
            "email": f"user_{random.randint(1000, 9999)}@example.com",
            "age": random.randint(18, 80),
            "active": random.choice([True, False])
        }
    
    tasks = [
        # Data generation (seeding the database)
        *([{
            "task_type": "db_generate_data",
            "count": random.randint(5, 20)
        }] * 10),
        
        # Create operations
        *([{
            "task_type": "db_create_user",
            "user_data": generate_user()
        }] * 20),
        
        # Query operations
        *([{
            "task_type": "db_find_users",
            "query": {"active": True},
            "limit": random.randint(5, 20)
        }] * 25),
        *([{
            "task_type": "db_find_users",
            "query": {"active": False},
            "limit": random.randint(5, 20)
        }] * 25),
        
        # Aggregation operations (heavier)
        *([{
            "task_type": "db_aggregate",
            "pipeline": [
                {"$group": {"_id": "$active", "count": {"$sum": 1}, "avg_age": {"$avg": "$age"}}}
            ]
        }] * 20)
    ]
    return random.choice(tasks)

def send_request(url, metrics, task_id, task_type="basic", batch_start_time=None):
    """Send a single request and record metrics"""
    if task_type == "basic":
        task = generate_basic_task()
    elif task_type == "database":
        task = generate_db_task()
    else:
        # Mix of both types
        task = generate_db_task() if random.random() < 0.4 else generate_basic_task()
    
    start_time = time.time()
    
    try:
       
    # Get API key from environment or use secure default
        api_key = '0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c'
        headers = {'X-API-Key': api_key}
        
        response = requests.post(url, json=task, headers=headers, timeout=30)
        end_time = time.time()
        response_time = end_time - start_time
        if response.status_code == 200:
            server = response.json().get('server', 'unknown')
            load = response.json().get('load', 'N/A')
            processing_time = response.json().get('processing_time', 'N/A')
            
            # Calculate queue time (time spent waiting before processing)
            queue_time = response_time - (processing_time if isinstance(processing_time, (int, float)) else 0)
            
            print(f"Request {task_id:3d} | {task['task_type']:15s} | "
                  f"Server: {server:15s} | Load: {load:2} | "
                  f"Time: {response_time:.2f}s (Queue: {queue_time:.2f}s)")
            
            metrics.record_request(server, task['task_type'], response_time)
        else:
            error_msg = f"Status {response.status_code}"
            if response.status_code == 503:
                error_msg = "Server Overloaded"
            print(f"Request {task_id:3d} | {task['task_type']:15s} | Failed: {error_msg}")
            metrics.record_request(None, task['task_type'], None, error_msg)
            
    except Exception as e:
        print(f"Request {task_id:3d} | {task['task_type']:15s} | Error: {str(e)}")
        metrics.record_request(None, task['task_type'], None, str(e))

def run_test_phase(url, num_requests, phase_name, task_type="basic", delay_between_requests=0.1):
    """Run a test phase with the specified number of requests"""
    metrics = PerformanceMetrics()
    
    print(f"\n{'='*20} {phase_name} {'='*20}")
    print(f"Starting {num_requests} requests ({task_type} tasks)...")
    print("\nRequest ID | Task Type       | Server          | Load | Time (Queue)")
    print("-" * 75)
    
    # Create and start threads
    threads = []
    batch_start_time = time.time()
    
    for i in range(num_requests):
        thread = threading.Thread(
            target=send_request,
            args=(url, metrics, i+1, task_type, batch_start_time)
        )
        threads.append(thread)
        thread.start()
        time.sleep(delay_between_requests)
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        
    metrics.print_summary(phase_name)
    return metrics
def test_authentication():
    """Test API key authentication"""
    print("\n=== Testing API Authentication ===")
    
    # Test with correct API key
    task = {"task_type": "addition", "num1": 5, "num2": 10}
    correct_api_key = '0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c'
    correct_headers = {'X-API-Key': correct_api_key}
    
    try:
        print("Testing with correct API key...")
        response = requests.post(LOAD_BALANCER_URL, json=task, headers=correct_headers, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print("Authentication successful!")
        else:
            print(f"Unexpected response: {response.text}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    
    # Test with incorrect API key
    incorrect_headers = {'X-API-Key': 'wrong-key-abc'}

    try:
        print("\nTesting with incorrect API key...")
        response = requests.post(LOAD_BALANCER_URL, json=task, headers=incorrect_headers, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 403:
            print("Authentication correctly blocked request with invalid API key!")
        else:
            print(f"Unexpected response: {response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")

    # Unblock before the no-key test so it's classified as missing_api_key, not ip_blocked
    _self_unblock()

    # Test with no API key
    try:
        print("\nTesting with no API key...")
        response = requests.post(LOAD_BALANCER_URL, json=task, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 403:
            print("IDMS correctly blocked request with missing API key!")
        else:
            print(f"Unexpected response: {response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    """Main test execution function"""
    _wait_for_idms()
    _self_unblock()
    test_authentication()
    _self_unblock()

    NUM_REQUESTS = 150   # mixed tasks per algorithm run
    DELAY_BETWEEN = 0.05 # 20 req/s — stays under IDMS rate limit (200/10s)

    print("\n=== Load Balancing Algorithm Comparison (via IDMS) ===")

    algorithms = ["round_robin", "source_hashing", "least_loaded"]
    algorithm_metrics = {}

    for algorithm in algorithms:
        print(f"\nSetting algorithm: {algorithm}...")
        try:
            resp = requests.post(SET_ALGO_URL, json={"algorithm": algorithm})
            if resp.status_code != 200:
                print(f"  Failed to set algorithm: {resp.status_code}")
                continue
        except Exception as e:
            print(f"  Error: {e}")
            continue

        time.sleep(3)  # let LB settle

        algorithm_metrics[algorithm] = run_test_phase(
            LOAD_BALANCER_URL,
            NUM_REQUESTS,
            f"{algorithm} — mixed workload",
            "mixed",
            DELAY_BETWEEN,
        )
        time.sleep(5)  # cool down between runs

    # ── Comparison table ──────────────────────────────────────────────────────
    print("\n=== Algorithm Comparison ===")
    print(f"\n{'Metric':<16} | {'Round Robin':>12} | {'Source Hash':>12} | {'Least Loaded':>12}")
    print("-" * 60)

    def get_stats(metrics):
        if not metrics or not metrics.response_times:
            return ("N/A",) * 5
        return (
            f"{len(metrics.response_times)/metrics.total_requests*100:.1f}%",
            f"{statistics.mean(metrics.response_times):.2f}s",
            f"{min(metrics.response_times):.2f}s",
            f"{max(metrics.response_times):.2f}s",
            f"{len(metrics.failed_requests)}",
        )

    rr = get_stats(algorithm_metrics.get("round_robin"))
    sh = get_stats(algorithm_metrics.get("source_hashing"))
    ll = get_stats(algorithm_metrics.get("least_loaded"))

    labels = ["Success Rate", "Avg Response", "Min Response", "Max Response", "Failed Reqs"]
    for i, label in enumerate(labels):
        print(f"{label:<16} | {rr[i]:>12} | {sh[i]:>12} | {ll[i]:>12}")

    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
