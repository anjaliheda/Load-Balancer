# Technical Reference — Traffic Inspection & Threat Mitigation in Load-Balanced Distributed Systems

> **Status legend:** ✅ Implemented · 🔄 In progress · ⬜ Planned

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Service Inventory](#2-service-inventory)
3. [Request Flow](#3-request-flow)
4. [API Reference](#4-api-reference)
5. [IDMS Detection Rules](#5-idms-detection-rules)
6. [Data Schemas](#6-data-schemas)
7. [Configuration Reference](#7-configuration-reference)
8. [Docker & Deployment](#8-docker--deployment)
9. [Phase Implementation Plan](#9-phase-implementation-plan)
10. [Metrics & Measurement](#10-metrics--measurement)

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         loadbalancer-net (bridge)                    │
│                                                                       │
│  ┌───────────┐    ┌──────────────┐    ┌──────────────────────┐      │
│  │  client   │───▶│  idms :5001  │───▶│  loadbalancer :5000  │      │
│  └───────────┘    │              │    └──────────────────────┘      │
│                   │  rule_engine │              │                     │
│  ┌──────────────┐ │  (Phase 2:   │    ┌─────────┼─────────┐          │
│  │ dashboard    │ │  anomaly_    │    ▼         ▼         ▼          │
│  │ :8080        │ │  engine)     │ server1  server2  server3/4       │
│  │ (reads IDMS  │ │              │  :5000    :5000    :5000           │
│  │  + servers)  │ └──────┬───────┘    └─────────┴────┬────┘          │
│  └──────────────┘        │                           │                │
│                           ▼                           ▼                │
│                  ┌─────────────┐           ┌──────────────┐          │
│                  │ honeypot    │           │  database    │          │
│                  │ :5002       │           │  (MongoDB)   │          │
│                  └─────────────┘           │  :27017      │          │
│                                            └──────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

- **Inline proxy model**: IDMS sits as a transparent reverse proxy — clients need no modification beyond pointing to port 5001 instead of 5000.
- **Separation of detection and mitigation**: `rule_engine.py` returns structured verdicts; `idms_proxy.py` acts on them. Phase 3 will introduce a `MitigationController` between the two.
- **Two-stage inspection pipeline**: Phase 1 (rule-based) + Phase 2 (anomaly/statistical) verdicts are combined before a mitigation action is chosen.
- **Honeypot over hard-block for injection**: SQL/NoSQL injection traffic is silently redirected to the honeypot rather than blocked, so attackers receive a plausible success response and continue sending data we can capture.

---

## 2. Service Inventory

| Container | Build context | Internal port | Exposed port | Purpose |
|---|---|---|---|---|
| `database` | `mongo:latest` | 27017 | 27017 | MongoDB — app data + request logs |
| `server1` | `./Server/Server1` | 5000 | — | Backend worker |
| `server2` | `./Server/Server2` | 5000 | — | Backend worker |
| `server3` | `./Server/Server3` | 5000 | — | Backend worker |
| `server4` | `./Server/Server4` | 5000 | — | Backend worker |
| `loadbalancer` | `./Server/LoadBalancer` | 5000 | 5000 | Routing + algorithm selection |
| `honeypot` | `./IDMS/honeypot` | 5002 | 5002 | Capture injection payloads |
| `idms` | `./IDMS/idms` | 5001 | 5001 | Traffic inspection + mitigation |
| `dashboard` | `./dashboard` | 8080 | 8080 | Live monitoring UI + control plane |
| `client` | `./Client` | — | — | Test runner / load generator |

All containers share the `loadbalancer-net` bridge network. `idms_data` and `honeypot_data` are named volumes for SQLite persistence.

---

## 3. Request Flow

### Normal (clean) request

```
client
  └─▶ POST idms:5001/request
        ├─ [0] IP block check      (SQLite lookup)
        ├─ [1] rule_engine.inspect()
        │     ├─ _check_sqli()
        │     ├─ _check_rate_limit()
        │     ├─ _check_endpoint_scan()
        │     ├─ _check_payload_size()
        │     └─ _check_headers()
        ├─ [2] anomaly_engine.score()   ← Phase 2
        ├─ [3] MitigationController     ← Phase 3
        │     └─ verdict: allow
        └─▶ POST loadbalancer:5000/request
              ├─ API key validation
              ├─ server selection (round_robin | source_hashing | least_loaded)
              └─▶ POST server_N:5000/request
                    ├─ task execution
                    └─◀ {"server", "task", "result", "load", "processing_time"}
```

### Blocked request (rate limit / header violation)

```
client ──▶ idms  ──▶ rule fires → _block_ip() → 403 {"error": "Request blocked by IDMS"}
```

### Honeypotted request (injection detected)

```
client ──▶ idms  ──▶ sqli rule fires → POST honeypot:5002/request → 200 (fake success)
```

### Deprioritised request (endpoint scan)

```
client ──▶ idms  ──▶ endpoint_scan fires → POST loadbalancer:5000/request (X-IDMS-Tag: deprioritised)
```

---

## 4. API Reference

### 4.1 IDMS Proxy (`idms:5001`)

#### `POST /request`
Main interception point. Inspects, classifies, and forwards or blocks.

**Request headers:**
```
X-API-Key: <64-char hex>
Content-Type: application/json
```

**Request body:** any valid task payload (see §4.3)

**Responses:**

| Status | Condition | Body |
|---|---|---|
| Proxied from LB | Clean request | LB response body |
| 403 | IP blocked or rule fires block/critical | `{"error": "Request blocked by IDMS", "reason": "<detail>"}` |
| 200 (fake) | Injection detected → honeypot | `{"status":"ok","server":"server1","result":null,...}` |
| 502/504 | Upstream unreachable / timeout | `{"error": "upstream unreachable/timeout"}` |

---

#### `POST /set_algorithm`
Proxy pass-through to load balancer.

**Body:** `{"algorithm": "round_robin" | "source_hashing" | "least_loaded"}`

**Response:** `{"message": "Algorithm set to <algo>"}` or `400`

---

#### `GET /health`
```json
{
  "idms": "healthy",
  "load_balancer": { "status": "healthy", "healthy_servers": 4, "algorithm": "round_robin" },
  "counters": { "allow": 120, "block": 3, "honeypot": 1, "deprioritise": 2 }
}
```

---

#### `GET /idms/metrics?n=100`
Returns last N events from in-memory ring (max 500) plus aggregate counters and live rate snapshot.

```json
{
  "counters": { "allow": 120, "block": 3, "honeypot": 1, "deprioritise": 2 },
  "events": [
    {
      "ts": 1711612800.123,
      "outcome": "block",
      "ip": "172.18.0.5",
      "rule_name": "rate_limit",
      "severity": "high",
      "inspect_ms": 0.42,
      "total_ms": 1.1,
      "path": "/request"
    }
  ],
  "rates": { "172.18.0.5": 31 }
}
```

---

#### `GET /idms/blocked`
List of currently active IP blocks from SQLite.

```json
[
  {
    "ip": "172.18.0.5",
    "rule_name": "rate_limit",
    "blocked_at": 1711612800.0,
    "unblock_at": 1711612860.0,
    "hit_count": 5
  }
]
```

---

#### `POST /idms/unblock/<ip>`
Admin endpoint. Immediately removes an IP block.

**Response:** `{"message": "172.18.0.5 unblocked"}`

---

#### `GET /idms/attack_log?limit=200`
Detection timeline from SQLite (newest first).

```json
[
  {
    "id": 42,
    "ts": 1711612800.0,
    "ip": "172.18.0.5",
    "path": "/request",
    "rule_name": "sqli",
    "severity": "critical",
    "action": "honeypot",
    "detail": "Injection pattern matched in value: 'UNION SELECT...'",
    "inspect_ms": 0.31,
    "total_ms": 2.4
  }
]
```

---

#### `GET /idms/config`
Returns current `RULE_CONFIG` dict.

#### `POST /idms/config`
Runtime threshold update (no restart). Only whitelisted numeric keys can be changed:
`rate_limit_window_seconds`, `rate_limit_max_requests`, `max_payload_bytes`,
`max_list_items`, `endpoint_scan_window_seconds`, `endpoint_scan_max_distinct`.

---

### 4.2 Load Balancer (`loadbalancer:5000`)

#### `POST /request`
Route a task to a backend server.

**Headers:** `X-API-Key` is forwarded from IDMS but not re-validated here. Auth is enforced solely at the IDMS boundary.

**Algorithms:**
- `round_robin` — cycles healthy servers in order
- `source_hashing` — MD5 of task type + parameters + 30s time bucket → deterministic server selection
- `least_loaded` — queries `/load` on all healthy servers, picks lowest + `uniform(0, 0.5)` jitter

**Response:** proxied from backend, adds server identification.

#### `POST /set_algorithm`
`{"algorithm": "round_robin" | "source_hashing" | "least_loaded"}`

#### `GET /health`
Returns healthy server count and current algorithm.

---

### 4.3 Backend Servers (`server1-4:5000`)

#### `POST /request`

**Task types and payloads:**

| `task_type` | Required fields | Weight |
|---|---|---|
| `addition` | `num1`, `num2` | light |
| `string_length` | `text` | light |
| `multiplication` | `num1`, `num2` | medium |
| `find_vowels` | `text` | medium |
| `factorial` | `num` (capped at 10) | heavy |
| `sort_large_list` | `numbers[]` (capped at 500 by IDMS) | heavy |
| `db_create_user` | `user_data{}` | DB write |
| `db_find_users` | `query{}`, `limit` | DB read |
| `db_update_user` | `user_id`, `update_data{}` | DB write |
| `db_aggregate` | `pipeline[]` | DB complex |
| `db_generate_data` | `count` (capped at 100) | DB bulk |

**Response:**
```json
{
  "server": "Server-1",
  "task": "factorial",
  "result": 5040,
  "load": 2,
  "processing_time": 0.21
}
```

**Load model:**
- `request_count` increments on arrival, decrements on completion (thread-safe).
- Processing delay: `0.1 × 1.5^(load−1)` seconds (exponential backoff under load).
- Returns `503` when `current_load > OVERLOAD_THRESHOLD` (8).

#### `GET /health`
Returns server name, status (`healthy` | `heavy_load` | `overloaded`), current load, total requests.

#### `GET /load`
Returns `{"server", "load", "total_requests"}`.

---

### 4.4 Honeypot (`honeypot:5002`)

#### `POST /request`
Accepts any forwarded request, logs it to SQLite, returns a convincing fake success.

**Response (always 200):**
```json
{ "status": "ok", "server": "server1", "result": null, "processing_time": 0.001, "load": 0 }
```

#### `GET /captures?limit=100`
Recent captures (id, ts, source_ip, path, payload_size, idms_tag).

#### `GET /health`

---

## 5. IDMS Detection Rules

### Rule priority (highest → lowest)

| # | Rule | File | Severity | Action | Trigger condition |
|---|---|---|---|---|---|
| 1 | `missing_api_key` | `rule_engine.py` | medium | block | `X-API-Key` header absent (case-insensitive lookup) |
| 2 | `malformed_api_key` | `rule_engine.py` | medium | block | Key length < 8 or contains `"';\\` |
| 3 | `invalid_api_key` | `rule_engine.py` | medium | block | Key present and well-formed but value does not match |
| 4 | `sqli` | `rule_engine.py` | critical | honeypot | Any SQL/NoSQL injection pattern in body strings or keys |
| 5 | `rate_limit` | `rule_engine.py` | high | block (60s) | >200 requests in 10s window per IP |
| 6 | `endpoint_scan` | `rule_engine.py` | high | deprioritise | >5 distinct paths in 10s per IP |
| 7 | `oversized_payload` | `rule_engine.py` | medium | block | Raw body > 8 192 bytes |
| 8 | `oversized_list` | `rule_engine.py` | medium | block | `sort_large_list.numbers` > 500 items |

> Auth runs first (rules 1–3). Unauthenticated requests are rejected immediately without body inspection — they are always classified by their auth failure, never by attack content. This keeps Phase 6 event classification clean.
>
> IDMS is the sole authentication boundary. The load balancer and backend servers perform no API key validation.

### Injection patterns (regex, case-insensitive)

```
UNION.*SELECT         DROP TABLE            INSERT.*INTO
DELETE.*FROM          OR \d=\d (tautology)  --, #, /*  (comment markers)
EXEC / EXECUTE / xp_  SLEEP() / WAITFOR     $where/$ne/$gt/$lt/$regex/$or/$and/$not
{'\$  (raw MongoDB operator in string)
```

Patterns are checked against **all string values AND all keys** via recursive `_extract_strings()` (depth-capped at 6).

### Sliding-window state

Both `_rate_windows` and `_endpoint_windows` are per-IP `deque` structures in memory. State is cleared by `reset_state_for_ip()` on unblock — `_unblock_ip()` in `idms_proxy.py` calls it automatically, so both the SQLite block record and the in-memory counters are reset together. Phase 3 MitigationController will also call it on timed expiry.

### Phase 2 additions (⬜ planned)

`anomaly_engine.py` will maintain per-IP baselines:

- Rolling mean and standard deviation of **request rate** and **payload size**.
- Anomaly score = Σ(z-score × weight) across dimensions.
- Score ≥ threshold → `DetectionResult(recommended="deprioritise")` or `"block"`.
- Baselines initialised after N=20 observations per IP; warm-up period returns `allow`.

---

## 6. Data Schemas

### 6.1 SQLite — `idms.db`

**`ip_reputation`**

| Column | Type | Notes |
|---|---|---|
| `ip` | TEXT PK | Client IP address |
| `status` | TEXT | `clean` \| `flagged` \| `blocked` |
| `rule_name` | TEXT | Last triggered rule |
| `blocked_at` | REAL | Unix timestamp of block start |
| `unblock_at` | REAL | Unix timestamp of auto-expiry |
| `hit_count` | INTEGER | Cumulative detection count |
| `last_seen` | REAL | Last request timestamp |

**`detection_log`**

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `ts` | REAL | Event timestamp |
| `ip` | TEXT | |
| `path` | TEXT | Request path |
| `rule_name` | TEXT | |
| `severity` | TEXT | low \| medium \| high \| critical |
| `action` | TEXT | allow \| block \| deprioritise \| honeypot |
| `detail` | TEXT | Human-readable description |
| `inspect_ms` | REAL | Rule engine latency |
| `total_ms` | REAL | Total proxy latency |

### 6.2 SQLite — `honeypot.db`

**`captures`**

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `ts` | REAL | Capture timestamp |
| `source_ip` | TEXT | |
| `path` | TEXT | |
| `method` | TEXT | |
| `headers` | TEXT | JSON-serialised headers |
| `payload` | TEXT | Raw request body |
| `payload_size` | INTEGER | Bytes |
| `idms_tag` | TEXT | Value of `X-IDMS-Tag` header |

### 6.3 MongoDB — `loadbalancer` database

**`requests` collection** (written by each server)

```json
{
  "server": "Server-1",
  "task_type": "factorial",
  "processing_time": 0.21,
  "timestamp": 1711612800.0,
  "status": "success",
  "result": "5040"
}
```

**`user_data` collection** (written/read by `db_*` tasks)

```json
{
  "username": "aqwertyzx",
  "email": "user_1234@example.com",
  "age": 34,
  "active": true,
  "created_at": 1711612800.0
}
```

---

## 7. Configuration Reference

### IDMS rule thresholds (`RULE_CONFIG` in `rule_engine.py`)

| Key | Default | Tunable at runtime |
|---|---|---|
| `rate_limit_window_seconds` | 10 | ✅ via `POST /idms/config` |
| `rate_limit_max_requests` | 200 | ✅ |
| `max_payload_bytes` | 8192 | ✅ |
| `max_list_items` | 500 | ✅ |
| `endpoint_scan_window_seconds` | 10 | ✅ |
| `endpoint_scan_max_distinct` | 5 | ✅ |
| `required_header` | `X-API-Key` | ❌ requires restart |
| `valid_api_key` | `0586c419...` | ❌ requires restart |

### Server load thresholds (`server.py`)

| Constant | Value | Effect |
|---|---|---|
| `MAX_CONCURRENT` | 5 | Above this, extra delay applied |
| `OVERLOAD_THRESHOLD` | 8 | Above this, 503 returned |

### IDMS environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LOAD_BALANCER_URL` | `http://loadbalancer:5000` | Upstream target |
| `HONEYPOT_URL` | `http://honeypot:5002` | Honeypot target |
| `API_KEY` | `0586c419...` | Passed to `RULE_CONFIG` |
| `SQLITE_PATH` | `/data/idms.db` | DB file location |

---

## 8. Docker & Deployment

### Build and run

```bash
# Full stack (from repo root)
docker compose up --build

# Tear down (preserves volumes)
docker compose down

# Tear down + wipe SQLite/MongoDB data
docker compose down -v
```

### Service startup order

`database` → `server1-4` → `loadbalancer` → `honeypot` → `idms` → `dashboard` + `client`

> `depends_on` ensures container start order, not Flask readiness. `client.py` handles this with `_wait_for_idms()`, which polls `GET /health` every 2 seconds (up to 60s timeout) before sending any requests. The client restart policy is `"no"` — it is a one-shot test runner, not a persistent service.

### Accessing dashboards and logs

```bash
# IDMS metrics
curl http://localhost:5001/idms/metrics

# Current blocked IPs
curl http://localhost:5001/idms/blocked

# Detection log (last 50 events)
curl "http://localhost:5001/idms/attack_log?limit=50"

# Honeypot captures
curl http://localhost:5002/captures

# Load balancer health
curl http://localhost:5000/health

# Follow IDMS logs in real time
docker logs -f idms
```

### Persistent data locations

| Volume | Mount point | Contents |
|---|---|---|
| `idms_data` | `/data` (idms container) | `idms.db` — IP reputation + detection log |
| `honeypot_data` | `/data` (honeypot container) | `honeypot.db` — captured payloads |

---

## 9. Phase Implementation Plan

### ✅ Phase 1 — Rule-Based Detection Engine

**Files:** `IDMS/idms/rule_engine.py`, `IDMS/idms/idms_proxy.py`, `IDMS/honeypot/honeypot.py`

Five stateless detection rules, structured `DetectionResult` dataclass, SQLite persistence, in-memory metrics ring, runtime-configurable thresholds, honeypot redirect. `client.py` runs auth validation then a 3-algorithm comparison (round robin → source hashing → least loaded), each with 150 mixed-workload requests.

**Verified and running.** First successful end-to-end run completed. Observed baseline metrics:

| Algorithm | Success rate | Avg response | Notes |
|---|---|---|---|
| Round robin | 100% | 0.37s | Even distribution, no server overwhelmed |
| Source hashing | ~67% | 1.54s | Hash concentration overloads individual servers under mixed workloads — valid research finding |
| Least loaded | 100% | 0.58s | 100% but ~0.2s slower than RR due to `/load` query overhead per request |

**Post-implementation fixes applied to reach first clean run:**

| Issue | Fix |
|---|---|
| `docker-compose.yml` contained Dockerfile content | Rewritten from scratch |
| Both IDMS Dockerfiles had markdown garbage after `CMD` | Stripped |
| Both IDMS `requirements.txt` files were empty | Added `flask==3.0.3`, `requests==2.32.3` |
| `loadbalancer.py` had dead `forward_request()` function and unused `import os` | Removed both |
| `loadbalancer.py` `is_server_healthy()` except block had silent `None` return | Added explicit `return False` |
| `client.py` restart policy `on-failure` caused blocking loop | Changed to `"no"` |
| `{"age": {"$gt": 30}}` in `generate_db_task()` matched `$gt` injection pattern | Replaced with `{"active": False}` |
| `rate_limit_max_requests: 30` blocked legitimate client at 20 req/s | Raised to `200` |
| `_check_headers()` used case-sensitive dict lookup; HTTP stack normalises header case | Changed to case-insensitive `next()` scan |
| `_unblock_ip()` cleared SQLite block but not in-memory rate counters | Added `reset_state_for_ip(ip)` call |
| Client had no IDMS readiness wait | Added `_wait_for_idms()` with 2s polling |
| Auth test expected 401 for missing-key case | Fixed to expect 403 (IDMS intercepts before LB) |

---

### ⬜ Phase 2 — Anomaly Engine

**File to create:** `IDMS/idms/anomaly_engine.py`

**Integration point:** `idms_proxy.py` line 11 comment placeholder.

Responsibilities:
- Per-IP sliding-window baseline: mean and stddev of request rate and payload size.
- Z-score calculation per dimension.
- Weighted anomaly score → `DetectionResult`.
- Warm-up period (first 20 observations): always returns `allow`.
- Callable as `anomaly_engine.score(client_ip, payload_size, ts) → DetectionResult`.

---

### ⬜ Phase 3 — MitigationController

**File to create:** `IDMS/idms/mitigation_controller.py`

**Integration point:** `idms_proxy.py` line 12 comment placeholder.

Responsibilities:
- Accept rule verdict + anomaly verdict, return final action.
- Precedence: critical rule result overrides anomaly; combined score escalates severity.
- Timed IP release: schedule `reset_state_for_ip()` call when block expires.
- Configurable escalation ladder: `allow → deprioritise → block` based on score thresholds.

---

### ⬜ Phase 4 — Attack Simulation Client

**File to create:** `Client/attack_client.py`

Attack modes:
| Mode | Description | Config params |
|---|---|---|
| `flood` | High-rate burst (>30 req/10s) | `--rate`, `--duration` |
| `slow_rate` | Low-rate evasion (just under threshold) | `--rate` |
| `sqli` | Payloads with SQL/NoSQL injection strings | `--intensity` |
| `mixed` | Interleaved legitimate + malicious | `--malicious_ratio` |

Output: timestamped CSV of requests sent, responses received, status codes.

---

### ✅ Phase 5 — Dashboard

**Files:** `dashboard/server.py`, `dashboard/templates/index.html`

Flask backend running on port 8080. Queries IDMS and backend servers from within the Docker network; exposes a clean `/api/*` surface to the browser to avoid CORS issues and keep IDMS internals private.

**Panels:**

| Panel | Data source | Refresh |
|---|---|---|
| Status bar (IDMS / LB / server count) | `GET /api/overview` | 2s |
| Algorithm selector | `POST /api/algorithm` → IDMS `/set_algorithm` | on change |
| Traffic counters (allow / block / honeypot / deprioritise) with % | `GET /api/overview` | 2s |
| Requests/sec line chart (60s rolling, zero-filled) | `GET /api/overview` | 2s |
| Server total requests bar chart (server1–4) | `GET /api/overview` → `server_N:5000/load` | 2s |
| Recent events table (last 20, outcome-tagged) | `GET /api/events` | 2s |
| Blocked IPs table with countdown + unblock button | `GET /api/blocked` | 5s |
| Inspection latency line chart (last 100 events) | `GET /api/overview` | 2s |
| Active IP rate badges (highlight near threshold) | `GET /api/overview` | 2s |

**Dashboard API (`dashboard:8080`)**

| Endpoint | Method | Proxies to |
|---|---|---|
| `/api/overview` | GET | IDMS `/health`, `/idms/metrics`, each server `/load` |
| `/api/events?n=N` | GET | IDMS `/idms/metrics` |
| `/api/blocked` | GET | IDMS `/idms/blocked` |
| `/api/algorithm` | POST | IDMS `/set_algorithm` |
| `/api/unblock/<ip>` | POST | IDMS `/idms/unblock/<ip>` |
| `/api/config` | GET / POST | IDMS `/idms/config` |

Access at `http://localhost:8080`.

---

### ⬜ Phase 6 — Experimental Evaluation

Four scenarios, each run for a fixed duration with fixed request rate:

| Scenario | IDMS | Attack | Measures |
|---|---|---|---|
| S1 — Baseline | ❌ | ❌ | Clean performance ceiling |
| S2 — Unprotected attack | ❌ | ✅ | Attack impact on throughput |
| S3 — Rule-only protection | Rule engine only | ✅ | Rule effectiveness + overhead |
| S4 — Full two-stage | Rule + anomaly | ✅ | Combined effectiveness + overhead |

**Metrics collected per scenario:**
- Average response time (ms)
- Throughput (requests/second)
- Success rate (%)
- False positive rate (legitimate requests blocked/deprioritised, %)
- Inspection latency overhead (ms added by IDMS, S3/S4 vs S1)
- Detection rate (% of attack requests caught)

---

## 10. Metrics & Measurement

### Inspection latency

`DetectionResult.inspection_ms` = `time.perf_counter()` delta inside `rule_engine.inspect()`.
`total_ms` = full proxy time from request receipt to upstream response.
Both logged to `detection_log` and the in-memory ring.

### Load balancer performance

Measured end-to-end in `client.py` as `time.time()` delta around `requests.post()`.
Broken down by server, task type, and algorithm in `PerformanceMetrics.print_summary()`.

### False positive identification

In Phase 6, S3/S4 runs use the legitimate `client.py` workload only (no `attack_client.py`).
Any `block` or `deprioritise` outcome recorded in `detection_log` during those runs counts as a false positive.

> **Rate threshold calibration:** `rate_limit_max_requests` is set to 200 (20 req/s × 10s window), matching the legitimate client's peak send rate. The Phase 4 attack client must target >200 req/10s to trigger the rate limit. This boundary should be documented explicitly when reporting S3/S4 false positive rates.
