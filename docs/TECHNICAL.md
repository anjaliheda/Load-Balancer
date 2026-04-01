# Technical Reference — Traffic Inspection & Threat Mitigation in Load-Balanced Distributed Systems

> **Status legend:** ✅ Implemented · 🔄 In progress · ⬜ Planned

> **Phase 3 status:** `mitigation_controller.py` is implemented. The proxy is now a thin HTTP shell — all detection and mitigation logic lives in the controller. See [§9](#9-phase-implementation-plan) for details.

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
    - [10.3 Testing Phase 2 — Anomaly Engine](#103-testing-phase-2-anomaly-engine)

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
│  ┌──────────────┐ │  anomaly_    │    ┌─────────┼─────────┐          │
│  │ dashboard    │ │  engine      │    ▼         ▼         ▼          │
│  │ :8080        │ │  mitigation_ │ server1  server2  server3/4       │
│  │ (reads IDMS  │ │  controller  │  :5000    :5000    :5000           │
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
- **Separation of detection and mitigation**: detection engines (`rule_engine.py`, `anomaly_engine.py`) return structured `DetectionResult` verdicts; `MitigationController` acts on them. `idms_proxy.py` is a thin HTTP shell — it parses requests and delegates entirely to the controller. No policy logic lives in the proxy.
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
        └─ MitigationController.process()
              ├─ [0] IP block check        (SQLite — short-circuit, no detection run)
              ├─ [1] rule_engine.inspect() (5 rules, auth-first)
              │     ├─ _check_headers()    ← auth boundary (highest priority)
              │     ├─ _check_sqli()
              │     ├─ _check_rate_limit()
              │     ├─ _check_endpoint_scan()
              │     └─ _check_payload_size()
              ├─ [2] anomaly_engine.score() (only when [1] returns clean)
              └─ [3] act on verdict
                    ├─ block        → _block_ip(), 403
                    ├─ honeypot     → POST honeypot:5002/request
                    ├─ deprioritise → check escalation → POST loadbalancer + X-IDMS-Tag
                    └─ allow        → POST loadbalancer:5000/request
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
      "outcome": "deprioritise",
      "ip": "172.18.0.5",
      "rule_name": "anomaly",
      "severity": "medium",
      "inspect_ms": 0.42,
      "total_ms": 1.1,
      "path": "/request"
    }
  ],
  "rates": { "172.18.0.5": 31 },
  "anomaly": {
    "172.18.0.5": { "samples": 18, "warmed_up": true },
    "172.18.0.6": { "samples": 4,  "warmed_up": false }
  }
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
Returns `RULE_CONFIG`, `ANOMALY_CONFIG`, and `MITIGATION_CONFIG`:

```json
{
  "rules":      { "rate_limit_window_seconds": 10, "rate_limit_max_requests": 200, "..." : "..." },
  "anomaly":    { "window_seconds": 30, "min_baseline_samples": 50, "zscore_threshold": 5.0, "..." : "..." },
  "mitigation": { "block_duration_medium": 60, "escalation_strikes": 20, "..." : "..." }
}
```

#### `POST /idms/config`
Runtime threshold update (no restart). Whitelisted keys:

**Rule keys:** `rate_limit_window_seconds`, `rate_limit_max_requests`, `max_payload_bytes`,
`max_list_items`, `endpoint_scan_window_seconds`, `endpoint_scan_max_distinct`

**Anomaly keys:** `window_seconds`, `min_baseline_samples`, `zscore_threshold`,
`zscore_high_multiplier`, `payload_zscore_weight`, `iat_zscore_weight`

**Mitigation keys:** `block_duration_medium`, `block_duration_high`, `block_duration_critical`,
`escalation_strikes`, `escalation_window_seconds`, `escalation_block_duration`

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
| 9 | `anomaly` | `anomaly_engine.py` | medium/high | deprioritise → escalate to block | IAT Z-score exceeds 5.0 (after 50-request warm-up). 20 deprioritise strikes in 120s auto-escalates to a 120s block. |

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

Both `_rate_windows` and `_endpoint_windows` are per-IP `deque` structures in memory. State is cleared by `reset_state_for_ip()` on unblock — `_unblock_ip()` in `MitigationController` calls both `rule_reset(ip)` and `anomaly_reset(ip)` and also clears the escalation strike window (`_strike_windows.pop(ip)`), so the SQLite block record, in-memory rate counters, anomaly baseline, and strike history are all reset atomically.

### Phase 2 — Anomaly Engine (`anomaly_engine.py`) ✅

`anomaly_engine.py` maintains per-IP sliding-window baselines over two dimensions:

| Dimension | Window | Weight | What it catches |
|---|---|---|---|
| `payload_bytes` | 30s | 0.0 (disabled) | Computed and logged for research, but excluded from scoring. Legitimate workloads use task types with inherently different payload sizes (a multimodal distribution that cannot be baselined per-IP without per-task-type state). The rule engine's 8 KB hard cap already handles the extreme case. |
| `inter_arrival_s` | 30s | 1.0 | Burst onset after slow warm-up — slow-rate attacker accelerating past the statistical baseline. |

**Algorithm:** Modified Z-score (`0.6745 × |x − median| / MAD`) — more robust than mean/stddev for the small, skewed samples typical of short traffic windows (Iglewicz & Hoaglin, 1993).

**Warm-up:** First 10 requests per IP always pass. No baseline exists until there is enough history to score against.

**Score escalation:**
- Combined score > 5.0 → `severity="medium"`, `recommended="deprioritise"`
- Combined score > 7.5 (5.0 × 1.5) → `severity="high"`, `recommended="deprioritise"`

**Warm-up calibration:** `min_baseline_samples` is set to 50 (not the statistical minimum of 10) so the baseline is established from steady-state burst traffic rather than the slow startup requests that precede the main workload. This prevents false positives on the startup-to-burst transition while preserving sensitivity to mid-session behavioural changes.

**`inspection_ms`:** timed with `time.perf_counter()` inside `score()` and set on every returned `DetectionResult`. Observed range on legitimate traffic: 0.17ms–1.9ms.

**Calling convention:** `anomaly_engine.score(client_ip, payload_bytes, ts)` — returns `DetectionResult`. Called by `idms_proxy.py` only when rule engine returns clean (layers are independent for Phase 6 attribution).

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

### Anomaly engine thresholds (`ANOMALY_CONFIG` in `anomaly_engine.py`)

| Key | Default | Tunable at runtime | Notes |
|---|---|---|---|
| `window_seconds` | 30 | ✅ via `POST /idms/config` | Sliding window for baseline |
| `min_baseline_samples` | 50 | ✅ | Warm-up requests before scoring starts; 50 ensures baseline reflects steady-state burst traffic, not slow startup requests |
| `zscore_threshold` | 5.0 | ✅ | IAT Z-score cutoff (effective, since payload weight=0). At baseline IAT 50ms with MAD 2ms, fires when current IAT < ~36ms. |
| `zscore_high_multiplier` | 1.5 | ✅ | Multiplied with threshold to escalate to "high" severity (effective cutoff: 7.5) |
| `payload_zscore_weight` | 0.0 | ✅ | Disabled — multimodal task payloads cause false positives. Value still computed and logged. |
| `iat_zscore_weight` | 1.0 | ✅ | IAT-only detection: burst attacks always accelerate request rate |

### Mitigation controller thresholds (`MITIGATION_CONFIG` in `mitigation_controller.py`)

| Key | Default | Tunable at runtime | Notes |
|---|---|---|---|
| `block_duration_medium` | 60s | ✅ via `POST /idms/config` | Block duration for medium-severity rules |
| `block_duration_high` | 300s | ✅ | Block duration for high-severity rules (e.g. rate_limit, endpoint_scan) |
| `block_duration_critical` | 900s | ✅ | Block duration for critical-severity rules (e.g. sqli — though sqli goes to honeypot) |
| `escalation_strikes` | 20 | ✅ | Deprioritise events within the window before auto-block |
| `escalation_window_seconds` | 120s | ✅ | Sliding window for counting deprioritise strikes |
| `escalation_block_duration` | 120s | ✅ | Duration of escalation-triggered block |

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
| `SQLITE_PATH` | `/data/idms.db` | DB file location |

> `API_KEY` is no longer an environment variable. The valid key is stored in `RULE_CONFIG["valid_api_key"]` in `rule_engine.py`. IDMS is the sole auth boundary — LB and servers perform no key validation.

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

**Linux / macOS (bash):**
```bash
curl http://localhost:5001/idms/metrics
curl http://localhost:5001/idms/blocked
curl "http://localhost:5001/idms/attack_log?limit=50"
curl http://localhost:5002/captures
curl http://localhost:5000/health
docker logs -f idms
```

**Windows PowerShell** — use `Invoke-RestMethod`, not `curl` (which is an alias for `Invoke-WebRequest` and returns an object, not raw text):
```powershell
Invoke-RestMethod "http://localhost:5001/idms/metrics?n=10"
Invoke-RestMethod "http://localhost:5001/idms/blocked"
Invoke-RestMethod "http://localhost:5001/idms/attack_log?limit=20"
Invoke-RestMethod "http://localhost:5002/captures"
Invoke-RestMethod "http://localhost:5000/health"
Invoke-RestMethod "http://localhost:5001/health"
Invoke-RestMethod "http://localhost:8080/api/overview"
docker logs -f idms
```

`Invoke-RestMethod` automatically parses JSON and prints it as a formatted PowerShell object. To get raw JSON instead:
```powershell
(Invoke-WebRequest -UseBasicParsing "http://localhost:5001/idms/metrics?n=10").Content | python -m json.tool
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

### ✅ Phase 2 — Anomaly Engine

**File:** `IDMS/idms/anomaly_engine.py`

Per-IP statistical baseline detection using modified Z-score (median + MAD) over two sliding-window dimensions: payload size and inter-arrival time. Independent from Phase 1 rule engine — only runs when rule engine returns clean, so Phase 6 metrics can attribute each detection event to exactly one layer.

**Integration changes to `idms_proxy.py`:**
- Step `2b` calls `anomaly_score()` immediately after `rule_inspect()` when the latter returns clean.
- `_unblock_ip()` now calls `anomaly_reset()` alongside `reset_state_for_ip()` to discard stale baselines on block expiry.
- `/idms/metrics` includes `"anomaly"` snapshot (per-IP sample counts + warm-up status).
- `/idms/config` exposes and accepts both `RULE_CONFIG` and `ANOMALY_CONFIG` keys.

**Key design decisions:**

*Directional IAT scoring:* IAT scoring is one-sided — only flags when `current_iat < median(baseline)` (request arrived faster than normal). A longer-than-usual gap scores `iat_z = 0`. Without this, the client's 3–5s sleeps between algorithm runs triggered ~11% FPR because a 3s gap against a 50ms baseline produces a very high Z-score.

*Payload scoring disabled:* The client sends task types with inherently different payload sizes (`sort_large_list` with 100 integers is ~700 bytes; `addition` is ~60 bytes). Every `sort_large_list` request scored above the threshold against the mixed-task baseline, causing ~9% of legitimate requests to be flagged — and enough strikes to trigger escalation, blocking the client mid-run. Payload anomaly detection would require per-task-type baselines (not implemented). The rule engine's 8 KB hard cap covers the extreme case. Payload Z-score is still computed and available in event logs for research but `payload_zscore_weight = 0.0`.

**Observed results:** `deprioritise` ≤ 1 and `block` = 2 (auth tests only) for the full legitimate client workload across all three algorithm phases. Phase 6 false positive baseline is clean.

See [§10.3](#103-testing-phase-2-anomaly-engine) for standalone and integration test commands.

---

### ✅ Phase 3 — MitigationController

**File:** `IDMS/idms/mitigation_controller.py`

**Architecture change:** `idms_proxy.py` is now a thin HTTP shell. All detection and mitigation logic moved into `MitigationController.process()`, which is the single entry point called per request.

**`process()` pipeline:**
1. IP block check (SQLite) — returns 403 immediately for blocked IPs, skipping detection entirely
2. `rule_engine.inspect()` — 5 rules, auth-first
3. `anomaly_engine.score()` — only when rule engine returns clean (layers stay independent)
4. `_act()` — executes verdict

**Verdict execution:**

| Recommended | Action |
|---|---|
| `block` | `_block_ip()` with severity-based duration (medium=60s, high=300s, critical=900s) + 403 |
| `honeypot` | Forward to `honeypot:5002` with `X-IDMS-Tag: honeypot` |
| `deprioritise` | Record strike → if threshold crossed, escalate to block; otherwise forward with `X-IDMS-Tag: deprioritised` |
| `allow` | Forward to load balancer unchanged |

**Escalation logic:**
Per-IP sliding-window strike counter (`_strike_windows`). 20 deprioritise events within 120 seconds triggers a 120-second block. This catches slow-rate attackers that stay under the hard rate limit but generate repeated anomaly flags. On unblock, `_unblock_ip()` clears SQLite record, rule engine counters, anomaly baseline, and strike window atomically.

**Verified results (full legitimate client run):**
- `allow` = 450, `block` = 2 (auth tests only), `deprioritise` ≤ 1
- All three algorithm phases complete — round robin 100%, source hash ~68% (hash concentration, not IDMS), least loaded 100%

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

---

## 10.3 Testing Phase 2 — Anomaly Engine

### Option A — Standalone unit test (no Docker required)

Run directly from the `IDMS/idms/` directory. Tests warm-up suppression, payload spike, and IAT burst (directional — pause must NOT trigger, burst must).

```bash
cd IDMS/idms
pip install flask==3.0.3 requests==2.32.3   # only needed once

python3 - <<'EOF'
import time
from anomaly_engine import score, reset_state_for_ip, ANOMALY_CONFIG

# Lower warm-up threshold for quick local test
ANOMALY_CONFIG["min_baseline_samples"] = 10

IP = "192.168.1.1"
BASE_TS = time.time()

print("=== Warm-up phase (should all be CLEAN) ===")
for i in range(10):
    r = score(IP, 500, ts=BASE_TS + i * 0.5)
    print(f"  [{i+1:2d}] flagged={r.flagged}  detail={r.detail}")

print("\n=== Payload spike (7 KB vs 500 B baseline) — payload_z computed but weight=0, should NOT flag ===")
r = score(IP, 7000, ts=BASE_TS + 5.5)
print(f"  flagged={r.flagged}  (expected False — payload_zscore_weight=0.0)")

print("\n=== Pause (5s gap) — must NOT trigger (directional IAT) ===")
r = score(IP, 500, ts=BASE_TS + 10.5)   # 5s after last request
print(f"  flagged={r.flagged}  (expected False)")

print("\n=== IAT burst (10ms gaps vs 500ms baseline) ===")
reset_state_for_ip(IP)
for i in range(12):                          # rebuild baseline at 500ms intervals
    score(IP, 500, ts=BASE_TS + i * 0.5)
for i in range(5):                           # sudden burst at 10ms intervals
    r = score(IP, 510, ts=BASE_TS + 6 + i * 0.01)
    print(f"  [burst {i+1}] flagged={r.flagged}  rule={r.rule_name}  detail={r.detail}")
EOF
```

**Expected output:**
- Warm-up (requests 1–10): all `flagged=False`
- Payload spike: `flagged=False` — payload scoring is disabled (`payload_zscore_weight=0.0`)
- Pause test: `flagged=False` — pause is not an attack (directional IAT scoring)
- Burst: `flagged=True` on requests 3–5 once baseline is established (IAT scoring only)

---

### Option B — Integration test against live Docker stack (PowerShell)

> All `Invoke-RestMethod` commands are verified working on Windows PowerShell. Do not use `curl` — it is an alias for `Invoke-WebRequest` in PowerShell and does not pipe as plain text.

**Step 1 — Start the stack**

```powershell
docker compose down -v      # wipe old SQLite data for a clean run
docker compose up --build
docker logs -f client       # watch client output in a second terminal
```

**Step 2 — Check overall health once client finishes**

```powershell
# Full stack health
Invoke-RestMethod "http://localhost:5001/health"

# Counters + anomaly snapshot + recent events
Invoke-RestMethod "http://localhost:5001/idms/metrics?n=10"

# Should be empty [] if _self_unblock() worked
Invoke-RestMethod "http://localhost:5001/idms/blocked"

# Auth-test detections (missing_api_key, invalid_api_key entries)
Invoke-RestMethod "http://localhost:5001/idms/attack_log?limit=20"

# Dashboard aggregated view
Invoke-RestMethod "http://localhost:8080/api/overview"
```

**Pass criteria:**
| Field | Expected |
|---|---|
| `idms` | `healthy` |
| `healthy_servers` | `4` |
| `counters.allow` | 400+ |
| `counters.block` | 2 (auth test only) |
| `counters.deprioritise` | ≤ 1 (near-zero false positives; payload scoring disabled) |
| `anomaly.<ip>.warmed_up` | `true` (after 50+ requests) |

**Step 3 — Verify anomaly engine catches a real burst**

After the client run, trigger a burst from the host machine. The anomaly engine needs a warmed-up baseline, so run this within 30 seconds of the client finishing (before the window expires):

```powershell
$API_KEY = "0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c"
$headers = @{ "X-API-Key" = $API_KEY; "Content-Type" = "application/json" }
$body    = '{"task_type":"addition","num1":1,"num2":2}'

# Rapid burst — 10 requests with no sleep
1..10 | ForEach-Object {
    Invoke-RestMethod -Method POST -Uri "http://localhost:5001/request" `
        -Headers $headers -Body $body -ContentType "application/json"
}

# Check for anomaly events
Invoke-RestMethod "http://localhost:5001/idms/metrics?n=15"
```

Look for `rule_name = anomaly` and `outcome = deprioritise` in the events list.

---

### Option C — Runtime config tuning (PowerShell)

Lower the threshold for testing without restarting:

```powershell
# Make engine more sensitive
Invoke-RestMethod -Method POST -Uri "http://localhost:5001/idms/config" `
    -ContentType "application/json" `
    -Body '{"zscore_threshold": 3.0}'

# Verify
(Invoke-RestMethod "http://localhost:5001/idms/config").anomaly.zscore_threshold

# Reset to calibrated default
Invoke-RestMethod -Method POST -Uri "http://localhost:5001/idms/config" `
    -ContentType "application/json" `
    -Body '{"zscore_threshold": 5.0}'
```

---

### What a successful Phase 2 test looks like

| Check | Expected |
|---|---|
| Requests 1–50 from a new IP | `flagged=False` in metrics, `warmed_up=false` in anomaly snapshot |
| Request 51+ with normal payload and timing | `flagged=False`, `warmed_up=true` |
| Request with 10× payload spike (after warm-up) | `flagged=False` — payload scoring disabled; rule engine 8 KB cap handles the extreme case |
| Burst after slow baseline (after warm-up) | `rule_name=anomaly` after 2–3 burst requests |
| `inspect_ms` on anomaly events | 0.1ms–2ms range (non-zero; was 0.0 before fix) |
| `/idms/attack_log` | `action=deprioritise`, `rule_name=anomaly` entries present |
| Rule-engine hits (rate limit, sqli, etc.) | `rule_name` is NOT `anomaly` — layers are independent |
| Legitimate client full run (450+ requests, 3 algorithms) | `deprioritise` ≤ 1, `block` = 2 (auth tests only) |
