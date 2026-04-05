# Project Overview — Traffic Inspection & Threat Mitigation in Load-Balanced Distributed Systems

---

## What this project is

Modern web applications distribute traffic across many servers to handle load. A **load balancer** sits in front of those servers and decides which one should handle each incoming request. This is standard practice — but it creates a gap: the load balancer is focused purely on *where* to send traffic, not *whether* it should be sent at all.

This project builds and studies a system that closes that gap. We add an **Intrusion Detection and Mitigation System (IDMS)** that intercepts every request *before* it reaches the load balancer, inspects it for threats, and decides whether to allow, slow down, capture, or block it — all without disrupting legitimate users.

The central research question is:

> **How much does integrated traffic inspection cost in terms of system performance, and how much security does it provide in return?**

The answer has real implications for any organisation running distributed backend infrastructure.

---

## Why this matters

When a web service is attacked, the attack usually arrives in the same channel as legitimate traffic — the same HTTP port, the same API endpoint, the same JSON format. A standard load balancer cannot tell the difference. The result:

- A **flood attack** saturates backend servers with junk requests, making the service slow or unavailable for real users.
- An **injection attack** sends carefully crafted data designed to manipulate the database — stealing records, corrupting data, or bypassing authentication.
- A **scanning attack** probes many different URLs looking for unprotected endpoints.

These are not hypothetical — they are among the most common attacks against web services today.

The challenge is that adding a security layer *inline* (in the request path) adds latency. Every millisecond of inspection overhead reduces throughput. This project measures that tradeoff precisely, across four controlled experimental scenarios.

---

## How the system works

Think of the system as a series of checkpoints:

```
User request
    │
    ▼
┌─────────────────────────────────────┐
│  IDMS (Intrusion Detection &        │  ◀── This is what we built
│  Mitigation System)                 │
│                                     │
│  "Is this request safe?"            │
│   ├─ Rule check (instant patterns)  │
│   └─ Anomaly check (learned norms)  │
└────────────┬──────────┬─────────────┘
             │          │
          SAFE       SUSPICIOUS
             │          │
             ▼          ├─▶ Block (return 403 error)
    Load Balancer        ├─▶ Honeypot (fake success, log payload)
    (where to send?)     └─▶ Deprioritise (let through, flag it)
             │
    ┌────────┴────────┐
    ▼        ▼        ▼
 Server1  Server2  Server3/4
    │
    ▼
  Result returned to user
```

### The IDMS has two detection layers

**Layer 1 — Rule engine (Phase 1)**

The rule engine checks every request against a fixed set of known-bad patterns in strict priority order. It is fast (sub-millisecond) and short-circuits on the first match — an unauthenticated request is blocked before SQL injection or rate-limit checks even run:

1. **API key validation** — Missing, malformed (under 8 chars or injection characters), or incorrect keys are blocked immediately.
2. **SQL / NoSQL injection** — Patterns like `UNION SELECT`, `DROP TABLE`, `OR 1=1`, MongoDB operators (`$where`, `$ne`) scanned across all JSON keys and values. Redirected to honeypot instead of blocked.
3. **Rate limiting** — More than 200 requests in 10 seconds from one IP triggers a block. Decision made inside the lock to prevent race-condition false positives at the threshold boundary.
4. **Endpoint scan** — More than 5 distinct paths in 10 seconds from one IP (reconnaissance pattern) → deprioritise.
5. **Payload size** — Requests over 8 KB, or sort_large_list with over 500 items → block.

**Layer 2 — Anomaly engine (Phase 2)**

Only runs on requests that passed all rule checks. Builds a per-IP sliding-window baseline (last 30 seconds) of inter-arrival times (IAT). After 150 warmup samples, each new request is scored using a **modified Z-score** (Iglewicz & Hoaglin 1993):

```
Z = 0.6745 × |x − median(baseline)| / MAD(baseline)
```

Detection is **directional** — only requests arriving *faster* than the baseline are flagged (burst attacks accelerate rate; pauses are not attacks). Threshold: Z > 1.5. Combined score is IAT-only (payload weight = 0%) because task types have naturally different payload sizes that cannot be baselined per-IP without per-task-type state.

### What happens to flagged traffic

| Verdict | What happens | Why |
|---|---|---|
| **Block** | 403 error returned immediately | Rate floods, missing auth, oversized payloads — clear attacks |
| **Honeypot** | Silently redirected to a fake server that logs everything | Injection attacks — capture the payload without alerting the attacker |
| **Deprioritise** | Forwarded with `X-IDMS-Tag: deprioritised`; repeated strikes escalate to block | Suspicious but not conclusive — monitor for recurrence |
| **Allow** | Forwarded to load balancer unchanged | Clean request |

Escalation: 8 deprioritise strikes within 120 seconds from the same IP → auto-block for 30 seconds.

### The honeypot

The honeypot is a deliberately fake server. When the IDMS detects injection code, instead of blocking (which would alert the attacker), it forwards the request to the honeypot. The honeypot returns a randomised realistic-looking success response (random server name, realistic processing time) and logs the full payload for forensic analysis. The attacker believes they succeeded.

### The load balancer

Once a request is cleared by the IDMS, the load balancer decides which of the four backend servers handles it. Three algorithms are available and can be switched at runtime via the dashboard:

- **Round Robin** — distributes requests evenly in rotation. Thread-safe iterator, background health-checker (5s interval), exponential backoff for failed servers.
- **Source Hashing** — routes similar requests to the same server (task type + parameters + time bucket). Optimised hash using first 8 hex chars of MD5. Falls back to ring-order on server failure.
- **Least Loaded** — always picks the server with the fewest active requests, with random jitter for tie-breaking. Load data fetched via `/load` endpoints.

All algorithms use a background health-checking thread (runs every 5 seconds) rather than making HTTP calls per request — a significant performance improvement over the original design.

### Backend servers

Four identical servers execute the actual work: arithmetic operations, string processing, factorial calculations, sorting, and MongoDB database operations. Each server tracks how many requests it is currently handling using a thread-safe counter with a **try/finally** guarantee — the counter always decrements even if a request crashes mid-processing. When overloaded beyond a threshold, a server returns 503 and the load balancer stops sending traffic to it temporarily.

---

## The dashboard

The dashboard is a multi-page interactive UI at `http://localhost:8080`:

| Page | URL | Content |
|---|---|---|
| **1 — Load Balancer** | `/loadbalancer` | Animated request simulation, algorithm cards with improvement details, before/after optimisation table |
| **2 — Rule Engine** | `/rules` | Pipeline position diagram, 6 rule cards with priority order, request trace visualisation, live test buttons |
| **3 — Anomaly Engine** | `/anomaly` | Modified Z-score formula, IAT distribution visualisation, baseline status indicator, burst demo button |
| **4 — Mitigation Controller** | `/mitigation` | Decision tree, escalation strike simulator, persistence details, block duration table |
| **5 — Live Demo** | `/` | Full live dashboard with real-time counters, request rate chart, server distribution chart, detection and allowed traffic tables, all demo buttons |

All pages share a persistent navigation bar. The Live Demo page auto-refreshes every 2 seconds.

---

## The four experiments

The project culminates in a controlled experimental evaluation comparing four scenarios:

| Scenario | IDMS active? | Under attack? | What it shows |
|---|---|---|---|
| **S1 — Baseline** | No | No | Maximum possible performance with no security overhead |
| **S2 — Unprotected attack** | No | Yes | How badly an attack degrades service without any protection |
| **S3 — Rule-only protection** | Rule engine only | Yes | Effectiveness and cost of pattern-matching security |
| **S4 — Full two-stage protection** | Rule + anomaly | Yes | Combined effectiveness — the complete system |

Each scenario measures: average response time, throughput, success rate, inspection latency overhead, false positive rate, detection rate.

---

## Project structure

```
Load-Balancer/
│
├── Client/                    Test client & attack simulation
│   ├── client.py              Load generator — sends mixed workloads through the system
│   ├── attack_client.py       Attack simulator — flood, sqli, slow_rate, mixed, stress modes; CSV output
│   └── performance_metrics.py Response time tracking
│
├── Server/
│   ├── LoadBalancer/
│   │   └── loadbalancer.py    Traffic router — 3 algorithms, background health checks, thread-safe
│   └── Server1-4/
│       └── server.py          Backend worker (identical on all 4), try/finally load counter
│
├── IDMS/
│   ├── idms/
│   │   ├── rule_engine.py           Phase 1: pattern-matching, 6 rules, race-condition-safe locks
│   │   ├── anomaly_engine.py        Phase 2: IAT modified Z-score, per-IP baseline, TTL pruning
│   │   ├── mitigation_controller.py Phase 3: full pipeline, escalation, SQLite WAL, persistent conn
│   │   └── idms_proxy.py            Thin HTTP shell — parses requests, delegates to controller
│   └── honeypot/
│       └── honeypot.py        Captures injection payloads, returns randomised fake success
│
├── dashboard/
│   ├── server.py              Flask backend — auto-baseline thread, demo scenarios, API routes
│   └── templates/
│       ├── base.html          Shared nav bar + CSS variables
│       ├── loadbalancer.html  Page 1 — LB simulation + algorithm details
│       ├── rules.html         Page 2 — Rule engine with live test buttons
│       ├── anomaly.html       Page 3 — Anomaly engine with Z-score visualisation
│       ├── mitigation.html    Page 4 — Mitigation pipeline + escalation simulator
│       └── index.html         Page 5 — Live demo dashboard (charts, tables, demo buttons)
│
├── docs/
│   ├── OVERVIEW.md            This document
│   ├── TECHNICAL.md           API reference, schemas, deployment guide
│   └── demo script            Step-by-step professor demo walkthrough
│
└── docker-compose.yml         8 services, health checks, ordered startup, MongoDB persistence
```

---

## Phase roadmap

| Phase | What | Status |
|---|---|---|
| 1 | Rule-based detection (6 rules), IDMS proxy, honeypot | ✅ Complete |
| 2 | Anomaly engine — per-IP IAT modified Z-score, directional scoring, TTL pruning | ✅ Complete |
| 3 | MitigationController — full pipeline, escalation, SQLite WAL, persistent connection | ✅ Complete |
| 4 | Attack simulation client — flood, SQLi, slow-rate, mixed, stress modes, CSV output | ✅ Complete |
| 5 | Multi-page dashboard — per-component pages, animations, live demo controls | ✅ Complete |
| 6 | Four-scenario experimental evaluation (S1–S4) | ⬜ Planned |

---

## Technology choices

| Component | Technology | Why |
|---|---|---|
| All services | Python / Flask | Consistent language across the stack; fast iteration |
| Service isolation | Docker Compose | Reproducible environment; clean network isolation; health-checked startup |
| IDMS state | SQLite (WAL mode) | Zero-dependency persistent storage; sub-millisecond reads; WAL for concurrent access |
| App data | MongoDB | Realistic DB workload; demonstrates NoSQL injection scenarios |
| Dashboard | Chart.js + Jinja2 | Lightweight, no build step; templated multi-page layout |
| Detection algorithms | Regex + modified Z-score | Regex for known patterns (low latency); Z-score for novel anomalies |

---

## Key design decisions

**Why an inline proxy rather than a sidecar or network tap?**
An inline proxy is the most realistic deployment model for applications that cannot modify their network infrastructure. It also allows active mitigation (blocking, redirecting) rather than just passive alerting.

**Why honeypot instead of block for injection attacks?**
Blocking tells the attacker that their probe was detected. A honeypot returns a convincing success response, encouraging the attacker to send more payloads — all captured for analysis. The honeypot response is now randomised (server name, processing time, load) to prevent fingerprinting.

**Why four separate backend servers?**
Four servers are the minimum needed to observe meaningful differences between load balancing algorithms. With fewer servers, round-robin and least-loaded are nearly indistinguishable.

**Why SQLite for the IDMS rather than MongoDB?**
The IDMS needs to make decisions in milliseconds. SQLite with WAL mode and a local file path has sub-millisecond read latency. A networked MongoDB query would add network round-trip time to every request decision — unacceptable for an inline security component.

**Why is the anomaly engine IAT-only?**
Payload size Z-score is computed and logged (for Phase 6 analysis) but weighted at 0% for the verdict. Task types have inherently different payload sizes (factorial vs sort_large_list), creating a multimodal distribution that cannot be baselined per-IP without per-task-type state. IAT captures burst attacks reliably without false positives.

**Why lower the rate limit for the anomaly baseline?**
The baseline thread sends ~10 req/s (100ms interval) rather than the original 20 req/s. At 20 req/s, the baseline IP's rate window fills to ~200 req/10s — the rate limit threshold. When burst adds 50 more requests, the rate limiter fires first, preventing the anomaly engine from ever scoring the burst. At 10 req/s, the window has ~100 requests, leaving headroom for the 50-request burst to be scored by the anomaly engine as intended.
