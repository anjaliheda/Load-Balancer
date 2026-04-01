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
             ▼          ├─▶ Block (return error)
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

**Layer 1 — Rule engine**

The rule engine checks every request against a fixed set of known-bad patterns. It is fast (sub-millisecond) and catches well-known threats immediately:

- *Is the request arriving too fast?* More than 200 requests in 10 seconds from one address triggers a 60-second block. This threshold is calibrated above the legitimate client's peak rate (~20 req/s) so that normal load-test traffic is never blocked, while attack floods (typically 50+ req/s) are caught.
- *Does the payload contain injection code?* Patterns like `UNION SELECT`, `DROP TABLE`, or MongoDB operators like `$where` in unexpected places are flagged.
- *Is the payload abnormally large?* Requests over 8 KB are blocked to prevent memory exhaustion.
- *Is the API key missing or malformed?* Requests without valid credentials are blocked.
- *Is this IP probing many different URLs quickly?* More than 5 distinct paths in 10 seconds suggests reconnaissance.

**Layer 2 — Anomaly engine** ✅

The anomaly engine learns what "normal" looks like for each IP address over time — specifically, how frequently requests arrive. When a request arrives significantly faster than the established baseline (measured using a modified Z-score of inter-arrival times), it is scored as suspicious. This catches attacks designed to stay just under the rule thresholds — such as a slow flood that ramps up gradually. Detection is directional: a client pausing between requests scores zero (not an attack); only acceleration triggers the alarm.

### What happens to flagged traffic

| Verdict | What happens | Why |
|---|---|---|
| **Block** | 403 error returned immediately | Rate floods, missing auth, oversized payloads — clear attacks |
| **Honeypot** | Silently redirected to a fake server that logs everything | Injection attacks — we want to capture the payload, not alert the attacker |
| **Deprioritise** | Forwarded with `X-IDMS-Tag: deprioritised`; repeated strikes escalate to block | Suspicious behaviour that isn't conclusive — forward but mark for monitoring. After 20 such events in 120s from the same IP, auto-block for 120s. |
| **Allow** | Forwarded to load balancer unchanged | Clean request |

### The honeypot

The honeypot is a deliberately fake server. When the IDMS detects injection code in a request, instead of blocking it (which would tell the attacker their probe was detected), it silently forwards the request to the honeypot. The honeypot returns a realistic-looking success response and logs the full payload for analysis. The attacker believes they succeeded.

### The load balancer

Once a request is cleared by the IDMS, the load balancer decides which of the four backend servers should handle it. Three algorithms are available and can be switched at runtime:

- **Round Robin** — distributes requests evenly in rotation. Simple, fair under uniform load.
- **Source Hashing** — routes similar requests to the same server (based on task type + parameters). Useful for cache locality.
- **Least Loaded** — always picks the server with the fewest active requests. Best under variable workload.

### Backend servers

Four identical servers execute the actual work: arithmetic operations, string processing, factorial calculations, sorting, and MongoDB database operations. Each server tracks how many requests it is currently handling and adds artificial delay as load increases — simulating realistic server behaviour under stress. When overloaded beyond a threshold, a server returns a 503 error, and the load balancer stops sending traffic to it temporarily.

---

## The four experiments

The project culminates in a controlled experimental evaluation comparing four scenarios:

| Scenario | IDMS active? | Under attack? | What it shows |
|---|---|---|---|
| **S1 — Baseline** | No | No | Maximum possible performance with no security overhead |
| **S2 — Unprotected attack** | No | Yes | How badly an attack degrades service without any protection |
| **S3 — Rule-only protection** | Rule engine only | Yes | Effectiveness and cost of pattern-matching security |
| **S4 — Full two-stage protection** | Rule + anomaly | Yes | Combined effectiveness — the complete system |

Each scenario measures:
- **Average response time** — how long does a legitimate user wait?
- **Throughput** — how many requests per second does the system handle?
- **Success rate** — what percentage of requests complete successfully?
- **Inspection latency overhead** — how many milliseconds does the IDMS add?
- **False positive rate** — what percentage of *legitimate* requests are wrongly blocked or flagged?
- **Detection rate** — what percentage of *attack* requests are caught?

These measurements quantify the security-performance tradeoff: how much protection do we buy, and what does it cost?

---

## Project structure

```
Load-Balancer/
│
├── Client/                    Test client & metrics collection
│   ├── client.py              Load generator — sends mixed workloads through the system
│   └── performance_metrics.py Response time tracking
│
├── Server/
│   ├── LoadBalancer/
│   │   └── loadbalancer.py    Traffic router with 3 algorithms
│   └── Server1-4/
│       └── server.py          Backend worker (identical on all 4)
│
├── IDMS/
│   ├── idms/
│   │   ├── rule_engine.py          Phase 1: pattern-matching detection
│   │   ├── anomaly_engine.py       Phase 2: IAT statistical baseline detection
│   │   ├── mitigation_controller.py Phase 3: full pipeline — block/honeypot/deprioritise/escalation
│   │   └── idms_proxy.py           Thin HTTP shell — parses requests, delegates to controller
│   └── honeypot/
│       └── honeypot.py        Captures injection payloads, returns fake success
│
├── dashboard/
│   ├── server.py              Flask backend — proxies IDMS/LB data, serves UI
│   └── templates/
│       └── index.html         Single-page dashboard (Chart.js, auto-refresh)
│
├── docs/
│   ├── OVERVIEW.md            This document
│   └── TECHNICAL.md           API reference, schemas, deployment guide
│
└── docker-compose.yml         Runs all 10 containers as one system
```

---

## Phase roadmap

| Phase | What | Status |
|---|---|---|
| 1 | Rule-based detection (5 rules), IDMS proxy, honeypot | ✅ Complete & verified |
| 2 | Anomaly engine — per-IP IAT-based statistical detection (modified Z-score) | ✅ Complete |
| 3 | MitigationController — full pipeline ownership, escalation, severity-based block durations | ✅ Complete |
| 4 | Attack simulation client — flood, SQLi, slow-rate, mixed modes | ⬜ |
| 5 | Real-time dashboard — live traffic charts, algorithm switcher, blocked IP management | ✅ Complete |
| 6 | Four-scenario experimental evaluation | ⬜ |

### Phase 1 observed results

First end-to-end run completed successfully. The client runs a 3-algorithm comparison — 150 mixed-workload requests per algorithm via the IDMS. Key findings:

- **Round robin and least loaded both achieve 100% success** under the mixed workload, with round robin slightly faster (0.37s vs 0.58s) because least loaded pays a per-request overhead querying all four servers for their current load before selecting one.
- **Source hashing achieves only ~67% success.** The mixed task workload creates an uneven hash distribution — many requests with similar `task_type` values hash to the same server, overloading it while others sit idle. This is a legitimate research finding demonstrating when source hashing is the wrong algorithm choice.

---

## Technology choices

| Component | Technology | Why |
|---|---|---|
| All services | Python / Flask | Consistent language across the stack; fast iteration |
| Service isolation | Docker Compose | Reproducible environment; clean network isolation |
| IDMS state | SQLite | Zero-dependency persistent storage; sufficient for single-node experiment |
| App data | MongoDB | Realistic DB workload; demonstrates NoSQL injection scenarios |
| Dashboard | Chart.js | Lightweight, no build step, runs in any browser |
| Detection algorithms | Regex + statistical z-score | Regex for known patterns (low latency); z-score for novel anomalies |

---

## Key design decisions

**Why an inline proxy rather than a sidecar or network tap?**
An inline proxy is the most realistic deployment model for applications that cannot modify their network infrastructure. It also allows active mitigation (blocking, redirecting) rather than just passive alerting.

**Why honeypot instead of block for injection attacks?**
Blocking tells the attacker that their probe was detected. A honeypot returns a convincing success response, encouraging the attacker to send more payloads — all of which are captured for analysis. It also prevents attackers from probing for the exact block threshold.

**Why four separate backend servers?**
Four servers are the minimum needed to observe meaningful differences between load balancing algorithms. With fewer servers, round-robin and least-loaded are nearly indistinguishable.

**Why SQLite for the IDMS rather than the same MongoDB used by the backend?**
The IDMS needs to make decisions in milliseconds. SQLite with WAL mode and a local file path has sub-millisecond read latency. Querying a networked MongoDB instance would add network round-trip time to every request decision — unacceptable for an inline security component.
