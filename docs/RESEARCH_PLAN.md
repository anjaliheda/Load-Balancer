# Research Plan — Making This a Valuable Paper

> **Status:** Phase A in progress  
> **Goal:** Produce measurable S1–S4 results, FPR data, and an evasion finding to support a research paper on two-stage inline traffic inspection in load-balanced systems.

---

## Core Research Claim

> A two-stage inline inspection pipeline (rule-based + statistical anomaly) provides meaningful attack detection with quantifiable overhead, and each stage contributes distinct, non-overlapping detection capability.

**Four things needed to defend this claim:**
1. Latency overhead is measured (inspection cost)
2. Detection rate is measured per stage (rule-only vs rule+anomaly)
3. False positive rate on clean traffic is measured
4. Each stage is shown to catch attacks the other misses (slow-rate evades rules but not anomaly)

---

## Experimental Scenarios

| Scenario | Client target | IDMS config | Attack | Purpose |
|---|---|---|---|---|
| **S1 — Baseline** | LB directly (`port 5000`) | — | None | Clean performance ceiling; no security overhead |
| **S2 — Unprotected attack** | LB directly (`port 5000`) | — | flood + sqli | Shows how badly an unprotected system degrades |
| **S3 — Rule-only** | IDMS (`port 5001`) | zscore_threshold=999 | flood + sqli + slow_rate | Rule engine effectiveness; anomaly disabled |
| **S4 — Full two-stage** | IDMS (`port 5001`) | default config | flood + sqli + slow_rate + ramp | Combined effectiveness; the full system |

**Key finding to look for:** S3 has 0% detection on slow_rate (evasion of rule engine). S4 should catch it via anomaly engine. If it does, that is the headline result. If the ramp mode also evades S4, that is a valid finding (honest limitation).

---

## Metrics to collect per scenario

| Metric | Source | How |
|---|---|---|
| Mean / median response time (ms) | client.py output | `PerformanceMetrics.print_summary()` |
| Throughput (req/s) | client.py output | total requests / duration |
| Success rate (%) | client.py output | successful / total |
| Detection rate (%) | attack_client.py CSV + IDMS attack_log | blocked + honeypot / total attack requests |
| False positive rate (%) | IDMS attack_log during clean runs | block + deprioritise on client.py traffic / total |
| Inspection latency overhead (ms) | IDMS metrics ring | `inspect_ms` mean from `/idms/metrics` — compare S1 vs S4 |

---

## Phase A — Experimental Infrastructure  ✅ In progress

### A1 — `TARGET_URL` env var in `client.py`
**File:** `Client/client.py`  
**Change:** Make request target configurable via `TARGET_URL` env var (default `http://idms:5001`).  
**Why:** S1 and S2 require the client to bypass the IDMS and go directly to the load balancer.  
**Backward compat:** Default unchanged — existing Docker run (`python client.py`) still works.

Run for S1/S2 (direct LB):
```powershell
# From project root, stack running
$env:TARGET_URL="http://localhost:5000"; python Client/client.py
```
Run for S3/S4 (through IDMS, as normal):
```powershell
$env:TARGET_URL="http://localhost:5001"; python Client/client.py
# or just: python Client/client.py  (default)
```

### A2 — `ramp` attack mode in `attack_client.py`
**File:** `Client/attack_client.py`  
**Change:** Add `run_ramp()` function and `ramp` mode choice.  
**What it does:** Sends requests starting at 5 req/s, stepping up by 3 req/s every 25 seconds up to 17 req/s. Never crosses the 200/10s rate limit ceiling (17 × 10 = 170 < 200). Each step: 25s × rate = 125–425 requests.  
**Research question:** Does the anomaly engine catch gradual acceleration, or does its rolling 30s baseline shift with the attacker?  
**Expected result:** Probably partial or no detection — the baseline adapts as the rate ramps. This is an honest finding about the system's limitation and worth a paragraph in the paper.

Run:
```powershell
python Client/attack_client.py --mode ramp --idms-url http://localhost:5001
```

### A3 — `results_analyzer.py`
**File:** `Client/results_analyzer.py`  
**What it does:**
- Reads one or more CSV files produced by `attack_client.py`
- Queries IDMS attack_log for FPR calculation
- Prints paper-ready results tables: scenario comparison, per-attack-type breakdown, latency percentiles

Run:
```powershell
# Analyze a single CSV
python Client/results_analyzer.py results/attack_flood_*.csv

# FPR check — query IDMS log after a clean client.py run
python Client/results_analyzer.py --fpr --idms-url http://localhost:5001

# Full paper table (all modes)
python Client/results_analyzer.py results/attack_all_*.csv --idms-url http://localhost:5001
```

---

## Phase B — Run the Experiments  ⬜ Not started

**Important:** Run each scenario 3× and average. Single runs are not measurements.

### Before each run
```powershell
# Wipe all state for a clean start
Invoke-RestMethod -Method POST "http://localhost:5001/idms/clear_log"
# For S1/S2: also restart the stack to remove any cached state
```

### B1 — S1 (5 min run, direct to LB, no attack)
```powershell
$env:TARGET_URL="http://localhost:5000"; python Client/client.py
```
**Record:** mean latency, throughput, success rate. This is the clean performance ceiling.

### B2 — S2 (direct to LB, under flood attack)
```powershell
# Terminal 1 — legitimate client
$env:TARGET_URL="http://localhost:5000"; python Client/client.py

# Terminal 2 — flood attack (simultaneously)
python Client/attack_client.py --mode flood --idms-url http://localhost:5000
```
**Record:** how much legitimate traffic degrades under an unprotected flood.  
**Expected:** success rate drops, latency spikes — this is the motivating result for the whole paper.

### B3 — S3 (IDMS, rule engine only, anomaly disabled)
```powershell
# Disable anomaly engine
Invoke-RestMethod -Method POST -Uri "http://localhost:5001/idms/config" `
    -ContentType "application/json" -Body '{"zscore_threshold": 999}'

# Terminal 1 — legitimate client through IDMS
python Client/client.py

# Terminal 2 — attack (flood + sqli + slow_rate separately)
python Client/attack_client.py --mode flood --idms-url http://localhost:5001
# then
python Client/attack_client.py --mode slow_rate --idms-url http://localhost:5001
```
**Key result:** slow_rate detection rate = 0% (rule engine cannot catch it). flood detection ~72%.

### B4 — S4 (full IDMS, both layers)
```powershell
# Restore anomaly engine
Invoke-RestMethod -Method POST -Uri "http://localhost:5001/idms/config" `
    -ContentType "application/json" -Body '{"zscore_threshold": 1.5}'

# Terminal 1 — legitimate client
python Client/client.py

# Terminal 2 — attacks
python Client/attack_client.py --mode all --idms-url http://localhost:5001
python Client/attack_client.py --mode ramp --idms-url http://localhost:5001
```
**Key result:** slow_rate IS now caught (anomaly engine detects IAT burst). Ramp may or may not be caught — either outcome is a finding.

### B5 — FPR measurement (clean traffic only, full IDMS)
```powershell
# Restore default config first
Invoke-RestMethod -Method POST -Uri "http://localhost:5001/idms/config" `
    -ContentType "application/json" -Body '{"zscore_threshold": 1.5}'

# Clear log
Invoke-RestMethod -Method POST "http://localhost:5001/idms/clear_log"

# Run legitimate client only (no attack)
python Client/client.py

# After run: query FPR
python Client/results_analyzer.py --fpr --idms-url http://localhost:5001
```
**What to check:** Any `block` or `deprioritise` in the detection log for the client's IP = false positive. Target: <1%.

---

## Phase C — Strengthen the Claims  ⬜ Not started

### C1 — Latency overhead table
From S1 vs S4 data, produce:

| Scenario | Median latency | IDMS overhead | Rule engine share | Anomaly share |
|---|---|---|---|---|
| S1 (no IDMS) | X ms | — | — | — |
| S3 (rule only) | X ms | +Y ms | Y ms | — |
| S4 (full) | X ms | +Z ms | Y ms | Z−Y ms |

Source: `inspect_ms` from `/idms/metrics` endpoint (rule engine time) and `total_ms − inspect_ms` (anomaly + forwarding).

### C2 — Per-attack-type detection table
| Attack | Layer that catches it | Detection rate | Client-visible | Notes |
|---|---|---|---|---|
| Rate flood | Rule (rate_limit) | ~72% ceiling | Yes (403) | First 200 always pass |
| SQL injection | Rule (sqli) | 100% | No (honeypot) | All payloads caught |
| Burst anomaly | Anomaly engine | ~X% | No (deprioritised → escalated) | Depends on baseline warmup |
| Slow ramp | Neither / partial | ~Y% | No | Baseline shifts with attacker |

### C3 — Scalability limitation (one paragraph)
Single-node IDMS: all per-IP state (rate windows, anomaly baselines, SQLite blocks) is local. Under horizontal scaling, state needs centralisation (Redis) or consistent IP-to-instance routing. This is a known limitation of inline inspection proxies. Document it explicitly — it shows architectural awareness.

---

## Paper Structure (when ready)

1. **Introduction** — The gap: LBs route but don't inspect. Research question.
2. **Background** — Signature vs anomaly IDS, modified Z-score (Iglewicz & Hoaglin 1993), related work on inline proxies.
3. **System Design** — Architecture, two-layer pipeline, escalation, honeypot.
4. **Experimental Setup** — Four scenarios, attack client design, metrics definition.
5. **Results** — S1–S4 comparison table, per-attack-type table, latency overhead table, FPR.
6. **Discussion** — Evasion cases (ramp), Docker jitter effect on threshold calibration, scalability limitation, threshold sensitivity.
7. **Conclusion** — Two-stage detection adds X% over rule-only at Y ms overhead; slow-rate attacks are the gap case; single-node bottleneck is the architectural constraint.

---

## Key numbers to track (fill in as experiments run)

| Metric | S1 | S2 | S3 | S4 |
|---|---|---|---|---|
| Mean response time (ms) | | | | |
| Throughput (req/s) | | | | |
| Success rate (%) | | | | |
| Flood detection rate (%) | — | 0% | ~72% | ~72% |
| SQLi detection rate (%) | — | 0% | 100% | 100% |
| Slow-rate detection rate (%) | — | 0% | 0% | TBD |
| Ramp detection rate (%) | — | 0% | 0% | TBD |
| FPR (%) | — | — | TBD | TBD |
| IDMS overhead (ms) | — | — | TBD | TBD |
