"""
anomaly_engine.py — Phase 2: Statistical Anomaly Detection
===========================================================
Per-IP sliding-window baseline profiling.

For each IP we maintain two rolling distributions over the last WINDOW seconds:
  • payload_bytes   : raw body size per request
  • inter_arrival_s : seconds between consecutive requests from the same IP

After MIN_BASELINE_SAMPLES observations, each new request is scored against
the per-IP baseline using a modified Z-score (median + MAD).  The approach
follows Iglewicz & Hoaglin (1993) and is robust to the small, skewed sample
sizes typical of short-window traffic analysis.

Why per-IP rather than global:
  Global thresholds miss slow-rate attacks that stay under the hard rate limiter
  in rule_engine.py.  A legitimate client has a stable inter-arrival distribution;
  an attacker slowly ramping up shows rising Z-scores long before crossing the
  rate_limit threshold.  This gives us a second, independent detection layer
  whose false-positive rate can be measured separately in Phase 6.

Integration:
  Called by idms_proxy.py AFTER rule_engine.inspect().
  Returns a DetectionResult so the proxy's mitigation logic is unchanged.
  Anomalies get "deprioritise" (not "block") by default — they indicate
  suspicious deviation, not confirmed attack.  Phase 3 MitigationController
  may escalate based on recurrence.

Metrics produced (for Phase 6 evaluation):
  • anomaly_score   : weighted combined Z-score
  • payload_z       : payload-size Z-score component
  • iat_z           : inter-arrival Z-score component
  • baseline_n      : samples used for scoring
"""

import time
import math
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from rule_engine import DetectionResult

logger = logging.getLogger("anomaly_engine")


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

ANOMALY_CONFIG: dict = {
    # Sliding window for baseline collection
    "window_seconds":           30,

    # Warm-up period — no scoring until at least this many samples exist.
    # 150 balances two constraints:
    #   • High enough that short-lived attack IPs (flood: blocked at 200 req)
    #     never warm up — flood IP sends ~250 in 2.5s but gets blocked at 200.
    #   • Low enough that the anomaly demo IP (~10 req/s baseline) warms up
    #     within ~15s so the burst demo is ready quickly.
    "min_baseline_samples":     150,

    # Modified Z-score threshold.
    # Lowered to 1.5 for the Docker demo environment: Windows Docker Desktop adds
    # 20–80ms of variable latency, which widens the IAT baseline distribution and
    # increases MAD. With high MAD, concurrent burst requests (sub-ms IAT) only
    # produce Z-scores of ~1.5–2.5, so 5.0 was unreachable in practice.
    "zscore_threshold":         1.5,

    # Escalated threshold — scores above this jump to "high" severity
    "zscore_high_multiplier":   1.5,

    # Contribution weights (must sum to 1.0 for interpretable combined score).
    # Payload scoring is disabled (weight=0.0): the rule engine already hard-caps
    # payloads at 8 KB, and legitimate workloads use task types with inherently
    # different payload sizes — a multimodal distribution that cannot be baselined
    # per-IP without per-task-type state.  Payload Z-score is still computed and
    # logged for research purposes (Phase 6) but does not affect the verdict.
    # Anomaly detection is IAT-only: burst attacks always accelerate request rate.
    "payload_zscore_weight":    0.0,
    "iat_zscore_weight":        1.0,
}


# ─────────────────────────────────────────────
# Per-IP state
# ─────────────────────────────────────────────

@dataclass
class _IPState:
    # (timestamp, payload_bytes) sliding window
    samples: deque = field(default_factory=deque)
    # Most-recent request timestamp (for IAT computation)
    last_ts: Optional[float] = None
    # Sliding window of inter-arrival times (seconds)
    inter_arrivals: deque = field(default_factory=deque)


_ip_states: dict = defaultdict(_IPState)
_state_lock = threading.Lock()


# ─────────────────────────────────────────────
# Statistics helpers
# ─────────────────────────────────────────────

def _median(values: list) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _mad(values: list, med: float) -> float:
    """Median Absolute Deviation — robust scale estimator."""
    if len(values) < 2:
        return 0.0
    return _median([abs(v - med) for v in values])


def _modified_zscore(observation: float, baseline: list) -> float:
    """
    Modified Z-score of `observation` relative to `baseline` values.

    Formula:  0.6745 * |x - median(baseline)| / MAD(baseline)
    The constant 0.6745 normalises MAD to be consistent with standard deviation
    under a normal distribution.

    Returns 0.0 if the baseline is too flat to distinguish (MAD ≈ 0).
    Returns 10.0 (capped) when the baseline is constant but the observation differs.
    """
    if len(baseline) < 2:
        return 0.0
    med = _median(baseline)
    mad = _mad(baseline, med)
    if mad < 1e-9:
        # Perfectly flat baseline — any deviation is maximally anomalous
        return 0.0 if abs(observation - med) < 1e-9 else 10.0
    return 0.6745 * abs(observation - med) / mad


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def score(
    client_ip: str,
    payload_bytes: int,
    ts: Optional[float] = None,
) -> DetectionResult:
    """
    Update per-IP baseline and return an anomaly verdict for this request.

    Parameters
    ----------
    client_ip     : source IP address (string)
    payload_bytes : raw request body size in bytes
    ts            : request arrival timestamp; defaults to time.time()

    Returns
    -------
    DetectionResult
        flagged=False  — request is within the established baseline
        flagged=True   — combined Z-score exceeds threshold; recommended action
                         is "deprioritise" (soft mitigation pending Phase 3)
    """
    t_start = time.perf_counter()

    if ts is None:
        ts = time.time()

    cfg = ANOMALY_CONFIG
    window     = cfg["window_seconds"]
    min_n      = cfg["min_baseline_samples"]
    cutoff     = ts - window

    with _state_lock:
        state = _ip_states[client_ip]

        # ── Record inter-arrival time ────────────────────────────────────────
        if state.last_ts is not None:
            iat = ts - state.last_ts
            state.inter_arrivals.append(iat)
        state.last_ts = ts

        # ── Record payload sample ────────────────────────────────────────────
        state.samples.append((ts, payload_bytes))

        # ── Evict samples outside the sliding window ─────────────────────────
        while state.samples and state.samples[0][0] < cutoff:
            state.samples.popleft()

        # Keep inter_arrivals length consistent with samples
        # (one IAT per gap between consecutive samples)
        max_iat = max(0, len(state.samples) - 1)
        while len(state.inter_arrivals) > max_iat:
            state.inter_arrivals.popleft()

        n_samples = len(state.samples)

        # ── Warm-up guard ─────────────────────────────────────────────────────
        if n_samples < min_n:
            logger.debug(
                "ANOMALY | ip=%-15s WARMUP n=%d/%d",
                client_ip, n_samples, min_n,
            )
            r = DetectionResult(flagged=False, recommended="allow")
            r.inspection_ms = (time.perf_counter() - t_start) * 1000
            return r

        # ── Compute Z-scores ──────────────────────────────────────────────────
        # Exclude the current observation from the baseline so we're scoring it
        # against prior behaviour, not including it in its own reference.
        payload_history  = [b for _, b in state.samples]
        baseline_payload = payload_history[:-1]
        # Directional payload scoring: only flag oversized requests.
        # Attacks inflate payload size relative to baseline; a small request
        # after large ones is never an attack. This mirrors the IAT fix and
        # eliminates false positives when legitimate traffic switches between
        # task types with very different payload sizes.
        payload_med = _median(baseline_payload)
        if float(payload_bytes) > payload_med:
            payload_z = _modified_zscore(float(payload_bytes), baseline_payload)
        else:
            payload_z = 0.0

        iat_list = list(state.inter_arrivals)
        if len(iat_list) >= 2:
            current_iat = iat_list[-1]
            baseline_iats = iat_list[:-1]
            # Only score when the request arrived FASTER than baseline (burst).
            # A longer-than-usual IAT means the client paused — not an attack.
            # Scoring pauses as anomalies causes false positives whenever the
            # legitimate client sleeps between algorithm runs.
            med = _median(baseline_iats)
            if current_iat < med:
                iat_z = _modified_zscore(current_iat, baseline_iats)
            else:
                iat_z = 0.0
        else:
            iat_z = 0.0

        # Local copy of n for logging outside lock
        baseline_n = n_samples

    # ── Weighted combined score ───────────────────────────────────────────────
    combined = (
        cfg["payload_zscore_weight"] * payload_z +
        cfg["iat_zscore_weight"]     * iat_z
    )

    threshold = cfg["zscore_threshold"]

    if combined <= threshold:
        logger.debug(
            "ANOMALY | ip=%-15s score=%.2f payload_z=%.2f iat_z=%.2f n=%d CLEAN",
            client_ip, combined, payload_z, iat_z, baseline_n,
        )
        r = DetectionResult(flagged=False, recommended="allow")
        r.inspection_ms = (time.perf_counter() - t_start) * 1000
        return r

    # ── Anomaly detected ─────────────────────────────────────────────────────
    severity = "high" if combined > threshold * cfg["zscore_high_multiplier"] else "medium"
    detail = (
        f"Anomaly score={combined:.2f} "
        f"(payload_z={payload_z:.2f} iat_z={iat_z:.2f} n={baseline_n})"
    )

    logger.warning(
        "ANOMALY | ip=%-15s score=%.2f payload_z=%.2f iat_z=%.2f n=%d severity=%s",
        client_ip, combined, payload_z, iat_z, baseline_n, severity,
    )

    return DetectionResult(
        flagged=True,
        rule_name="anomaly",
        severity=severity,
        detail=detail,
        recommended="deprioritise",
        inspection_ms=(time.perf_counter() - t_start) * 1000,
    )


def reset_state_for_ip(client_ip: str) -> None:
    """
    Discard per-IP anomaly baseline.
    Called by idms_proxy._unblock_ip() alongside rule_engine.reset_state_for_ip().
    """
    with _state_lock:
        _ip_states.pop(client_ip, None)
    logger.info("ANOMALY | cleared baseline for %s", client_ip)


def reset_all() -> None:
    """Clear ALL per-IP baselines. Called by clear_log for full demo reset."""
    with _state_lock:
        _ip_states.clear()
    logger.info("ANOMALY | cleared all per-IP baselines")


def _prune_stale_states() -> None:
    """Remove per-IP state for IPs with no samples in the current window.
    Prevents unbounded memory growth from IPs that stop sending traffic."""
    cutoff = time.time() - ANOMALY_CONFIG["window_seconds"]
    with _state_lock:
        stale = [ip for ip, st in _ip_states.items()
                 if not st.samples or st.samples[-1][0] < cutoff]
        for ip in stale:
            del _ip_states[ip]
    if stale:
        logger.debug("ANOMALY | pruned %d stale IP states", len(stale))


def _prune_loop():
    """Background thread: prune stale IP states every 60 seconds."""
    while True:
        time.sleep(60)
        _prune_stale_states()


threading.Thread(target=_prune_loop, daemon=True).start()


def get_anomaly_snapshot() -> dict:
    """
    Return per-IP baseline stats for the /idms/metrics endpoint.
    Only includes IPs with samples in the current window.

    Returns { ip: { "samples": int, "warmed_up": bool } }
    """
    now    = time.time()
    cutoff = now - ANOMALY_CONFIG["window_seconds"]
    min_n  = ANOMALY_CONFIG["min_baseline_samples"]
    out    = {}
    with _state_lock:
        for ip, state in _ip_states.items():
            n = sum(1 for ts, _ in state.samples if ts >= cutoff)
            if n > 0:
                out[ip] = {
                    "samples":   n,
                    "warmed_up": n >= min_n,
                }
    return out
