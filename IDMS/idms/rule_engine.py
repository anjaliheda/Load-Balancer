"""
rule_engine.py — Phase 1: Rule-Based Detection Engine
======================================================
Stateless pattern matching against configurable rule sets.
Covers four detection dimensions:
  1. Per-IP rate limiting      (sliding window counter)
  2. Payload inspection        (SQL injection, oversized payloads)
  3. Header validation         (missing/malformed API key)
  4. Rapid multi-endpoint scan (many distinct endpoints from one IP)

Each check returns a DetectionResult dataclass so the caller
(idms_proxy.py) always gets a structured verdict, never bare strings.
"""

import re
import time
import threading
import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("rule_engine")


# ─────────────────────────────────────────────
# Configuration  (tune per-scenario in Phase 7)
# ─────────────────────────────────────────────

RULE_CONFIG = {
    # Rate limiting — requests per IP per window
    "rate_limit_window_seconds": 10,
    "rate_limit_max_requests": 200,       # >200 req/10 s → flag (legitimate client sends ~150/phase at 20 req/s; attack client will exceed this)

    # Payload size
    "max_payload_bytes": 8192,            # 8 KB hard limit
    "max_list_items": 500,               # sort_large_list safety cap

    # Multi-endpoint scan
    "endpoint_scan_window_seconds": 10,
    "endpoint_scan_max_distinct": 5,      # >5 distinct paths in window → flag

    # SQL injection — patterns checked against all string values in JSON body
    "sqli_patterns": [
        r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bDROP\b\s+\bTABLE\b)",
        r"(?i)(\bINSERT\b.*\bINTO\b)",
        r"(?i)(\bDELETE\b.*\bFROM\b)",
        r"(?i)(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",  # OR 1=1
        r"(?i)(--|#|/\*)",                                          # comment markers
        r"(?i)(\bEXEC\b|\bEXECUTE\b|\bxp_)",                       # stored procs
        r"(?i)(\bSLEEP\b\s*\(|\bWAITFOR\b)",                       # time-based blind
        r"(?i)(\$where|\$ne|\$gt|\$lt|\$regex|\$or|\$and|\$not)",     # MongoDB operators in values
        r"(?i)(\{\s*['\"]?\$)",                                     # raw MongoDB operator in string
    ],

    # Malformed header patterns
    "required_header": "X-API-Key",
    "valid_api_key": "0586c419972ff7e63d40d6e0c87bb494fcd04dcbd770089724339fed98f81a5c",
}


# ─────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────

@dataclass
class DetectionResult:
    """
    Verdict from the rule engine for a single request.

    Fields:
        flagged       : True if any rule fired
        rule_name     : Which rule triggered (e.g. "rate_limit", "sqli")
        severity      : "low" | "medium" | "high" | "critical"
        detail        : Human-readable description for the dashboard
        recommended   : Suggested mitigation action for MitigationController
        inspection_ms : Time spent in rule engine (latency measurement for Phase 7)
    """
    flagged: bool = False
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    detail: Optional[str] = None
    recommended: str = "allow"          # allow | block | deprioritise | honeypot
    inspection_ms: float = 0.0


# ─────────────────────────────────────────────
# Internal sliding-window state
# ─────────────────────────────────────────────

# Per-IP request timestamps for rate limiting
# { ip: deque([timestamp, ...]) }
_rate_windows: dict = defaultdict(deque)
_rate_lock = threading.Lock()

# Per-IP endpoint sets for scan detection
# { ip: deque([(timestamp, path), ...]) }
_endpoint_windows: dict = defaultdict(deque)
_endpoint_lock = threading.Lock()


# ─────────────────────────────────────────────
# Individual rule checks
# ─────────────────────────────────────────────

def _check_rate_limit(client_ip: str, ts: float) -> Optional[DetectionResult]:
    """
    Sliding-window counter: reject IPs exceeding MAX requests in WINDOW seconds.
    Thread-safe via _rate_lock.
    """
    window = RULE_CONFIG["rate_limit_window_seconds"]
    max_req = RULE_CONFIG["rate_limit_max_requests"]
    cutoff = ts - window

    with _rate_lock:
        dq = _rate_windows[client_ip]
        # Evict timestamps outside the current window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(ts)
        count = len(dq)

    if count > max_req:
        return DetectionResult(
            flagged=True,
            rule_name="rate_limit",
            severity="high",
            detail=f"{count} requests in {window}s (limit {max_req})",
            recommended="block",
        )
    return None


def _check_payload_size(body_bytes: int, body: dict) -> Optional[DetectionResult]:
    """
    Two sub-checks:
      a) Raw body size in bytes
      b) sort_large_list item count (abuse vector specific to this app)
    """
    max_bytes = RULE_CONFIG["max_payload_bytes"]
    if body_bytes > max_bytes:
        return DetectionResult(
            flagged=True,
            rule_name="oversized_payload",
            severity="medium",
            detail=f"Body {body_bytes}B exceeds {max_bytes}B limit",
            recommended="block",
        )

    if body.get("task_type") == "sort_large_list":
        items = len(body.get("numbers", []))
        if items > RULE_CONFIG["max_list_items"]:
            return DetectionResult(
                flagged=True,
                rule_name="oversized_list",
                severity="medium",
                detail=f"sort_large_list with {items} items (limit {RULE_CONFIG['max_list_items']})",
                recommended="block",
            )
    return None


def _extract_strings(obj, depth=0) -> list:
    """
    Recursively extract all strings (both keys AND values) from a JSON object.
    Including keys is essential: MongoDB operator injection uses $where/$ne as
    dict keys, not values, so value-only extraction misses them entirely.
    Capped at depth 6 to prevent DoS via deeply nested payloads.
    """
    if depth > 6:
        return []
    strings = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                strings.append(k)          # capture keys — catches $where, $ne, etc.
            strings.extend(_extract_strings(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_extract_strings(item, depth + 1))
    return strings


def _check_sqli(body: dict) -> Optional[DetectionResult]:
    """
    Scan all string values in the JSON body against compiled SQLi/NoSQLi patterns.
    Patterns are pre-compiled once at import time for efficiency.
    """
    candidates = _extract_strings(body)
    for value in candidates:
        for pattern in _COMPILED_SQLI:
            if pattern.search(value):
                return DetectionResult(
                    flagged=True,
                    rule_name="sqli",
                    severity="critical",
                    detail=f"Injection pattern matched in value: {value[:80]!r}",
                    recommended="honeypot",   # redirect rather than block — capture payload
                )
    return None


def _check_headers(headers: dict) -> Optional[DetectionResult]:
    """
    Validate that the required API key header is present and non-empty.
    We do NOT validate the key value here — that stays with the load balancer.
    We do flag completely missing or obviously malformed keys.

    Uses a case-insensitive lookup because dict(request.headers) produces a
    plain Python dict whose keys may be normalised (e.g. X-Api-Key) by the
    HTTP stack, even when the client sent X-API-Key.
    """
    required = RULE_CONFIG["required_header"].lower()
    key = next((v for k, v in headers.items() if k.lower() == required), "")

    if not key:
        return DetectionResult(
            flagged=True,
            rule_name="missing_api_key",
            severity="medium",
            detail="Request missing X-API-Key header",
            recommended="block",
        )

    # Flag keys that are clearly crafted probes (< 8 chars, or containing injection chars)
    if len(key) < 8 or re.search(r"[\"';\\]", key):
        return DetectionResult(
            flagged=True,
            rule_name="malformed_api_key",
            severity="medium",
            detail=f"Malformed API key: {key[:20]!r}",
            recommended="block",
        )

    # Validate key value — IDMS is the sole auth boundary
    if key != RULE_CONFIG["valid_api_key"]:
        return DetectionResult(
            flagged=True,
            rule_name="invalid_api_key",
            severity="medium",
            detail="API key does not match",
            recommended="block",
        )

    return None


def _check_endpoint_scan(client_ip: str, path: str, ts: float) -> Optional[DetectionResult]:
    """
    Detect rapid probing of multiple distinct endpoints.
    Attackers enumerating API surface hit many paths quickly.
    """
    window = RULE_CONFIG["endpoint_scan_window_seconds"]
    max_distinct = RULE_CONFIG["endpoint_scan_max_distinct"]
    cutoff = ts - window

    with _endpoint_lock:
        dq = _endpoint_windows[client_ip]
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        dq.append((ts, path))
        distinct = len({entry[1] for entry in dq})

    if distinct > max_distinct:
        return DetectionResult(
            flagged=True,
            rule_name="endpoint_scan",
            severity="high",
            detail=f"{distinct} distinct endpoints probed in {window}s",
            recommended="deprioritise",
        )
    return None


# Pre-compile SQLi patterns once at import time
_COMPILED_SQLI = [re.compile(p) for p in RULE_CONFIG["sqli_patterns"]]


# ─────────────────────────────────────────────
# Public API — called by idms_proxy.py
# ─────────────────────────────────────────────

def inspect(
    client_ip: str,
    path: str,
    headers: dict,
    body: dict,
    raw_body_bytes: int,
) -> DetectionResult:
    """
    Run all rule checks against a single incoming request.
    Returns the FIRST (highest-priority) triggered DetectionResult,
    or a clean allow result if nothing fires.

    Priority order (highest first):
      1. SQLi / injection          — critical, always honeypot
      2. Rate limit                — high, block
      3. Endpoint scan             — high, deprioritise
      4. Payload size              — medium, block
      5. Header validation         — medium, block

    Inspection latency is measured and attached to the result.
    """
    t_start = time.perf_counter()

    # Run checks in priority order; return on first hit
    #
    # Auth is first: no reason to inspect an unauthenticated request — it is
    # blocked immediately, and its content is never analysed or characterised
    # as an attack type. This keeps Phase 6 measurements clean: a blocked event
    # with rule_name="missing_api_key" or "invalid_api_key" is unambiguously an
    # auth failure, never confused with a sqli or rate-limit event.
    checks = [
        lambda: _check_headers(headers),
        lambda: _check_sqli(body),
        lambda: _check_rate_limit(client_ip, t_start),
        lambda: _check_endpoint_scan(client_ip, path, t_start),
        lambda: _check_payload_size(raw_body_bytes, body),
    ]

    result = None
    for check in checks:
        result = check()
        if result is not None:
            break

    inspection_ms = (time.perf_counter() - t_start) * 1000

    if result is None:
        result = DetectionResult(flagged=False, recommended="allow")

    result.inspection_ms = inspection_ms

    if result.flagged:
        logger.warning(
            "RULE_ENGINE | ip=%-15s rule=%-20s severity=%-8s detail=%s latency=%.2fms",
            client_ip, result.rule_name, result.severity, result.detail, inspection_ms,
        )
    else:
        logger.debug(
            "RULE_ENGINE | ip=%-15s ALLOW latency=%.2fms",
            client_ip, inspection_ms,
        )

    return result


def reset_state_for_ip(client_ip: str) -> None:
    """
    Clear all sliding-window state for an IP.
    Called by MitigationController when a timed block expires.
    """
    with _rate_lock:
        _rate_windows.pop(client_ip, None)
    with _endpoint_lock:
        _endpoint_windows.pop(client_ip, None)
    logger.info("RULE_ENGINE | cleared state for %s", client_ip)


def get_current_rates() -> dict:
    """
    Snapshot of current request counts per IP for the dashboard.
    Returns { ip: count_in_current_window }
    """
    now = time.time()
    window = RULE_CONFIG["rate_limit_window_seconds"]
    cutoff = now - window
    snapshot = {}
    with _rate_lock:
        for ip, dq in _rate_windows.items():
            count = sum(1 for ts in dq if ts >= cutoff)
            if count > 0:
                snapshot[ip] = count
    return snapshot