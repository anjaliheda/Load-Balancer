"""
results_analyzer.py — Phase 6 Results Aggregator
==================================================
Reads CSV files produced by attack_client.py and/or queries the IDMS
attack_log to produce paper-ready summary tables.

Usage
-----
  # Analyze a CSV from any attack mode
  python results_analyzer.py results/attack_flood_20260405_120000.csv

  # Analyze multiple CSVs (e.g. all runs of --mode all)
  python results_analyzer.py results/attack_all_*.csv

  # False positive rate — query IDMS after a clean client.py run
  python results_analyzer.py --fpr --idms-url http://localhost:5001

  # Full scenario comparison table (supply one CSV per scenario)
  python results_analyzer.py --scenario S3 results/s3_all.csv \
                              --scenario S4 results/s4_all.csv \
                              --idms-url http://localhost:5001

  # Latency overhead — compare S1 baseline to S4 IDMS overhead
  python results_analyzer.py --overhead \
      --s1-latency 320 \
      --idms-url http://localhost:5001
"""

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict

import requests as http


# ── Helpers ────────────────────────────────────────────────────────────────────

def _divider(title: str = "", width: int = 70) -> None:
    if title:
        pad = width - len(title) - 2
        print(f"\n{'─' * (pad // 2)} {title} {'─' * (pad - pad // 2)}")
    else:
        print("─" * width)


def _load_csv(path: str) -> list:
    """Load rows from an attack_client.py CSV. Returns list of dicts."""
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except FileNotFoundError:
        print(f"  ERROR: file not found: {path}", file=sys.stderr)
        return []


def _fetch_attack_log(idms_url: str, limit: int = 2000) -> list:
    """Fetch detection_log from IDMS."""
    try:
        r = http.get(f"{idms_url}/idms/attack_log?limit={limit}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"  WARNING: could not fetch IDMS attack_log ({e})", file=sys.stderr)
    return []


def _fetch_metrics(idms_url: str) -> dict:
    """Fetch in-memory metrics ring from IDMS."""
    try:
        r = http.get(f"{idms_url}/idms/metrics?n=500", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ── Single-CSV analysis ────────────────────────────────────────────────────────

def analyze_csv(rows: list, label: str = "") -> dict:
    """
    Aggregate outcome counts, detection rate, and latency stats from CSV rows.
    Returns a dict suitable for table printing.
    """
    if not rows:
        return {}

    outcomes: dict = defaultdict(int)
    latencies = []
    for r in rows:
        outcomes[r.get("outcome", "?")] += 1
        try:
            latencies.append(float(r["response_ms"]))
        except (KeyError, ValueError):
            pass

    total    = len(rows)
    blocked  = outcomes.get("blocked", 0)
    honeypot = outcomes.get("honeypot", 0)
    allowed  = outcomes.get("allowed", 0)
    deprio   = outcomes.get("deprioritise", 0)
    overload = outcomes.get("overloaded", 0)
    other    = total - blocked - honeypot - allowed - deprio - overload

    det_pct  = (blocked + honeypot) / total * 100 if total else 0
    avg_ms   = statistics.mean(latencies)   if latencies else 0.0
    med_ms   = statistics.median(latencies) if latencies else 0.0
    p95_ms   = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0.0

    return {
        "label":    label,
        "total":    total,
        "allowed":  allowed,
        "blocked":  blocked,
        "honeypot": honeypot,
        "deprio":   deprio,
        "overload": overload,
        "other":    other,
        "det_pct":  det_pct,
        "avg_ms":   avg_ms,
        "med_ms":   med_ms,
        "p95_ms":   p95_ms,
    }


def print_mode_summary(rows: list, path: str) -> None:
    """Print a detailed breakdown of one CSV by mode and phase."""
    _divider(f"FILE: {path.split('/')[-1].split(chr(92))[-1]}")

    # Group by mode
    by_mode: dict = defaultdict(list)
    for r in rows:
        by_mode[r.get("mode", "?")].append(r)

    print(f"  Total rows : {len(rows)}")
    print(f"  Modes      : {', '.join(sorted(by_mode))}\n")

    for mode, mode_rows in sorted(by_mode.items()):
        # Only analyse attack-phase rows for attack modes; warmup/legitimate are separate
        attack_rows = [r for r in mode_rows if r.get("phase") in ("attack", "")]
        if not attack_rows:
            attack_rows = mode_rows   # stress mode uses phase names like stress_20

        stats = analyze_csv(attack_rows, label=mode)
        if not stats:
            continue

        print(f"  [{mode.upper()}]  {stats['total']} requests")
        print(f"    allowed      : {stats['allowed']:5d}  ({stats['allowed']/stats['total']*100:.1f}%)")
        print(f"    blocked      : {stats['blocked']:5d}  ({stats['blocked']/stats['total']*100:.1f}%)")
        print(f"    honeypot     : {stats['honeypot']:5d}  ({stats['honeypot']/stats['total']*100:.1f}%)")
        print(f"    deprioritised: {stats['deprio']:5d}  ({stats['deprio']/stats['total']*100:.1f}%)")
        if stats['overload']:
            print(f"    overloaded   : {stats['overload']:5d}  ({stats['overload']/stats['total']*100:.1f}%)")
        print(f"    detection    : {stats['det_pct']:.1f}%  (blocked + honeypot / total)")
        print(f"    latency      : mean={stats['avg_ms']:.1f}ms  median={stats['med_ms']:.1f}ms  p95={stats['p95_ms']:.1f}ms")
        print()


# ── FPR analysis ───────────────────────────────────────────────────────────────

def analyze_fpr(idms_url: str, client_ip: str = None) -> None:
    """
    Query IDMS attack_log and metrics ring to estimate false positive rate.

    A false positive is any block or deprioritise event logged for a legitimate
    client IP (one not running attack_client.py).  Run this immediately after a
    clean client.py run with no attack traffic.
    """
    _divider("FALSE POSITIVE RATE ANALYSIS")

    log = _fetch_attack_log(idms_url)
    metrics = _fetch_metrics(idms_url)

    if not log and not metrics:
        print("  No data — is the IDMS running? Did you run client.py first?")
        return

    counters = metrics.get("counters", {})
    total_allow  = counters.get("allow", 0)
    total_block  = counters.get("block", 0)
    total_honey  = counters.get("honeypot", 0)
    total_deprio = counters.get("deprioritise", 0)
    grand_total  = total_allow + total_block + total_honey + total_deprio

    print(f"  IDMS counters (since last reset):")
    print(f"    allow        : {total_allow}")
    print(f"    block        : {total_block}")
    print(f"    honeypot     : {total_honey}")
    print(f"    deprioritise : {total_deprio}")
    print(f"    total        : {grand_total}")

    # Known attack IPs to exclude from FPR calculation
    ATTACK_IP_RANGES = ("192.168.100.", "10.10.0.")
    fp_events = [
        e for e in log
        if not any(e.get("ip", "").startswith(pfx) for pfx in ATTACK_IP_RANGES)
        and e.get("action") in ("block", "deprioritise")
    ]

    if not fp_events:
        if total_allow > 0:
            print(f"\n  False positives: 0 events")
            print(f"  FPR            : 0.0%  (no legitimate traffic flagged)")
            print(f"  Result         : CLEAN — all legitimate requests passed through")
        else:
            print(f"\n  No allow events found — did client.py complete a run?")
        return

    # Group by IP and rule
    by_ip: dict = defaultdict(list)
    by_rule: dict = defaultdict(int)
    for e in fp_events:
        by_ip[e.get("ip", "?")].append(e)
        by_rule[e.get("rule_name", "?")] += 1

    fp_total  = len(fp_events)
    fpr       = fp_total / grand_total * 100 if grand_total else 0.0

    print(f"\n  False positive events: {fp_total} (block or deprioritise on non-attack IPs)")
    print(f"  FPR                  : {fpr:.2f}%  ({fp_total} / {grand_total})")

    print(f"\n  By rule:")
    for rule, cnt in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"    {rule:<30} : {cnt}")

    print(f"\n  By IP:")
    for ip, events in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        actions = defaultdict(int)
        for e in events:
            actions[e.get("action", "?")] += 1
        print(f"    {ip:<20} : {len(events)} events  {dict(actions)}")

    if fpr < 0.5:
        verdict = "GOOD — well within acceptable range for production"
    elif fpr < 2.0:
        verdict = "ACCEPTABLE — minor tuning may improve"
    else:
        verdict = "HIGH — investigate rule thresholds; may affect legitimate traffic"
    print(f"\n  Verdict: {verdict}")


# ── Scenario comparison table ──────────────────────────────────────────────────

def print_scenario_table(scenarios: list) -> None:
    """
    Print the S1–S4 paper comparison table.
    scenarios = list of (label, stats_dict)
    """
    _divider("SCENARIO COMPARISON TABLE  (paper-ready)")

    print(f"{'Scenario':<8} {'Total':>7} {'Allowed':>9} {'Blocked':>9} "
          f"{'Honeypot':>10} {'Deprio':>8} {'Det%':>7} {'Avg ms':>8} {'Med ms':>8} {'p95 ms':>8}")
    _divider(width=85)

    for label, s in scenarios:
        if not s:
            print(f"{label:<8}  (no data)")
            continue
        print(f"{label:<8} {s['total']:>7} {s['allowed']:>9} {s['blocked']:>9} "
              f"{s['honeypot']:>10} {s['deprio']:>8} {s['det_pct']:>6.1f}% "
              f"{s['avg_ms']:>8.1f} {s['med_ms']:>8.1f} {s['p95_ms']:>8.1f}")


# ── Overhead analysis ──────────────────────────────────────────────────────────

def analyze_overhead(idms_url: str, s1_latency_ms: float) -> None:
    """
    Compare IDMS inspect_ms to S1 baseline latency to compute overhead breakdown.
    """
    _divider("LATENCY OVERHEAD ANALYSIS")

    metrics = _fetch_metrics(idms_url)
    events  = metrics.get("events", [])

    if not events:
        print("  No events in metrics ring — run some traffic through the IDMS first.")
        return

    inspect_times = [e["inspect_ms"] for e in events if e.get("inspect_ms", 0) > 0]
    total_times   = [e["total_ms"]   for e in events if e.get("total_ms",   0) > 0]

    if not inspect_times:
        print("  No inspect_ms data found.")
        return

    avg_inspect = statistics.mean(inspect_times)
    med_inspect = statistics.median(inspect_times)
    avg_total   = statistics.mean(total_times) if total_times else 0
    overhead    = avg_total - s1_latency_ms if s1_latency_ms else 0

    print(f"  S1 baseline latency (no IDMS) : {s1_latency_ms:.1f} ms  (supplied)")
    print(f"  Rule engine inspect_ms        : mean={avg_inspect:.2f}ms  median={med_inspect:.2f}ms")
    print(f"  Total IDMS proxy time         : mean={avg_total:.2f}ms")
    print(f"  Overhead vs S1 baseline       : ~{overhead:.1f}ms  ({overhead/s1_latency_ms*100:.1f}% increase)" if s1_latency_ms else "")
    print(f"\n  Breakdown estimate:")
    print(f"    Rule engine inspection : ~{avg_inspect:.2f}ms")
    print(f"    Network + forwarding   : ~{max(0, avg_total - avg_inspect):.2f}ms")
    print(f"    Anomaly scoring        : included in total_ms (no separate timer)")
    print(f"\n  Note: anomaly scoring time is included in total_ms but not in inspect_ms.")
    print(f"  To isolate: anomaly ≈ total_ms − inspect_ms − forwarding_time")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("csvfiles", nargs="*", help="CSV files from attack_client.py")
    p.add_argument("--idms-url", default="http://localhost:5001",
                   help="IDMS base URL for live queries (default: %(default)s)")
    p.add_argument("--fpr", action="store_true",
                   help="Query IDMS attack_log to estimate false positive rate")
    p.add_argument("--overhead", action="store_true",
                   help="Print IDMS latency overhead breakdown")
    p.add_argument("--s1-latency", type=float, default=0.0,
                   help="S1 baseline mean latency in ms (required for --overhead comparison)")
    p.add_argument("--scenario", nargs=2, action="append", metavar=("LABEL", "CSVFILE"),
                   help="Add a labeled scenario for the comparison table (e.g. --scenario S3 s3.csv)")

    args = p.parse_args()
    idms_url = args.idms_url.rstrip("/")
    ran_something = False

    # ── Per-file detailed breakdown ───────────────────────────────────────────
    for path in args.csvfiles:
        rows = _load_csv(path)
        if rows:
            print_mode_summary(rows, path)
            ran_something = True

    # ── Scenario comparison table ─────────────────────────────────────────────
    if args.scenario:
        scenario_stats = []
        for label, csvpath in args.scenario:
            rows = _load_csv(csvpath)
            attack_rows = [r for r in rows if r.get("phase") == "attack"]
            if not attack_rows:
                attack_rows = rows
            scenario_stats.append((label, analyze_csv(attack_rows, label)))
        print_scenario_table(scenario_stats)
        ran_something = True

    # ── FPR analysis ──────────────────────────────────────────────────────────
    if args.fpr:
        analyze_fpr(idms_url)
        ran_something = True

    # ── Overhead analysis ─────────────────────────────────────────────────────
    if args.overhead:
        analyze_overhead(idms_url, args.s1_latency)
        ran_something = True

    if not ran_something:
        p.print_help()


if __name__ == "__main__":
    main()
