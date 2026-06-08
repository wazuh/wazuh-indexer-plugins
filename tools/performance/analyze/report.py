#!/usr/bin/env python3
"""Summarize a performance run into a hardware-utilization report.

Reads a run directory produced by the sampler (metrics.csv [+ run-metadata.json])
and emits report.md: steady-state averages and peaks of the metrics that matter
for sizing — whole-host CPU/RAM/disk, per-process split, achieved ingest rate,
and indexer JVM/GC. The report is labeled (e.g. "wazuh-5.0.0") so a 4.x run and a
5.x run can be compared side by side after the fact.

Usage:
  python3 report.py --run ./runs/aio-run [--warmup 5] [--label wazuh-5.0.0]
"""

import argparse
import csv
import json
import os
import statistics

# (csv column, human label, unit, aggregation) — aggregation: "peak" reports
# max, "rate" reports avg + peak, "gauge" reports avg + peak.
METRICS = [
    ("host_cpu_percent", "Host CPU", "%", "gauge"),
    ("host_load1", "Host load (1m)", "", "gauge"),
    ("host_mem_used_gb", "Host RAM used", "GB", "gauge"),
    ("host_mem_used_percent", "Host RAM used", "%", "gauge"),
    ("host_swap_used_gb", "Host swap used", "GB", "peak"),
    ("host_disk_used_gb", "Host disk used", "GB", "gauge"),
    ("host_disk_read_bytes_per_s", "Disk read", "B/s", "rate"),
    ("host_disk_write_bytes_per_s", "Disk write", "B/s", "rate"),
    ("proc_indexer_cpu_percent", "wazuh-indexer CPU", "%", "gauge"),
    ("proc_indexer_rss_gb", "wazuh-indexer RAM", "GB", "gauge"),
    ("proc_manager_cpu_percent", "wazuh-manager CPU", "%", "gauge"),
    ("proc_manager_rss_gb", "wazuh-manager RAM", "GB", "gauge"),
    ("proc_dashboard_cpu_percent", "wazuh-dashboard CPU", "%", "gauge"),
    ("proc_dashboard_rss_gb", "wazuh-dashboard RAM", "GB", "gauge"),
    ("index_total_per_s", "Ingest rate", "docs/s", "rate"),
    ("query_total_per_s", "Query rate", "q/s", "rate"),
    ("index_latency_ms", "Index latency", "ms/op", "rate"),
    ("query_latency_ms", "Query latency", "ms/op", "rate"),
    ("heap_used_percent", "Indexer JVM heap", "%", "gauge"),
    ("gc_old_time_ms_per_s", "Old-GC time", "ms/s", "rate"),
    ("indexing_pressure_bytes", "Indexing pressure", "B", "gauge"),
    ("write_queue", "Write queue depth", "", "gauge"),
    ("search_queue", "Search queue depth", "", "gauge"),
    ("write_rejected_per_s", "Write rejections", "/s", "rate"),
    ("search_rejected_per_s", "Search rejections", "/s", "rate"),
    ("doc_count", "Total documents", "", "peak"),
    ("store_size_bytes", "Store size", "B", "peak"),
]


def load_rows(run_dir):
    with open(os.path.join(run_dir, "metrics.csv")) as fd:
        return list(csv.DictReader(fd))


def load_meta(run_dir):
    path = os.path.join(run_dir, "run-metadata.json")
    if os.path.exists(path):
        with open(path) as fd:
            return json.load(fd)
    return {}


def col(rows, name):
    vals = []
    for r in rows:
        v = r.get(name, "")
        if v not in ("", None):
            try:
                vals.append(float(v))
            except ValueError:
                pass
    return vals


def fmt(v, unit):
    if unit == "B" or unit == "B/s":
        for u in ["B", "KB", "MB", "GB", "TB"]:
            if abs(v) < 1024 or u == "TB":
                s = f"{v:.1f} {u}" + ("/s" if unit.endswith("/s") else "")
                return s
            v /= 1024
    return f"{v:,.2f}{(' ' + unit) if unit else ''}"


def main():
    p = argparse.ArgumentParser(description="Summarize a perf run into report.md")
    p.add_argument("--run", required=True, help="run directory (with metrics.csv)")
    p.add_argument("--warmup", type=int, default=0,
                   help="leading samples to drop as warm-up (default 0 = keep all)")
    p.add_argument("--label", default=None, help="run label; overrides run-metadata.json")
    args = p.parse_args()

    rows = load_rows(args.run)
    meta = load_meta(args.run)
    label = args.label or meta.get("label") or meta.get("version") or os.path.basename(os.path.abspath(args.run))

    steady = rows[args.warmup:] if len(rows) > args.warmup else rows
    lines = []
    lines.append(f"# Performance report — {label}")
    lines.append("")
    if args.warmup > 0:
        lines.append(f"- Samples: {len(rows)} total "
                     f"({len(rows) - len(steady)} warm-up dropped, {len(steady)} analyzed)")
    else:
        lines.append(f"- Samples: {len(rows)} (all included; --warmup N drops the first N)")
    if meta.get("start"):
        lines.append(f"- Window: {meta.get('start')} → {meta.get('stop')} "
                     f"({meta.get('duration_s', '?')}s @ {meta.get('interval_s', '?')}s)")
    if meta.get("endpoint"):
        lines.append(f"- Endpoint: {meta['endpoint']}")
    lines.append("")
    lines.append("| Metric | Avg | Peak |")
    lines.append("|--------|-----|------|")
    for name, human, unit, agg in METRICS:
        vals = col(steady, name)
        if not vals:
            continue
        peak = fmt(max(vals), unit)
        avg = "—" if agg == "peak" else fmt(statistics.fmean(vals), unit)
        lines.append(f"| {human}{(' (' + unit + ')') if unit and unit not in ('B', 'B/s') else ''} | {avg} | {peak} |")

    lines.append("")
    lines.append("## Sizing takeaways")
    cpu = col(steady, "host_cpu_percent")
    mem = col(steady, "host_mem_used_gb")
    eps = col(steady, "index_total_per_s")
    if cpu and mem:
        lines.append(f"- At ~{statistics.fmean(eps):,.0f} docs/s avg ingest, the host used "
                     f"**{statistics.fmean(cpu):.0f}% CPU avg / {max(cpu):.0f}% peak** and "
                     f"**{statistics.fmean(mem):.1f} GB RAM avg / {max(mem):.1f} GB peak**.")
        lines.append("- Use peak figures for *minimum* hardware and add headroom for *recommended*.")
    rej_peak = max((col(steady, "write_rejected_per_s") or [0])
                   + (col(steady, "search_rejected_per_s") or [0]))
    if rej_peak > 0:
        lines.append(f"- ⚠️ Thread-pool rejections observed (peak {rej_peak:.1f}/s) — "
                     f"the host was saturated at some point during the window.")

    out = os.path.join(args.run, "report.md")
    with open(out, "w") as fd:
        fd.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n[INFO] Wrote {out}")


if __name__ == "__main__":
    main()
