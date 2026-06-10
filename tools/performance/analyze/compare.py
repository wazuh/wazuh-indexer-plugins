#!/usr/bin/env python3
"""Compare two (or more) perf runs side by side into compare.md.

Reuses the per-metric steady-state aggregation from report.py. For every metric
it shows each run's value plus the delta of the LAST run vs the FIRST (e.g.
wazuh-5.0.0 vs wazuh-4.x), so you can read "how much more does 5.x cost".

Usage:
  python3 compare.py 4.x=/path/4.x/metrics.csv 5.0.0=/path/aio/metrics.csv
  python3 compare.py /path/4.x /path/aio          # labels from the parent dir
  [--warmup 5] [--out compare.md]
"""

import argparse
import csv
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402  (reuse METRICS, col, fmt)


def load_csv(path):
    if os.path.isdir(path):
        path = os.path.join(path, "metrics.csv")
    with open(path) as fd:
        return list(csv.DictReader(fd))


def parse_input(arg):
    """`label=path` or bare `path` (label inferred from the parent dir)."""
    if "=" in arg:
        label, path = arg.split("=", 1)
        return label, path
    d = os.path.dirname(path := arg) if arg.endswith(".csv") else arg
    return os.path.basename(os.path.normpath(d)) or path, path


def aggregate(rows, warmup):
    steady = rows[warmup:] if len(rows) > warmup else rows
    out = {}
    for name, _human, _unit, aggm in report.METRICS:
        vals = report.col(steady, name)
        if not vals:
            continue
        out[name] = {
            "avg": None if aggm == "peak" else statistics.fmean(vals),
            "peak": max(vals),
            "cmp": max(vals) if aggm == "peak" else statistics.fmean(vals),
        }
    return out, len(steady)


def main():
    p = argparse.ArgumentParser(description="Compare perf runs side by side")
    p.add_argument("inputs", nargs="+", help="label=metrics.csv (or a run dir)")
    p.add_argument("--warmup", type=int, default=0,
                   help="leading samples dropped per run (default 0 = keep all)")
    p.add_argument("--out", default="compare.md")
    args = p.parse_args()

    runs = []  # [(label, agg, nsteady)]
    for arg in args.inputs:
        label, path = parse_input(arg)
        agg, n = aggregate(load_csv(path), args.warmup)
        runs.append((label, agg, n))

    labels = [r[0] for r in runs]
    first, last = runs[0][1], runs[-1][1]
    L = []
    L.append(f"# Performance comparison — {' vs '.join(labels)}")
    L.append("")
    L.append("- Samples analyzed: " + ", ".join(f"{l}={n}" for l, _, n in runs))
    if args.warmup > 0:
        L.append(f"- Warm-up dropped: first {args.warmup} samples per run")
    L.append("")
    L.append("| Metric | " + " | ".join(labels) + f" | Δ ({labels[-1]} vs {labels[0]}) |")
    L.append("|" + "---|" * (len(labels) + 2))

    for name, human, unit, aggm in report.METRICS:
        if not any(name in r[1] for r in runs):
            continue
        unit_lbl = f" ({unit})" if unit and unit not in ("B", "B/s") else ""
        metric = f"{human}{unit_lbl} ({'peak' if aggm == 'peak' else 'avg / peak'})"
        cells = []
        for _, agg, _ in runs:
            s = agg.get(name)
            if not s:
                cells.append("—")
            elif aggm == "peak":
                cells.append(report.fmt(s["peak"], unit))
            else:
                cells.append(f"{report.fmt(s['avg'], unit)} / {report.fmt(s['peak'], unit)}")
        a, b = first.get(name, {}).get("cmp"), last.get(name, {}).get("cmp")
        dcell = f"{(b - a) / a * 100:+.0f}%" if a not in (None, 0) and b is not None else "—"
        L.append(f"| {metric} | " + " | ".join(cells) + f" | {dcell} |")

    L.append("")
    L.append("## Headline (sizing)")
    for name, human in [("host_cpu_percent", "Host CPU %"),
                        ("host_mem_used_gb", "Host RAM (GB)"),
                        ("proc_indexer_rss_gb", "Indexer RSS (GB)"),
                        ("index_total_per_s", "Ingest (docs/s)")]:
        parts = []
        for l, agg, _ in runs:
            s = agg.get(name)
            if s:
                v = s["avg"] if s["avg"] is not None else s["peak"]
                parts.append(f"{l}: {v:.1f} avg / {s['peak']:.1f} peak")
        if parts:
            L.append(f"- **{human}** — " + "; ".join(parts))

    out = "\n".join(L) + "\n"
    with open(args.out, "w") as fd:
        fd.write(out)
    print(out)
    print(f"[INFO] Wrote {args.out}")


if __name__ == "__main__":
    main()
