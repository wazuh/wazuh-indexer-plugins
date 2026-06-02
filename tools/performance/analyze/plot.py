#!/usr/bin/env python3
"""Plot perf-run metrics over an elapsed-minute timeline, overlaying runs.

Aggregates hide *when* spikes happen (cold-start bursts, GC pauses, ingest dips).
This aligns runs to minutes-since-start (absolute clocks differ between runs) and
renders a PNG grid of line charts — one panel per metric, one line per run.

Usage:
  python3 plot.py 4.x=/path/4.x/metrics.csv 5.0.0=/path/aio/metrics.csv
  [--metrics host_cpu_percent,index_total_per_s,...] [--out timeline.png]

Requires matplotlib (pip install matplotlib).
"""

import argparse
import csv
import datetime
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_METRICS = [
    ("host_cpu_percent", "Host CPU %"),
    ("host_mem_used_gb", "Host RAM (GB)"),
    ("proc_indexer_rss_gb", "Indexer RSS (GB)"),
    ("proc_manager_rss_gb", "Manager RSS (GB)"),
    ("index_total_per_s", "Ingest (docs/s)"),
    ("heap_used_percent", "Indexer heap %"),
    ("gc_old_time_ms_per_s", "Old-GC (ms/s)"),
    ("host_disk_write_bytes_per_s", "Disk write (B/s)"),
]


def load_csv(path):
    if os.path.isdir(path):
        path = os.path.join(path, "metrics.csv")
    with open(path) as fd:
        return list(csv.DictReader(fd))


def parse_input(arg):
    if "=" in arg:
        label, path = arg.split("=", 1)
        return label, path
    d = os.path.dirname(arg) if arg.endswith(".csv") else arg
    return os.path.basename(os.path.normpath(d)) or arg, arg


def parse_ts(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def series(rows, metric):
    """Return (minutes_since_start, values) for the metric, skipping blanks."""
    t0 = parse_ts(rows[0]["@timestamp"])
    xs, ys = [], []
    for r in rows:
        v = r.get(metric, "")
        if v in ("", None):
            continue
        try:
            ys.append(float(v))
        except ValueError:
            continue
        xs.append((parse_ts(r["@timestamp"]) - t0).total_seconds() / 60.0)
    return xs, ys


def main():
    p = argparse.ArgumentParser(description="Timeline plot of perf runs")
    p.add_argument("inputs", nargs="+", help="label=metrics.csv (or a run dir)")
    p.add_argument("--metrics", help="comma-separated metric columns to plot")
    p.add_argument("--out", default="timeline.png")
    args = p.parse_args()

    runs = [(lbl, load_csv(path)) for lbl, path in map(parse_input, args.inputs)]
    metrics = [(m, m) for m in args.metrics.split(",")] if args.metrics else DEFAULT_METRICS

    cols = 2
    rows_n = (len(metrics) + cols - 1) // cols
    fig, axes = plt.subplots(rows_n, cols, figsize=(13, 3 * rows_n), squeeze=False)
    for i, (metric, title) in enumerate(metrics):
        ax = axes[i // cols][i % cols]
        for label, rows in runs:
            xs, ys = series(rows, metric)
            if ys:
                ax.plot(xs, ys, label=label, linewidth=1.2)
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("minutes")
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=8)
    for j in range(len(metrics), rows_n * cols):
        axes[j // cols][j % cols].axis("off")

    fig.suptitle("Perf timeline — " + " vs ".join(l for l, _ in runs), fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(args.out, dpi=110)
    print(f"[INFO] Wrote {args.out}  ({len(metrics)} panels, {len(runs)} runs)")


if __name__ == "__main__":
    main()
