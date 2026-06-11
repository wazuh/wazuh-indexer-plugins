#!/usr/bin/env python3
"""Plot perf-run metrics, overlaying runs — raw timeline or smoothed moving average.

Two complementary views over the same metric grid:
  --kind timeline (default): one line per run over elapsed minutes — shows *when* spikes
    happen (cold-start bursts, GC pauses, ingest dips).
  --kind average: a trailing moving-average line per run (like an SMA on a financial chart),
    with the raw series faint behind it — smooths the spikes so the trend/level is easy to
    read and compare between runs.

Usage:
  python3 plot.py 4.x=/path/4.x/metrics.csv 5.0.0=/path/aio/metrics.csv
  [--metrics host_cpu_percent,index_total_per_s,...] [--kind timeline|average]
  [--window N] [--out FILE]

Requires matplotlib (pip install matplotlib).
"""

import argparse
import csv
import datetime
import os
from collections import deque

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_METRICS = [
    ("host_cpu_percent", "Host CPU %"),
    ("host_mem_used_gb", "Host RAM (GB)"),
    ("proc_indexer_rss_gb", "Indexer RSS (GB)"),
    ("proc_manager_rss_gb", "Manager RSS (GB)"),
    ("index_total_per_s", "Ingest (docs/s)"),
    ("index_latency_ms", "Index latency (ms/op)"),
    ("heap_used_percent", "Indexer heap %"),
    ("heap_used_gb", "Indexer heap used (GB)"),
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


def draw_timeline(ax, runs, metric):
    """One line per run over elapsed minutes."""
    plotted = 0
    for label, rows in runs:
        xs, ys = series(rows, metric)
        if ys:
            ax.plot(xs, ys, label=label, linewidth=1.2)
            plotted += 1
    ax.set_xlabel("minutes")
    # Only draw a legend when a run had data — else matplotlib warns "No artists with labels".
    if plotted:
        ax.legend(fontsize=8)


def moving_average(ys, window):
    """Trailing simple moving average (each point = mean of the last `window` samples)."""
    dq, total, out = deque(), 0.0, []
    for v in ys:
        dq.append(v)
        total += v
        if len(dq) > window:
            total -= dq.popleft()
        out.append(total / len(dq))
    return out


def draw_average(ax, runs, metric, colors, window):
    """Trailing moving-average line per run (SMA), raw series faint behind it."""
    plotted = 0
    for j, (label, rows) in enumerate(runs):
        xs, ys = series(rows, metric)
        if not ys:
            continue
        color = colors[j % len(colors)] if colors else None
        w = window if window else max(3, len(ys) // 12)  # auto: ~1/12 of the run, min 3
        ax.plot(xs, ys, color=color, linewidth=0.7, alpha=0.20)          # raw, for context
        ax.plot(xs, moving_average(ys, w), color=color, linewidth=1.8,   # the moving average
                label=f"{label} (SMA{w})")
        plotted += 1
    ax.set_xlabel("minutes")
    if plotted:
        ax.legend(fontsize=8)


def main():
    p = argparse.ArgumentParser(description="Plot perf runs (timeline or averages)")
    p.add_argument("inputs", nargs="+", help="label=metrics.csv (or a run dir)")
    p.add_argument("--metrics", help="comma-separated metric columns to plot")
    p.add_argument("--kind", choices=["timeline", "average"], default="timeline",
                   help="timeline (raw lines) or average (trailing moving-average line)")
    p.add_argument("--window", type=int, default=0,
                   help="moving-average window in samples (0 = auto, ~1/12 of the run)")
    p.add_argument("--out", default="timeline.png")
    args = p.parse_args()

    runs = [(lbl, load_csv(path)) for lbl, path in map(parse_input, args.inputs)]
    requested = [(m, m) for m in args.metrics.split(",")] if args.metrics else DEFAULT_METRICS

    # Drop metrics that have no data in ANY run, so we don't render blank panels. The
    # per-process splits (proc_indexer_rss_gb / proc_manager_rss_gb) only exist in the
    # real-world scenario (local psutil); in isolated the sampler reads node_exporter, which
    # has no per-process breakdown and there's no manager — so those panels are omitted there.
    def has_data(metric):
        return any(series(rows, metric)[1] for _, rows in runs)

    metrics = [(m, t) for (m, t) in requested if has_data(m)]
    dropped = [m for (m, _) in requested if not has_data(m)]
    if dropped:
        print(f"[INFO] Skipping {len(dropped)} metric(s) with no data: {', '.join(dropped)}")
    if not metrics:
        print("[WARN] No metrics with data to plot — nothing written.")
        return

    colors = plt.rcParams["axes.prop_cycle"].by_key().get("color", [])
    cols = 2
    rows_n = (len(metrics) + cols - 1) // cols
    fig, axes = plt.subplots(rows_n, cols, figsize=(13, 3 * rows_n), squeeze=False)
    for i, (metric, title) in enumerate(metrics):
        ax = axes[i // cols][i % cols]
        if args.kind == "average":
            draw_average(ax, runs, metric, colors, args.window)
        else:
            draw_timeline(ax, runs, metric)
        ax.set_title(title, fontsize=10)
        ax.grid(True, alpha=0.3)
    for j in range(len(metrics), rows_n * cols):
        axes[j // cols][j % cols].axis("off")

    heading = "moving average" if args.kind == "average" else "timeline"
    fig.suptitle(f"Perf {heading} — " + " vs ".join(l for l, _ in runs), fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(args.out, dpi=110)
    print(f"[INFO] Wrote {args.out}  ({len(metrics)} panels, {len(runs)} runs, {args.kind})")


if __name__ == "__main__":
    main()
