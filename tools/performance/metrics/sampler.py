#!/usr/bin/env python3
"""Per-minute Wazuh Indexer performance sampler.

Polls the indexer's ``_nodes/stats`` and ``_cluster/stats`` endpoints on a fixed
interval (default 60s) for a fixed duration (default 3600s), and emits:

  - ``metrics.csv``     one row per sample, per-minute rates derived from counters
  - ``metrics.ndjson``  the raw extracted values per sample (one JSON object/line)

Used by both performance tracks (real-world agent run and OpenSearch Benchmark).
"""

import argparse
import csv
import datetime
import json
import logging
import os
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sampler")

# Counter metrics: reported as per-second rates computed from the delta between
# consecutive samples. Everything else is reported as an instantaneous gauge.
RATE_FIELDS = {
    "index_total",
    "index_time_ms",
    "query_total",
    "query_time_ms",
    "gc_young_count",
    "gc_young_time_ms",
    "gc_old_count",
    "gc_old_time_ms",
    "merge_total",
    "merge_time_ms",
    "refresh_total",
    "refresh_time_ms",
    "flush_total",
    "flush_time_ms",
    "host_disk_read_bytes",
    "host_disk_write_bytes",
    # Rejections are monotonic counters since node start; as rates they are
    # attributed to the measurement window (excludes cold-start/provisioning).
    "write_rejected",
    "search_rejected",
}

# Per-process groups for the AIO host. A process belongs to a group if any of its
# patterns is a substring of the process command line. Whole-host CPU/RAM/disk do
# not depend on this; the per-group split is best-effort attribution.
PROCESS_GROUPS = {
    "indexer": ["wazuh-indexer"],
    "dashboard": ["wazuh-dashboard", "opensearch-dashboards"],
    "manager": ["wazuh-manager", "wazuh-server", "wazuh-engine", "wazuh-analysisd", "wazuh-remoted"],
}
GIB = 1024 ** 3


class HostCollector:
    """Collects whole-host + per-process resource usage on the AIO box via psutil.

    This is the metric the hardware-requirements deliverable cares about: total
    CPU/RAM/disk of the box, plus a per-process split between wazuh-indexer,
    wazuh-manager (engine) and wazuh-dashboard. Returns an empty dict and logs a
    warning if psutil is unavailable, so the indexer sampling still works.
    """

    def __init__(self, disk_path="/"):
        self.disk_path = disk_path
        self.enabled = False
        self._proc_cache = {}  # pid -> psutil.Process (kept across samples for cpu_percent)
        try:
            import psutil

            self.psutil = psutil
            self.ncpu = psutil.cpu_count() or 1
            psutil.cpu_percent(interval=None)  # prime system-wide cpu_percent
            self.enabled = True
        except ImportError:
            log.warning("psutil not installed — host/process metrics disabled "
                        "(install with: pip install psutil)")

    def sample(self):
        if not self.enabled:
            return {}
        ps = self.psutil
        vm = ps.virtual_memory()
        sw = ps.swap_memory()
        du = ps.disk_usage(self.disk_path)
        out = {
            "host_cpu_percent": round(ps.cpu_percent(interval=None), 2),
            "host_load1": round(ps.getloadavg()[0], 2),
            "host_mem_used_percent": vm.percent,
            "host_mem_used_gb": round(vm.used / GIB, 3),
            "host_mem_total_gb": round(vm.total / GIB, 3),
            "host_swap_used_gb": round(sw.used / GIB, 3),
            "host_disk_used_percent": du.percent,
            "host_disk_used_gb": round(du.used / GIB, 3),
        }
        io = ps.disk_io_counters()
        if io:
            out["host_disk_read_bytes"] = io.read_bytes
            out["host_disk_write_bytes"] = io.write_bytes

        # Per-process attribution.
        rss = {g: 0.0 for g in PROCESS_GROUPS}
        cpu = {g: 0.0 for g in PROCESS_GROUPS}
        seen = set()
        for proc in ps.process_iter(["pid", "cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if not cmdline:
                    continue
                for group, patterns in PROCESS_GROUPS.items():
                    if any(pat in cmdline for pat in patterns):
                        pid = proc.info["pid"]
                        seen.add(pid)
                        handle = self._proc_cache.setdefault(pid, proc)
                        rss[group] += handle.memory_info().rss
                        # cpu_percent across the interval, normalized to whole host.
                        cpu[group] += handle.cpu_percent(interval=None) / self.ncpu
                        break
            except (ps.NoSuchProcess, ps.AccessDenied):
                continue
        for pid in list(self._proc_cache):  # drop dead pids
            if pid not in seen:
                del self._proc_cache[pid]
        for group in PROCESS_GROUPS:
            out[f"proc_{group}_rss_gb"] = round(rss[group] / GIB, 3)
            out[f"proc_{group}_cpu_percent"] = round(cpu[group], 2)
        return out


def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_json(session, url):
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract(nodes_stats, cluster_stats):
    """Flatten the stats responses into a single dict of the metrics we track.

    Node-level stats are summed across all data nodes so the row represents the
    whole cluster (an AIO has a single node, but this stays correct for multi-node).
    """
    out = {
        "doc_count": cluster_stats.get("indices", {}).get("docs", {}).get("count", 0),
        "store_size_bytes": cluster_stats.get("indices", {}).get("store", {}).get("size_in_bytes", 0),
        "segment_count": cluster_stats.get("indices", {}).get("segments", {}).get("count", 0),
    }
    # Accumulators across nodes.
    acc = {
        "index_total": 0, "index_time_ms": 0,
        "query_total": 0, "query_time_ms": 0,
        "gc_young_count": 0, "gc_young_time_ms": 0,
        "gc_old_count": 0, "gc_old_time_ms": 0,
        "merge_total": 0, "merge_time_ms": 0,
        "refresh_total": 0, "refresh_time_ms": 0,
        "flush_total": 0, "flush_time_ms": 0,
        "heap_used_bytes": 0, "heap_max_bytes": 0,
        "write_queue": 0, "write_rejected": 0,
        "search_queue": 0, "search_rejected": 0,
        "cpu_percent": 0, "indexing_pressure_bytes": 0,
    }
    node_count = 0
    for node in nodes_stats.get("nodes", {}).values():
        node_count += 1
        idx = node.get("indices", {})
        acc["index_total"] += idx.get("indexing", {}).get("index_total", 0)
        acc["index_time_ms"] += idx.get("indexing", {}).get("index_time_in_millis", 0)
        acc["query_total"] += idx.get("search", {}).get("query_total", 0)
        acc["query_time_ms"] += idx.get("search", {}).get("query_time_in_millis", 0)
        acc["merge_total"] += idx.get("merges", {}).get("total", 0)
        acc["merge_time_ms"] += idx.get("merges", {}).get("total_time_in_millis", 0)
        acc["refresh_total"] += idx.get("refresh", {}).get("total", 0)
        acc["refresh_time_ms"] += idx.get("refresh", {}).get("total_time_in_millis", 0)
        acc["flush_total"] += idx.get("flush", {}).get("total", 0)
        acc["flush_time_ms"] += idx.get("flush", {}).get("total_time_in_millis", 0)

        jvm = node.get("jvm", {})
        acc["heap_used_bytes"] += jvm.get("mem", {}).get("heap_used_in_bytes", 0)
        acc["heap_max_bytes"] += jvm.get("mem", {}).get("heap_max_in_bytes", 0)
        for name, coll in jvm.get("gc", {}).get("collectors", {}).items():
            key = "gc_young" if name in ("young", "G1 Young Generation") else "gc_old"
            acc[f"{key}_count"] += coll.get("collection_count", 0)
            acc[f"{key}_time_ms"] += coll.get("collection_time_in_millis", 0)

        pools = node.get("thread_pool", {})
        acc["write_queue"] += pools.get("write", {}).get("queue", 0)
        acc["write_rejected"] += pools.get("write", {}).get("rejected", 0)
        acc["search_queue"] += pools.get("search", {}).get("queue", 0)
        acc["search_rejected"] += pools.get("search", {}).get("rejected", 0)

        acc["cpu_percent"] += node.get("os", {}).get("cpu", {}).get("percent", 0)
        acc["indexing_pressure_bytes"] += (
            node.get("indexing_pressure", {})
            .get("memory", {})
            .get("total", {})
            .get("combined_coordinating_and_primary_in_bytes", 0)
        )

    out.update(acc)
    out["node_count"] = node_count
    out["heap_used_percent"] = round(
        100 * acc["heap_used_bytes"] / acc["heap_max_bytes"], 2
    ) if acc["heap_max_bytes"] else 0
    return out


def derive_rates(curr, prev, elapsed_s):
    """Return a row combining gauges with per-second rates for counter fields."""
    row = {"@timestamp": curr["_ts"]}
    for key, val in curr.items():
        if key.startswith("_"):
            continue
        if key in RATE_FIELDS:
            if prev is not None and elapsed_s > 0:
                row[f"{key}_per_s"] = round((val - prev[key]) / elapsed_s, 2)
            else:
                row[f"{key}_per_s"] = 0
        else:
            row[key] = val

    # Per-operation latency over the window: (Δ total_time_ms) / (Δ op_count).
    # More useful than ms/s — it is the typical time the indexer spent per
    # indexed doc / per query. 0 when no ops happened (idle minute / cold start).
    for op, count_key, time_key in (
        ("index", "index_total", "index_time_ms"),
        ("query", "query_total", "query_time_ms"),
    ):
        latency = 0
        if prev is not None:
            d_count = curr[count_key] - prev[count_key]
            if d_count > 0:
                latency = round((curr[time_key] - prev[time_key]) / d_count, 3)
        row[f"{op}_latency_ms"] = latency
    return row


def main():
    p = argparse.ArgumentParser(description="Per-minute Wazuh Indexer perf sampler")
    p.add_argument("--endpoint", default="https://localhost:9200")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--interval", type=int, default=60, help="seconds between samples")
    p.add_argument("--duration", type=int, default=3600, help="total run seconds")
    p.add_argument("--out", default="./run", help="output directory")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--no-host", action="store_true",
                   help="skip whole-host/process metrics (use when not running on the AIO)")
    p.add_argument("--disk-path", default="/", help="filesystem path to measure disk usage on")
    args = p.parse_args()

    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    os.makedirs(args.out, exist_ok=True)
    session = requests.Session()
    session.auth = (args.user, args.password)
    session.verify = not args.insecure

    host = None if args.no_host else HostCollector(disk_path=args.disk_path)
    samples = max(1, args.duration // args.interval)
    log.info("Sampling %s every %ss for %ss (%s samples) → %s",
             args.endpoint, args.interval, args.duration, samples, args.out)

    csv_path = os.path.join(args.out, "metrics.csv")
    ndjson_path = os.path.join(args.out, "metrics.ndjson")
    prev = None
    writer = None
    with open(csv_path, "w", newline="") as csv_fd, open(ndjson_path, "w") as nd_fd:
        for i in range(samples):
            loop_start = time.monotonic()
            try:
                nodes = get_json(session, f"{args.endpoint}/_nodes/stats/indices,jvm,thread_pool,os,indexing_pressure")
                cluster = get_json(session, f"{args.endpoint}/_cluster/stats")
                curr = extract(nodes, cluster)
                if host:
                    curr.update(host.sample())
                curr["_ts"] = utc_now_iso()
                elapsed = (loop_start - prev["_mono"]) if prev else 0
                row = derive_rates(curr, prev, elapsed)
                curr["_mono"] = loop_start
                prev = curr

                if writer is None:
                    writer = csv.DictWriter(csv_fd, fieldnames=list(row.keys()))
                    writer.writeheader()
                writer.writerow(row)
                csv_fd.flush()
                nd_fd.write(json.dumps(row) + "\n")
                nd_fd.flush()
                log.info("sample %d/%d  cpu=%s%% mem=%sGB idx/s=%s heap=%s%%",
                         i + 1, samples, row.get("host_cpu_percent", "-"),
                         row.get("host_mem_used_gb", "-"),
                         row.get("index_total_per_s"), row.get("heap_used_percent"))
            except Exception as exc:  # keep sampling even if one poll fails
                log.error("sample %d failed: %s", i + 1, exc)

            sleep_for = args.interval - (time.monotonic() - loop_start)
            if i < samples - 1 and sleep_for > 0:
                time.sleep(sleep_for)

    log.info("Done. Wrote %s and %s", csv_path, ndjson_path)


if __name__ == "__main__":
    sys.exit(main())
