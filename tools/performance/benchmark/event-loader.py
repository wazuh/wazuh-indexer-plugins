#!/usr/bin/env python3
"""Steady-rate event loader for the isolated performance scenario.

Indexes copies of a fixed system-activity event into the
``wazuh-events-v5-system-activity`` data stream at a target rate (events/sec) for a
fixed duration, so the pre-created detector (see setup-detector.sh) turns each event
into a finding. The data stream is append-only, so ``_bulk`` uses the ``create`` action.

Each second it submits one ``_bulk`` of ``--rate`` events (each with a fresh
``@timestamp``) and sleeps off the remainder of the second, logging achieved vs target
rate. This produces a sustained, real-world-like load rather than a one-shot burst.

Usage:
  event-loader.py --target https://host:9200 --user admin --password admin \
      --rate 1000 --duration 600 [--index wazuh-events-v5-system-activity] [--insecure]
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# The canonical perf event. event.action="modified" + category "system-activity" is what
# the pre-created Sigma rule / detector matches. @timestamp is overwritten per document.
TEST_EVENT_TEMPLATE = {
    "event.action": "modified",
    "wazuh": {"integration": {"category": "system-activity", "name": "wazuh-fim"}},
}


def iso_now(epoch):
    """RFC3339 UTC timestamp (ms precision) for a given epoch seconds float."""
    ms = int((epoch - int(epoch)) * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + f".{ms:03d}Z"


def main():
    p = argparse.ArgumentParser(description="Steady-rate Wazuh event loader")
    p.add_argument("--target", default="https://localhost:9200")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--index", default="wazuh-events-v5-system-activity")
    p.add_argument("--rate", type=int, default=1000, help="events per second")
    p.add_argument("--duration", type=int, default=600, help="seconds to sustain the load")
    p.add_argument("--clients", type=int, default=4, help="concurrent bulk clients")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = p.parse_args()

    import json

    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.auth = (args.user, args.password)
    session.verify = not args.insecure
    base = args.target.rstrip("/")
    # Data streams are append-only → bulk into <stream>/_bulk with the "create" action.
    bulk_url = f"{base}/{args.index}/_bulk"
    action = json.dumps({"create": {}}) + "\n"

    def build_payload(n, now):
        ts = iso_now(now)
        doc = dict(TEST_EVENT_TEMPLATE)
        doc["@timestamp"] = ts
        line = json.dumps(doc, separators=(",", ":")) + "\n"
        return "".join(action + line for _ in range(n))

    def send(payload):
        r = session.post(
            bulk_url, data=payload, headers={"Content-Type": "application/x-ndjson"}, timeout=120
        )
        r.raise_for_status()
        body = r.json()
        errs = (
            sum(1 for it in body.get("items", []) if it.get("create", {}).get("status", 200) >= 300)
            if body.get("errors")
            else 0
        )
        return errs

    print(
        f"[INFO] Loading '{args.index}' at {args.rate} events/s for {args.duration}s "
        f"({args.clients} clients)"
    )
    total = total_errs = 0
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.clients) as pool:
        for sec in range(args.duration):
            tick = time.monotonic()
            payload = build_payload(args.rate, time.time())
            try:
                total_errs += pool.submit(send, payload).result()
            except Exception as exc:  # keep the load running; surface at the end
                total_errs += args.rate
                print(f"[WARN] bulk at t={sec}s failed: {exc}", file=sys.stderr)
            total += args.rate
            if sec % 30 == 0:
                elapsed = max(time.monotonic() - t0, 1e-9)
                print(f"[INFO] t={sec}s sent={total} achieved={total/elapsed:,.0f}/s errors={total_errs}")
            # Pace to one batch per wall-clock second.
            slept = time.monotonic() - tick
            if slept < 1.0:
                time.sleep(1.0 - slept)

    elapsed = max(time.monotonic() - t0, 1e-9)
    session.post(f"{base}/{args.index}/_refresh", timeout=120)
    print(
        f"[INFO] Done: sent {total} events in {elapsed:.1f}s "
        f"({total/elapsed:,.0f}/s), {total_errs} error(s)"
    )
    return 1 if total_errs else 0


if __name__ == "__main__":
    sys.exit(main())
