#!/usr/bin/env python3

# Generates the dashboards of the integrations: the views of the Splunk app (Dashboard Studio
# definitions), Kibana saved objects and OpenSearch Dashboards saved objects. The dashboards
# are built from code because their export formats are too verbose to maintain by hand:
# change them here, then regenerate.
#
# Usage:
#   generate.py           write the dashboards
#   generate.py --check   fail if a committed dashboard differs from what this code builds

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kibana  # noqa: E402
import opensearch  # noqa: E402
import splunk  # noqa: E402

INTEGRATIONS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TARGETS = {
    os.path.join(INTEGRATIONS, "splunk", "app", "wazuh_integration", "default", "data", "ui"): splunk.build,
    os.path.join(INTEGRATIONS, "elastic"): kibana.build,
    os.path.join(INTEGRATIONS, "opensearch"): opensearch.build,
}


def duplicate_ids(ndjson: str) -> list:
    """Ids that two saved objects, or two panels of a dashboard, share."""
    objects = [json.loads(line) for line in ndjson.splitlines()]
    ids = Counter((o["type"], o["id"]) for o in objects)
    for o in objects:
        if o["type"] == "dashboard":
            ids.update((o["id"], p["panelIndex"]) for p in json.loads(o["attributes"]["panelsJSON"]))
    return sorted(str(key) for key, count in ids.items() if count > 1)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generates the dashboards of the integrations.")
    parser.add_argument("--check", action="store_true", help="Fail if a committed dashboard is out of date.")
    args = parser.parse_args(argv)

    outdated = []
    for directory, build in TARGETS.items():
        files = build()
        # Views of the Splunk app no longer built, such as those of a dashboard that was removed.
        for folder in sorted({os.path.dirname(name) for name in files if os.path.dirname(name)}):
            for stale in sorted(set(os.listdir(os.path.join(directory, folder))) - {os.path.basename(n) for n in files if os.path.dirname(n) == folder}):
                path = os.path.join(directory, folder, stale)
                relative = os.path.relpath(path, os.path.dirname(INTEGRATIONS))
                if args.check:
                    outdated.append(relative)
                else:
                    os.remove(path)
                    print(f"removed {relative}")
        for name, content in files.items():
            duplicated = duplicate_ids(content) if name.endswith(".ndjson") else []
            if duplicated:
                print(f"{name}: saved objects or panels with the same id, rejected by the import: {duplicated}")
                return 1
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, os.path.dirname(INTEGRATIONS))
            if args.check:
                current = open(path).read() if os.path.exists(path) else None
                if current != content:
                    outdated.append(relative)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fd:
                fd.write(content)
            print(f"written {relative}")

    if outdated:
        print("out of date, run integrations/tools/dashboards/generate.py:", *outdated, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
