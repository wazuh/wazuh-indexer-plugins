#!/usr/bin/env python3

# Generates the dashboards of the integrations: Splunk Dashboard Studio definitions, Kibana
# saved objects and OpenSearch Dashboards saved objects. The dashboards are built from code because their export formats
# are too verbose to maintain by hand: change them here, then regenerate.
#
# Usage:
#   generate.py           write the dashboards
#   generate.py --check   fail if a committed dashboard differs from what this code builds

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kibana  # noqa: E402
import opensearch  # noqa: E402
import splunk  # noqa: E402

INTEGRATIONS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TARGETS = {
    os.path.join(INTEGRATIONS, "splunk", "dashboards"): splunk.build,
    os.path.join(INTEGRATIONS, "elastic"): kibana.build,
    os.path.join(INTEGRATIONS, "opensearch"): opensearch.build,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generates the dashboards of the integrations.")
    parser.add_argument("--check", action="store_true", help="Fail if a committed dashboard is out of date.")
    args = parser.parse_args(argv)

    outdated = []
    for directory, build in TARGETS.items():
        for name, content in build().items():
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, os.path.dirname(INTEGRATIONS))
            if args.check:
                current = open(path).read() if os.path.exists(path) else None
                if current != content:
                    outdated.append(relative)
                continue
            os.makedirs(directory, exist_ok=True)
            with open(path, "w") as fd:
                fd.write(content)
            print(f"written {relative}")

    if outdated:
        print("out of date, run integrations/tools/dashboards/generate.py:", *outdated, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
