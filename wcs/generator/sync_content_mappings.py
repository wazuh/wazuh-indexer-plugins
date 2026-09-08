#!/usr/bin/env python3
"""Derive a Content Manager mapping file from a generated setup index template.

The threat-intel content mappings are consumed by two plugins. The setup plugin creates each
index from an index template, and the Content Manager keeps a bare mappings document so it can
create the blue/green shadow index during a content swap without setup intervention. Both must
describe the same index, so only one of them is authored: the WCS module generates the setup
template, and this script writes the Content Manager copy from it.

Usage:
    sync_content_mappings.py <setup-template.json> <content-manager-mappings.json>
"""

import json
import sys


def main(template_path: str, mappings_path: str) -> int:
    with open(template_path, encoding="utf-8") as handle:
        template = json.load(handle)

    try:
        mappings = template["template"]["mappings"]
    except KeyError:
        print(
            f"error: {template_path} has no 'template.mappings'; nothing to derive",
            file=sys.stderr,
        )
        return 1

    with open(mappings_path, "w", encoding="utf-8") as handle:
        json.dump(mappings, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
