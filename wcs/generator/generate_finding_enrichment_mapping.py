"""Generate the static finding-enrichment mapping from the events index template.

Reads the Main events template (before dynamic_templates conversion) and
extracts the mappings block as a standalone static mapping file suitable for the
Security Analytics Plugin.

The generated file is written to a temporary location. In GHA, it is then
copied to the SAP repository and a PR is opened automatically. For local
development, copy the output manually to the SAP repo.

This script is meant to run AFTER generate_schema.sh produces the static
events template and BEFORE convert_to_dynamic_templates.py converts it.

Usage:
    python3 generate_finding_enrichment_mapping.py <events_template> <output_file>

Example:
    python3 generate_finding_enrichment_mapping.py \
        plugins/setup/src/main/resources/templates/streams/events.json \
        /tmp/wazuh-finding-enrichment-mapping.json
"""

import json
import argparse
import sys


def extract_static_mappings(template_data):
    """
    Extract the mappings block from an index template.

    This script runs before convert_to_dynamic_templates.py, so the template
    is expected to contain only static properties.
    """
    mappings = template_data.get("template", {}).get("mappings", {})

    if not mappings:
        print("Error: No mappings found in the template.", file=sys.stderr)
        sys.exit(1)

    properties = mappings.get("properties", {})

    return {
        "date_detection": False,
        "dynamic": "strict",
        "properties": properties,
    }


def count_leaves(props):
    """Count leaf (non-object) fields in a properties tree."""
    count = 0
    for v in props.values():
        if "properties" in v:
            count += count_leaves(v["properties"])
        else:
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Generate a static finding-enrichment mapping from the events template."
    )
    parser.add_argument("input", help="Path to the events index template JSON")
    parser.add_argument("output", help="Path to write the finding-enrichment mapping JSON")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        template_data = json.load(f)

    mapping = extract_static_mappings(template_data)

    with open(args.output, "w") as f:
        json.dump(mapping, f, indent=2)
        f.write("\n")

    leaf_count = count_leaves(mapping["properties"])
    print(f"Generated finding-enrichment mapping with {leaf_count} fields -> {args.output}")


if __name__ == "__main__":
    main()
