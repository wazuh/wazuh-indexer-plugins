"""Generate the static finding-enrichment mapping from the events index template.

Reads the Main events template (before dynamic_templates conversion) and
extracts the mappings block. It then injects specific required fields (like 
event.doc_id, event.index, and the rule object) to ensure they are always 
present for the Security Analytics Plugin.

The generated file is written to a temporary location.

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


def deep_merge(base, update):
    """
    Recursively merges dictionary 'update' into 'base'.
    Ensures that if 'event' already exists, 'doc_id' and 'index' are added
    to its properties without overwriting the entire 'event' object.
    """
    for key, value in update.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def inject_required_fields(mapping):
    """
    Injects explicitly required fields into the mapping properties.
    """
    required_fields = {
        "event": {
            "type": "object",
            "properties": {
                "doc_id": {
                    "type": "keyword"
                },
                "index": {
                    "type": "keyword"
                }
            }
        },
        "rule": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "keyword"
                },
                "title": {
                    "type": "keyword"
                },
                "tags": {
                    "type": "keyword"
                },
                "level": {
                    "type": "keyword"
                },
                "status": {
                    "type": "keyword"
                },
                "sigma_id": {
                    "type": "keyword"
                },
                "compliance": {
                    "type": "object",
                    "dynamic": True
                },
                "mitre": {
                    "type": "object",
                    "properties": {
                        "tactic": {
                            "type": "keyword"
                        },
                        "technique": {
                            "type": "keyword"
                        },
                        "subtechnique": {
                            "type": "keyword"
                        }
                    }
                }
            }
        }
    }
    
    deep_merge(mapping["properties"], required_fields)


def count_leaves(props):
    """Count leaf (non-object) fields in a properties tree."""
    count = 0
    for v in props.values():
        if isinstance(v, dict) and "properties" in v:
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
    inject_required_fields(mapping)
    with open(args.output, "w") as f:
        json.dump(mapping, f, indent=2)
        f.write("\n")

    leaf_count = count_leaves(mapping["properties"])
    print(f"Generated finding-enrichment mapping with {leaf_count} fields -> {args.output}")


if __name__ == "__main__":
    main()
