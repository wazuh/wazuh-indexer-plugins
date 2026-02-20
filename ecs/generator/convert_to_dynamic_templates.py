#!/usr/bin/env python3
"""
Convert Wazuh Common Schema (WCS) static index templates to dynamic_templates.

Reads an OpenSearch legacy index template with a monolithic static `properties`
block and generates an optimized `dynamic_templates` array. The output template
uses `"dynamic": "strict_allow_templates"` so that only fields matching the
WCS schema are accepted, but mappings are created lazily (on first ingest)
rather than statically.

Usage:
    python3 convert_to_dynamic_templates.py <input_template.json> [output_template.json]

If no output path is given, writes to stdout.
"""

import json
import sys
import argparse
from collections import defaultdict
from typing import Any


# ---------------------------------------------------------------------------
# 1. Flatten the nested properties into (dotted_path -> mapping_config) pairs
# ---------------------------------------------------------------------------

def flatten_properties(obj: dict, prefix: str = "") -> dict[str, dict]:
    """
    Recursively walk a nested `properties` mapping and return a flat dict
    of {dotted.field.path: {type, ...extra settings}} for every leaf field.
    """
    result: dict[str, dict] = {}
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if "properties" in value:
            result.update(flatten_properties(value["properties"], path))
        elif "type" in value:
            result[path] = dict(value)
    return result


# ---------------------------------------------------------------------------
# 2. Analyse suffix patterns and build optimised wildcard rules
# ---------------------------------------------------------------------------

BASE_FIELDS = {"@timestamp"}
WILDCARD_MIN_FIELDS = 3


def _suffix(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def build_dynamic_templates(
    flat: dict[str, dict],
    object_names: set[str] | None = None,
) -> list[dict]:
    """
    Given the flattened field map, produce an optimised `dynamic_templates` list.

    ``object_names`` is the set of suffixes (last path segment) that are also
    used as intermediate object node names in the mapping scaffolding.  Wildcard
    rules like ``*.hash`` are **not** emitted for these suffixes because
    ``strict_allow_templates`` would try to map the intermediate object node
    itself as a leaf, causing type conflicts.  Instead, every field with such a
    suffix gets an exact ``path_match`` rule.
    """
    if object_names is None:
        object_names = set()

    suffix_type_map: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for path, mapping in flat.items():
        if path in BASE_FIELDS:
            continue
        s = _suffix(path)
        suffix_type_map[s][mapping["type"]].append(path)

    templates: list[dict] = []
    handled_paths: set[str] = set()
    all_keyword_paths: set[str] = set()

    for suffix, type_groups in sorted(suffix_type_map.items()):
        # If this suffix is also an intermediate object name, never wildcard it
        suffix_is_object = suffix in object_names

        if len(type_groups) == 1:
            typ = next(iter(type_groups))
            paths = type_groups[typ]

            if typ == "keyword":
                all_keyword_paths.update(paths)
                continue

            if len(paths) >= WILDCARD_MIN_FIELDS and not suffix_is_object:
                mapping = _representative_mapping(flat, paths)
                name = f"wcs_{typ}_{suffix}"
                templates.append({
                    name: {
                        "path_match": f"*.{suffix}",
                        "mapping": mapping,
                    }
                })
                handled_paths.update(paths)
            else:
                for p in sorted(paths):
                    mapping = dict(flat[p])
                    name = f"wcs_{_safe_name(p)}"
                    templates.append({
                        name: {
                            "path_match": p,
                            "mapping": mapping,
                        }
                    })
                    handled_paths.add(p)
        else:
            for typ, paths in type_groups.items():
                if typ == "keyword":
                    all_keyword_paths.update(paths)
                    continue
                for p in sorted(paths):
                    mapping = dict(flat[p])
                    name = f"wcs_{_safe_name(p)}"
                    templates.append({
                        name: {
                            "path_match": p,
                            "mapping": mapping,
                        }
                    })
                    handled_paths.add(p)

    # Remaining non-keyword, non-handled fields
    for path, mapping in sorted(flat.items()):
        if path in handled_paths or path in BASE_FIELDS or path in all_keyword_paths:
            continue
        name = f"wcs_{_safe_name(path)}"
        templates.append({
            name: {
                "path_match": path,
                "mapping": dict(mapping),
            }
        })
        handled_paths.add(path)

    # Keyword wildcard groups
    kw_suffix_groups: dict[str, list[str]] = defaultdict(list)
    for p in all_keyword_paths:
        kw_suffix_groups[_suffix(p)].append(p)

    kw_handled: set[str] = set()
    for suffix, paths in sorted(kw_suffix_groups.items(), key=lambda x: -len(x[1])):
        if len(paths) >= WILDCARD_MIN_FIELDS and suffix not in object_names:
            name = f"wcs_keyword_{suffix}"
            templates.append({
                name: {
                    "path_match": f"*.{suffix}",
                    "mapping": {"type": "keyword", "ignore_above": 1024},
                }
            })
            kw_handled.update(paths)

    for p in sorted(all_keyword_paths - kw_handled):
        name = f"wcs_{_safe_name(p)}"
        templates.append({
            name: {
                "path_match": p,
                "mapping": {"type": "keyword", "ignore_above": 1024},
            }
        })

    return templates


def _representative_mapping(flat: dict[str, dict], paths: list[str]) -> dict:
    mappings = [flat[p] for p in paths]
    base = {"type": mappings[0]["type"]}
    extra_keys = set()
    for m in mappings:
        extra_keys.update(k for k in m if k != "type")
    for key in extra_keys:
        values = [m.get(key) for m in mappings if key in m]
        if len(set(str(v) for v in values)) == 1 and len(values) == len(mappings):
            base[key] = values[0]
    return base


def _safe_name(path: str) -> str:
    return path.replace(".", "_").replace("-", "_")


# ---------------------------------------------------------------------------
# 3. Build object scaffolding from ALL known field paths
# ---------------------------------------------------------------------------

def _build_object_scaffolding(properties: dict, all_field_paths: set[str]) -> dict:
    """
    Build the intermediate object scaffolding needed by strict_allow_templates.

    This merges two sources:
    1. The original nested `properties` tree (preserves existing intermediate objects).
    2. All known leaf field paths — intermediate segments that don't exist in the
       original tree are added as empty object nodes.

    This is critical because some fields (e.g. agent.host.ip) may be defined as
    leaves without their parent (agent.host) being an explicit object node in
    the original static mapping.
    """
    # Start from the original tree structure
    result = _extract_object_tree(properties)

    # Add missing intermediate nodes derived from all known field paths
    for path in sorted(all_field_paths):
        parts = path.split(".")
        # Walk all intermediate segments (skip the last one — that's the leaf)
        node = result
        for part in parts[:-1]:
            if part not in node:
                node[part] = {"properties": {}}
            elif "properties" not in node[part]:
                node[part]["properties"] = {}
            node = node[part]["properties"]

    return result


def _extract_object_tree(properties: dict) -> dict:
    """Extract only the intermediate object nodes from a properties tree."""
    result = {}
    for key, value in properties.items():
        if "properties" in value:
            children = _extract_object_tree(value["properties"])
            result[key] = {"properties": children}
    return result


# ---------------------------------------------------------------------------
# 4. Reassemble the full index template
# ---------------------------------------------------------------------------

def _collect_object_names(properties: dict) -> set[str]:
    """
    Collect the set of all key names used as intermediate object nodes.

    These names must NOT be used in wildcard ``*.suffix`` dynamic templates
    because ``strict_allow_templates`` would attempt to map the object node
    itself as a leaf field, causing type conflicts.
    """
    names: set[str] = set()
    for key, value in properties.items():
        if "properties" in value:
            names.add(key)
            names.update(_collect_object_names(value["properties"]))
    return names


# Enrichment document fields — added as exact dynamic_templates so that
# threat intelligence enrichments (IoC matches, etc.) are properly typed.
ENRICHMENT_TEMPLATES = [
    # enrichment.indicator.*
    {"wcs_enrichment_indicator_id":                {"path_match": "enrichment.indicator.id",            "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_name":              {"path_match": "enrichment.indicator.name",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_type":              {"path_match": "enrichment.indicator.type",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_confidence":         {"path_match": "enrichment.indicator.confidence",    "mapping": {"type": "long"}}},
    {"wcs_enrichment_indicator_first_seen":         {"path_match": "enrichment.indicator.first_seen",    "mapping": {"type": "date"}}},
    {"wcs_enrichment_indicator_last_seen":          {"path_match": "enrichment.indicator.last_seen",     "mapping": {"type": "date"}}},
    {"wcs_enrichment_indicator_reference":          {"path_match": "enrichment.indicator.reference",     "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_tags":               {"path_match": "enrichment.indicator.tags",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_provider":           {"path_match": "enrichment.indicator.provider",      "mapping": {"type": "keyword", "ignore_above": 1024}}},
    # enrichment.indicator.software.*
    {"wcs_enrichment_indicator_software_type":      {"path_match": "enrichment.indicator.software.type", "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_software_name":      {"path_match": "enrichment.indicator.software.name", "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_software_alias":     {"path_match": "enrichment.indicator.software.alias","mapping": {"type": "keyword", "ignore_above": 1024}}},
    # enrichment.indicator.feed.*
    {"wcs_enrichment_indicator_feed_name":          {"path_match": "enrichment.indicator.feed.name",     "mapping": {"type": "keyword", "ignore_above": 1024}}},
    # enrichment.type
    {"wcs_enrichment_type":                        {"path_match": "enrichment.type",                   "mapping": {"type": "keyword", "ignore_above": 1024}}},
]

# Object scaffolding for the enrichment namespace
ENRICHMENT_SCAFFOLDING = {
    "enrichment": {
        "properties": {
            "indicator": {
                "properties": {
                    "software": {"properties": {}},
                    "feed": {"properties": {}},
                }
            }
        }
    }
}


def convert_template(input_data: dict) -> dict:
    template_block = input_data.get("template", {})
    mappings = template_block.get("mappings", {})
    properties = mappings.get("properties", {})

    # Flatten and convert
    flat = flatten_properties(properties)

    # Remove old enrichments.custom.* fields — replaced by enrichment.indicator.*
    flat = {k: v for k, v in flat.items()
            if not k.startswith("enrichments.custom.") and k != "enrichments.source"}

    # Collect all intermediate object node names to prevent wildcard conflicts
    object_names = _collect_object_names(properties)

    dynamic_templates = build_dynamic_templates(flat, object_names=object_names)

    # Collect ALL known field paths (for scaffolding)
    all_field_paths = set(flat.keys())

    # Build scaffolding from original tree + all field paths
    static_props = _build_object_scaffolding(properties, all_field_paths)

    # Add enrichment object scaffolding; remove old enrichments.* scaffolding
    static_props.pop("enrichments", None)
    static_props.update(ENRICHMENT_SCAFFOLDING)

    # Re-inject base fields with their full mapping
    for field in BASE_FIELDS:
        if field in properties:
            static_props[field] = properties[field]

    # Remove individual check.*, policy.*, compliance.requirement.* exact rules
    # from generated templates — they are replaced by catch-all wildcards below.
    dynamic_templates = [
        t for t in dynamic_templates
        if not any(
            r.get("path_match", "").startswith(("check.", "policy.", "compliance.requirement."))
            for r in t.values()
        )
    ]

    # Catch-all wildcard templates for namespaces where all fields are keyword.
    # Placed before the generated rules so they match first.
    CATCHALL_TEMPLATES = [
        {"wcs_policy_all":     {"path_match": "policy.*",       "mapping": {"type": "keyword", "ignore_above": 1024}}},
        {"wcs_check_all":      {"path_match": "check.*",        "mapping": {"type": "keyword", "ignore_above": 1024}}},
        {"wcs_compliance_all": {"path_match": "compliance.*.*",  "mapping": {"type": "keyword", "ignore_above": 1024}}},
    ]

    # Add compliance.requirement scaffolding
    if "compliance" in static_props:
        static_props["compliance"].setdefault("properties", {}).setdefault(
            "requirement", {"properties": {}}
        )

    # Build final dynamic_templates:
    # 1. Enrichment templates (IoC indicator structure)
    # 2. Catch-all templates (policy, check, compliance)
    # 3. WCS schema templates (generated)
    all_dt = ENRICHMENT_TEMPLATES + CATCHALL_TEMPLATES + dynamic_templates

    new_mappings = {
        "date_detection": mappings.get("date_detection", False),
        "dynamic": "strict_allow_templates",
        "dynamic_templates": all_dt,
        "properties": static_props,
    }

    output = dict(input_data)
    output["template"] = dict(template_block)
    output["template"]["mappings"] = new_mappings
    return output


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert WCS static properties to dynamic_templates"
    )
    parser.add_argument("input", help="Path to the source OpenSearch template JSON")
    parser.add_argument("output", nargs="?", help="Output path (default: stdout)")
    parser.add_argument(
        "--stats", action="store_true",
        help="Print conversion statistics to stderr"
    )
    args = parser.parse_args()

    with open(args.input) as f:
        input_data = json.load(f)

    result = convert_template(input_data)

    if args.stats:
        flat = flatten_properties(
            input_data["template"]["mappings"]["properties"]
        )
        n_templates = len(result["template"]["mappings"]["dynamic_templates"])
        n_wildcard = sum(
            1 for t in result["template"]["mappings"]["dynamic_templates"]
            for v in t.values()
            if "*" in v.get("path_match", "")
        )
        print(f"[stats] Input leaf fields:    {len(flat)}", file=sys.stderr)
        print(f"[stats] Output templates:     {n_templates}", file=sys.stderr)
        print(f"[stats] Wildcard templates:   {n_wildcard}", file=sys.stderr)
        print(f"[stats] Exact templates:      {n_templates - n_wildcard}", file=sys.stderr)
        if n_templates:
            print(f"[stats] Compression ratio:    {len(flat)/n_templates:.1f}x", file=sys.stderr)

    output_json = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json + "\n")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
