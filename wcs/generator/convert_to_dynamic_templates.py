"""
Convert Wazuh Common Schema (WCS) static index templates to dynamic_templates.

Reads an OpenSearch legacy index template with a monolithic static `properties`
block and generates an optimized `dynamic_templates` array. The output template
uses `"dynamic": "false_allow_templates"` so that only fields matching the
WCS schema are accepted, but mappings are created lazily (on first ingest).

Usage:
    python3 convert_to_dynamic_templates.py input_template.json [output_template.json]
"""

import json
import sys
import argparse
import copy
from collections import defaultdict

BASE_FIELDS = {"@timestamp"}
WILDCARD_MIN_FIELDS = 3

def flatten_properties(obj: dict, prefix: str = "") -> dict:
    """Recursively flatten a nested properties mapping."""
    result = {}
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if "properties" in value:
            result.update(flatten_properties(value["properties"], path))
        elif "type" in value:
            result[path] = copy.deepcopy(value)
    return result

def _suffix(path: str) -> str:
    return path.rsplit(".", 1)[-1]

def _safe_name(path: str) -> str:
    return path.replace(".", "_").replace("-", "_")

def build_dynamic_templates(flat: dict, object_names: set) -> list:
    """Produce an optimized dynamic_templates list using wildcard suffixes where possible."""
    suffix_type_map = defaultdict(lambda: defaultdict(list))
    for path, mapping in flat.items():
        if path in BASE_FIELDS:
            continue
        suffix_type_map[_suffix(path)][mapping["type"]].append(path)

    templates = []
    handled_paths = set()
    all_keyword_paths = set()

    # Process grouped suffixes
    for suffix, type_groups in sorted(suffix_type_map.items()):
        suffix_is_object = suffix in object_names

        if len(type_groups) == 1:
            typ = next(iter(type_groups))
            paths = type_groups[typ]

            if typ == "keyword":
                all_keyword_paths.update(paths)
                continue

            if len(paths) >= WILDCARD_MIN_FIELDS and not suffix_is_object:
                mapping = _representative_mapping(flat, paths)
                templates.append({
                    f"wcs_{typ}_{suffix}": {
                        "path_match": f"*.{suffix}",
                        "mapping": mapping,
                    }
                })
                handled_paths.update(paths)
            else:
                for p in sorted(paths):
                    templates.append({
                        f"wcs_{_safe_name(p)}": {
                            "path_match": p,
                            "mapping": flat[p],
                        }
                    })
                    handled_paths.add(p)
        else:
            for typ, paths in type_groups.items():
                if typ == "keyword":
                    all_keyword_paths.update(paths)
                    continue
                for p in sorted(paths):
                    templates.append({
                        f"wcs_{_safe_name(p)}": {
                            "path_match": p,
                            "mapping": flat[p],
                        }
                    })
                    handled_paths.add(p)

    # Handle remaining non-keyword fields
    for path, mapping in sorted(flat.items()):
        if path in handled_paths or path in BASE_FIELDS or path in all_keyword_paths:
            continue
        templates.append({
            f"wcs_{_safe_name(path)}": {
                "path_match": path,
                "mapping": mapping,
            }
        })
        handled_paths.add(path)

    # Process keyword fields (wildcards and exacts)
    kw_suffix_groups = defaultdict(list)
    for p in all_keyword_paths:
        kw_suffix_groups[_suffix(p)].append(p)

    kw_handled = set()
    for suffix, paths in sorted(kw_suffix_groups.items(), key=lambda x: -len(x[1])):
        if len(paths) >= WILDCARD_MIN_FIELDS and suffix not in object_names:
            templates.append({
                f"wcs_keyword_{suffix}": {
                    "path_match": f"*.{suffix}",
                    "mapping": {"type": "keyword", "ignore_above": 1024},
                }
            })
            kw_handled.update(paths)

    for p in sorted(all_keyword_paths - kw_handled):
        templates.append({
            f"wcs_{_safe_name(p)}": {
                "path_match": p,
                "mapping": {"type": "keyword", "ignore_above": 1024},
            }
        })

    return templates

def _representative_mapping(flat: dict, paths: list) -> dict:
    mappings = [flat[p] for p in paths]
    base = {"type": mappings[0]["type"]}
    extra_keys = set().union(*(m.keys() for m in mappings)) - {"type"}
    for key in extra_keys:
        values = [m.get(key) for m in mappings if key in m]
        if len(set(str(v) for v in values)) == 1 and len(values) == len(mappings):
            base[key] = values[0]
    return base

def _extract_object_tree(properties: dict) -> dict:
    result = {}
    for key, value in properties.items():
        if "properties" in value:
            result[key] = {"properties": _extract_object_tree(value["properties"])}
    return result

def _build_object_scaffolding(properties: dict, all_field_paths: set) -> dict:
    """Build intermediate object scaffolding needed by false_allow_templates."""
    result = _extract_object_tree(properties)
    for path in sorted(all_field_paths):
        parts = path.split(".")
        node = result
        for part in parts[:-1]:
            node = node.setdefault(part, {}).setdefault("properties", {})
    return result

def _collect_object_names(properties: dict) -> set:
    names = set()
    for key, value in properties.items():
        if "properties" in value:
            names.add(key)
            names.update(_collect_object_names(value["properties"]))
    return names

ENRICHMENT_TEMPLATES = [
    {"wcs_enrichment_indicator_id":         {"path_match": "enrichment.indicator.id",            "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_name":       {"path_match": "enrichment.indicator.name",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_type":       {"path_match": "enrichment.indicator.type",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_confidence": {"path_match": "enrichment.indicator.confidence",    "mapping": {"type": "long"}}},
    {"wcs_enrichment_indicator_first_seen": {"path_match": "enrichment.indicator.first_seen",    "mapping": {"type": "date"}}},
    {"wcs_enrichment_indicator_last_seen":  {"path_match": "enrichment.indicator.last_seen",     "mapping": {"type": "date"}}},
    {"wcs_enrichment_indicator_reference":  {"path_match": "enrichment.indicator.reference",     "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_tags":       {"path_match": "enrichment.indicator.tags",          "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_provider":   {"path_match": "enrichment.indicator.provider",      "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_software_type": {"path_match": "enrichment.indicator.software.type", "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_software_name": {"path_match": "enrichment.indicator.software.name", "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_software_alias": {"path_match": "enrichment.indicator.software.alias","mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_indicator_feed_name":  {"path_match": "enrichment.indicator.feed.name",     "mapping": {"type": "keyword", "ignore_above": 1024}}},
    {"wcs_enrichment_type":                 {"path_match": "enrichment.type",                    "mapping": {"type": "keyword", "ignore_above": 1024}}},
]

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
    output = copy.deepcopy(input_data)
    template_block = output.get("template", {})
    mappings = template_block.get("mappings", {})
    properties = mappings.get("properties", {})

    flat = flatten_properties(properties)
    flat = {k: v for k, v in flat.items() if not k.startswith("enrichments.custom.") and k != "enrichments.source"}
    
    object_names = _collect_object_names(properties)
    dynamic_templates = build_dynamic_templates(flat, object_names)
    
    all_field_paths = set(flat.keys())
    static_props = _build_object_scaffolding(properties, all_field_paths)

    # Swap enrichment namespaces
    static_props.pop("enrichments", None)
    static_props.update(copy.deepcopy(ENRICHMENT_SCAFFOLDING))

    for field in BASE_FIELDS:
        if field in properties:
            static_props[field] = properties[field]

    # Remove specific catch-all overlaps
    dynamic_templates = [
        t for t in dynamic_templates
        if not any(r.get("path_match", "").startswith(("check.", "policy.", "compliance.requirement.")) for r in t.values())
    ]

    CATCHALL_TEMPLATES = [
        {"wcs_policy_all":     {"path_match": "policy.*",       "mapping": {"type": "keyword", "ignore_above": 1024}}},
        {"wcs_check_all":      {"path_match": "check.*",        "mapping": {"type": "keyword", "ignore_above": 1024}}},
        {"wcs_compliance_all": {"path_match": "compliance.*.*", "mapping": {"type": "keyword", "ignore_above": 1024}}},
    ]

    if "compliance" in static_props:
        static_props["compliance"].setdefault("properties", {}).setdefault("requirement", {"properties": {}})

    all_dt = ENRICHMENT_TEMPLATES + CATCHALL_TEMPLATES + dynamic_templates

    template_block["mappings"] = {
        "date_detection": mappings.get("date_detection", False),
        "dynamic": "false_allow_templates",
        "dynamic_templates": all_dt,
        "properties": static_props,
    }

    return output

def main():
    parser = argparse.ArgumentParser(description="Convert static properties to dynamic_templates")
    parser.add_argument("input", help="Source JSON template")
    parser.add_argument("output", nargs="?", help="Output JSON template")
    parser.add_argument("--stats", action="store_true", help="Print stats to stderr")
    args = parser.parse_args()

    with open(args.input) as f:
        input_data = json.load(f)

    result = convert_template(input_data)

    if args.stats:
        flat = flatten_properties(input_data["template"]["mappings"]["properties"])
        dts = result["template"]["mappings"]["dynamic_templates"]
        n_wildcard = sum(1 for t in dts for v in t.values() if "*" in v.get("path_match", ""))
        print(f"[stats] Input leaf fields:  {len(flat)}", file=sys.stderr)
        print(f"[stats] Output templates:   {len(dts)}", file=sys.stderr)
        print(f"[stats] Wildcard templates: {n_wildcard}", file=sys.stderr)
        print(f"[stats] Compression ratio:  {len(flat)/len(dts):.1f}x", file=sys.stderr)

    output_json = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json + "\n")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output_json)

if __name__ == "__main__":
    main()