#!/usr/bin/env python3

# Generates the index templates that the integrations install on the destination
# platforms, from the Wazuh Common Schema (WCS) events and findings modules.
#
# The fields are never written by hand: they are read from the templates the WCS
# generator produces (wcs/stateless/events/{main,findings}), and converted to
# dynamic_templates with the WCS generator's own converter, as the setup plugin
# does for the source data streams. Only the settings and mapping types that the
# destination does not support are translated.
#
# Usage:
#   generate.py           write the templates
#   generate.py --check   fail if a committed template differs from the WCS modules

import argparse
import copy
import glob
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
WCS_EVENTS = os.path.join(REPO_ROOT, "wcs", "stateless", "events")
INTEGRATIONS = os.path.join(REPO_ROOT, "integrations")

sys.path.insert(0, os.path.join(REPO_ROOT, "wcs", "generator"))
from convert_to_dynamic_templates import convert_template  # noqa: E402

# WCS modules whose fields the exported documents can carry.
MODULES = ("main", "findings")


def load_wcs_template(module: str) -> dict:
    """Template the WCS generator produces for a module."""
    paths = glob.glob(os.path.join(WCS_EVENTS, module, "mappings", "*", "generated", "elasticsearch", "legacy", "template.json"))
    if len(paths) != 1:
        raise SystemExit(f"expected one generated template for the WCS module '{module}', found {len(paths)}")
    with open(paths[0]) as fd:
        return json.load(fd)


def merge_properties(target: dict, source: dict, path: str = "") -> dict:
    """Union of two properties trees. A field mapped differently in both is an error."""
    for name, mapping in source.items():
        field = f"{path}{name}"
        if name not in target:
            target[name] = copy.deepcopy(mapping)
        elif "properties" in mapping and "properties" in target[name]:
            merge_properties(target[name]["properties"], mapping["properties"], f"{field}.")
        elif target[name] != mapping:
            raise SystemExit(f"the WCS modules map '{field}' differently: {target[name]} and {mapping}")
    return target


def merge_settings(templates: list) -> dict:
    """Settings of the WCS templates, with the larger limits and every default query field."""
    settings = copy.deepcopy(templates[0]["settings"])
    index = settings["index"]
    for template in templates[1:]:
        other = template["settings"]["index"]
        index["max_docvalue_fields_search"] = max(index["max_docvalue_fields_search"], other["max_docvalue_fields_search"])
        index["query.default_field"] = sorted(set(index["query.default_field"]) | set(other["query.default_field"]))
    return settings


def wcs_template() -> dict:
    """WCS events and findings fields as one template, converted to dynamic_templates."""
    templates = [load_wcs_template(module) for module in MODULES]
    properties = {}
    for template in templates:
        merge_properties(properties, template["mappings"]["properties"])
    mappings = dict(templates[0]["mappings"], properties=properties)
    converted, _ = convert_template({"template": {"settings": merge_settings(templates), "mappings": mappings}})
    return converted["template"]


def destination_template(wcs: dict, mapping) -> dict:
    """
    Composable index template for the data streams an integration writes to,
    logs-wazuh.<kind>.<category>-<namespace>, with every field mapping passed through mapping().
    """
    settings = copy.deepcopy(wcs["settings"])
    # The source data streams are managed with an Index State Management policy of the Wazuh
    # indexer. Retention at the destination is up to its operator.
    for key in [k for k in settings if k.startswith("plugins.")]:
        del settings[key]
    # zstd needs the OpenSearch custom-codecs plugin. best_compression is available everywhere,
    # and Elasticsearch implements it with zstd.
    if settings["index"].get("codec") == "zstd":
        settings["index"]["codec"] = "best_compression"

    mappings = copy.deepcopy(wcs["mappings"])
    # dynamic_templates only apply with dynamic set to true. Fields outside WCS, such as those of
    # custom data streams, are mapped dynamically instead of being rejected.
    mappings["dynamic"] = True
    for rule in mappings["dynamic_templates"]:
        for body in rule.values():
            body["mapping"] = mapping(body["mapping"])

    return {
        "index_patterns": ["logs-wazuh.*-*"],
        "data_stream": {},
        "priority": 200,
        "_meta": {
            "description": "Wazuh events and findings exported from the Wazuh indexer. "
                           "Generated from the Wazuh Common Schema by integrations/tools/templates/generate.py.",
        },
        "template": {"settings": settings, "mappings": mappings},
    }


def elastic_mapping(mapping: dict) -> dict:
    """A WCS field mapping, in a form Elasticsearch supports: flat_object is OpenSearch's flattened."""
    if mapping.get("type") == "flat_object":
        return {"type": "flattened"}
    return mapping


def elastic_template(wcs: dict) -> dict:
    return destination_template(wcs, elastic_mapping)


def opensearch_template(wcs: dict) -> dict:
    return destination_template(wcs, lambda mapping: mapping)


TARGETS = {
    os.path.join(INTEGRATIONS, "elastic", "templates", "wazuh-index-template.json"): elastic_template,
    os.path.join(INTEGRATIONS, "opensearch", "templates", "wazuh-index-template.json"): opensearch_template,
}


def render(template: dict) -> str:
    return json.dumps(template, indent=2) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generates the integrations index templates from the WCS modules.")
    parser.add_argument("--check", action="store_true", help="Fail if a committed template is out of date.")
    args = parser.parse_args(argv)

    wcs = wcs_template()
    outdated = []
    for path, build in TARGETS.items():
        content = render(build(wcs))
        relative = os.path.relpath(path, REPO_ROOT)
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
        print("out of date with the WCS modules, run integrations/tools/templates/generate.py:", *outdated, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
