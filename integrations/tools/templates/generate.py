#!/usr/bin/env python3

# Generates the index templates that the integrations install on the destination
# platforms, from the Wazuh Common Schema (WCS) events and findings modules.
#
# The fields are never written by hand: they are read from the index templates the setup
# plugin installs for the source data streams (wazuh-events-v5-* and wazuh-findings-v5-*),
# which hold the WCS events and findings modules as dynamic_templates. Only the settings
# and mapping types that the destination does not support are translated.
#
# Usage:
#   generate.py           write the templates
#   generate.py --check   fail if a committed template differs from the WCS modules

import argparse
import copy
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
STREAM_TEMPLATES = os.path.join(REPO_ROOT, "plugins", "setup", "src", "main", "resources", "templates", "streams")
INTEGRATIONS = os.path.join(REPO_ROOT, "integrations")

# Index templates of the setup plugin whose fields the exported documents can carry.
SOURCES = ("findings", "events")


def load_source_template(name: str) -> dict:
    """Index template the setup plugin installs for a kind of source data stream."""
    with open(os.path.join(STREAM_TEMPLATES, f"{name}.json")) as fd:
        return json.load(fd)["template"]


def merge_properties(target: dict, source: dict, path: str = "") -> dict:
    """Union of two properties trees. A field mapped differently in both is an error."""
    for name, mapping in source.items():
        field = f"{path}{name}"
        if name not in target:
            target[name] = copy.deepcopy(mapping)
        elif "properties" in mapping and "properties" in target[name]:
            merge_properties(target[name]["properties"], mapping["properties"], f"{field}.")
        elif target[name] != mapping:
            raise SystemExit(f"the source templates map '{field}' differently: {target[name]} and {mapping}")
    return target


def merge_dynamic_templates(target: list, source: list) -> list:
    """Union of two dynamic_templates lists, by name. A rule defined differently in both is an error."""
    rules = {next(iter(rule)): rule for rule in target}
    for rule in source:
        name = next(iter(rule))
        if name not in rules:
            rules[name] = copy.deepcopy(rule)
            target.append(rules[name])
        elif rules[name] != rule:
            raise SystemExit(f"the source templates define the dynamic template '{name}' differently")
    return target


def merge_settings(templates: list) -> dict:
    """Settings of the source templates, with the larger limits and every default query field."""
    settings = copy.deepcopy(templates[0]["settings"])
    index = settings["index"]
    for template in templates[1:]:
        other = template["settings"]["index"]
        index["max_docvalue_fields_search"] = max(index["max_docvalue_fields_search"], other["max_docvalue_fields_search"])
        index["query.default_field"] = sorted(set(index["query.default_field"]) | set(other["query.default_field"]))
    return settings


def wcs_template() -> dict:
    """WCS events and findings fields as one template, as dynamic_templates."""
    templates = [load_source_template(name) for name in SOURCES]
    properties, dynamic_templates = {}, []
    for template in templates:
        merge_properties(properties, template["mappings"]["properties"])
        merge_dynamic_templates(dynamic_templates, template["mappings"]["dynamic_templates"])
    mappings = dict(templates[0]["mappings"], properties=properties, dynamic_templates=dynamic_templates)
    return {"settings": merge_settings(templates), "mappings": mappings}


def destination_template(wcs: dict, mapping) -> dict:
    """
    Composable index template for the data streams an integration writes to,
    logs-wazuh.<kind>.<category>-<namespace>, with every field mapping passed through mapping().
    """
    settings = copy.deepcopy(wcs["settings"])
    # The source data streams are managed with an Index State Management policy of the Wazuh
    # indexer. The destination has its own lifecycle: see elastic_template, and the ISM policy
    # of the OpenSearch integration.
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
    template = destination_template(wcs, elastic_mapping)
    # The template takes over the logs-*-* names from the built-in logs template (priority 100),
    # so it composes the same component templates: logs@mappings (data_stream.* as
    # constant_keyword) and logs@settings (the logs lifecycle policy: rollover, no deletion).
    # logs-wazuh@custom, created by the operator, overrides any of them, and survives the
    # template being installed again.
    template["composed_of"] = ["logs@mappings", "logs@settings", "logs-wazuh@custom"]
    template["ignore_missing_component_templates"] = ["logs-wazuh@custom"]
    return template


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
