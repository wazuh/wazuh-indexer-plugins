#!/usr/bin/env python3
"""
Check that every changed index template carries the right schema versions.

The Setup plugin upgrades existing indices from the `schema_version` and `compat_version` each
template carries (see stamp_schema_versions.py). Nothing at runtime can verify that the values
were raised correctly when a template changed, so this check does it on every pull request:
it diffs each template under `plugins/setup/src/main/resources/templates/` (and the other
destinations of `wcs/module_list.txt`) against the base branch, classifies the change, and
fails when the versions do not match the classification.

Rules, per template:

  * The versions stamped in the template must match the `_meta` of the module's
    `fields/mapping-settings.json` (otherwise the template was not regenerated) and be
    consistent with each other.
  * If the mappings or settings changed, `schema_version` must be the number of the release
    the branch targets (`VERSION.json`). Two changes to the same template within one release
    cycle both carry that release's number, so only the first one has to raise it.
  * If the change is breaking, `compat_version` must be equal to the new `schema_version`.
    Breaking: a field removed, a field type or any other non-updatable parameter changed, an
    analyzer or normalizer changed, a static index setting changed, the index patterns or the
    data stream flag changed.
  * If only fields, multi-fields or dynamic templates were added, or dynamic settings changed,
    `compat_version` keeps its previous value.
  * If `schema_version` changed without any change to the template, a warning is reported.
  * Templates that did not change are not checked.
  * The ISM configuration template (`ism-config.json`) is not checked: the ISM plugin versions
    that mapping itself through its own `_meta.schema_version`, so it carries no Wazuh versions.

The classification is reported per template, in the GitHub job summary when run in a
workflow (`GITHUB_STEP_SUMMARY`) and on standard output otherwise.

Usage:
    python3 check_schema_versions.py [--base <git ref>] [--version <x.y.z>]

    --base      git ref to compare against (default: origin/<BASE_BRANCH> or origin/main); the
                templates are read at the merge base of HEAD and this ref, as GitHub's diff does
    --version   release the branch targets (default: the "version" of VERSION.json)
"""

import argparse
import json
import os
import re
import subprocess
import sys

from stamp_schema_versions import (
    META_KEY,
    RESOURCES_PATH,
    load_module_map,
    load_versions,
    release_number,
    repository_root,
    template_path,
)

TEMPLATES_DIR = os.path.join(RESOURCES_PATH, "templates")

# Templates left out of the schema versioning, relative to the templates directory.
EXCLUDED_TEMPLATES = frozenset({"ism-config.json"})

# Field parameters that OpenSearch lets a mapping update change on an existing field. A change
# to any other parameter of an existing field needs a new index.
UPDATABLE_FIELD_PARAMETERS = frozenset({"ignore_above", "search_analyzer", "meta"})

# Index settings that cannot be changed on an open index. Written without the "index." prefix.
# Everything else in the shipped templates is dynamic and reaches an existing index in place.
# The prefixes cover the analysis chain (custom analyzers and normalizers), the codec options,
# soft deletes, index sorting and the store type.
STATIC_SETTINGS = frozenset(
    {
        "codec",
        "load_fixed_bitset_filters_eagerly",
        "number_of_routing_shards",
        "number_of_shards",
        "routing_partition_size",
        "shard.check_on_startup",
    }
)
STATIC_SETTING_PREFIXES = ("analysis.", "codec.", "soft_deletes.", "sort.", "store.")

# Mapping keys handled on their own; every other top-level mapping key (dynamic, date_detection,
# numeric_detection, dynamic_date_formats) is updatable.
STRUCTURAL_MAPPING_KEYS = frozenset({"properties", "dynamic_templates", "_meta"})

OK, WARN, FAIL = "ok", "warn", "fail"


# ---- template reading -----------------------------------------------------------------------


def git_show(root, ref, path):
    """Return the parsed JSON of a file at a git ref, or None when it does not exist there."""
    result = subprocess.run(
        ["git", "-C", root, "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def fork_point(root, base_ref):
    """Return the merge base of HEAD and base_ref, the commit GitHub diffs a pull request against.

    A change that reached the base branch after this branch was cut is not part of the pull
    request, so comparing with the tip of the base branch would misreport it.
    """
    result = subprocess.run(
        ["git", "-C", root, "merge-base", "HEAD", base_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.exit(f"Error: cannot find the merge base of HEAD and {base_ref}: {result.stderr.strip()}")
    return result.stdout.strip()


def read_versions(template):
    """Return (version, schema_version, compat_version) as stored in a template, any may be None."""
    meta = template.get("template", {}).get("mappings", {}).get(META_KEY, {})
    if not isinstance(meta, dict):
        meta = {}
    return template.get("version"), meta.get("schema_version"), meta.get("compat_version")


def list_templates(root, modules):
    """Return {path: module or None} for every template the check covers."""
    templates = {}
    for module, destination in modules.items():
        path = os.path.relpath(template_path(root, destination), root)
        templates[path] = module
    templates_dir = os.path.join(root, TEMPLATES_DIR)
    for current, _dirs, files in os.walk(templates_dir):
        for name in sorted(files):
            if name.endswith(".json"):
                path = os.path.relpath(os.path.join(current, name), root)
                if os.path.relpath(os.path.join(current, name), templates_dir) in EXCLUDED_TEMPLATES:
                    continue
                templates.setdefault(path, None)
    return dict(sorted(templates.items()))


# ---- classification -------------------------------------------------------------------------


def flatten_fields(mappings):
    """Return {path: definition} for every leaf field, from properties and dynamic templates.

    Multi-fields are listed as their own path (`name.keyword`) and removed from the parent's
    definition, so that adding one is an addition rather than a change to the parent.
    """
    fields = {}

    def add_leaf(path, definition):
        definition = dict(definition)
        for sub_name, sub_definition in (definition.pop("fields", None) or {}).items():
            add_leaf(f"{path}.{sub_name}", sub_definition)
        fields[path] = definition

    def walk(properties, prefix):
        for name, definition in (properties or {}).items():
            path = f"{prefix}{name}"
            if isinstance(definition, dict) and "properties" in definition:
                walk(definition["properties"], f"{path}.")
                container = {k: v for k, v in definition.items() if k != "properties"}
                if container:
                    fields[path] = container
            elif isinstance(definition, dict):
                add_leaf(path, definition)

    walk(mappings.get("properties"), "")
    for entry in mappings.get("dynamic_templates") or []:
        for name, rule in entry.items():
            path = rule.get("path_match")
            if isinstance(path, str):
                # Several rules can share a path and differ in match_mapping_type: keep each apart.
                conditions = {k: v for k, v in rule.items() if k not in ("path_match", "mapping")}
                if conditions:
                    path = f"{path} {json.dumps(conditions, sort_keys=True)}"
                add_leaf(path, rule.get("mapping", {}))
            else:
                fields[f"dynamic_template:{name}"] = rule
    return fields


def flatten_settings(settings, prefix=""):
    """Return {dotted key: value} for a settings block, without the leading "index." prefix."""
    flat = {}
    for key, value in (settings or {}).items():
        full = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten_settings(value, f"{full}."))
        else:
            flat[full[len("index.") :] if full.startswith("index.") else full] = value
    return flat


def is_static_setting(key):
    return key in STATIC_SETTINGS or key.startswith(STATIC_SETTING_PREFIXES)


def updatable_difference(old, new):
    """True when two field definitions differ only in parameters a mapping update can change."""
    strip = lambda d: {k: v for k, v in d.items() if k not in UPDATABLE_FIELD_PARAMETERS}
    return strip(old) == strip(new)


def classify(base, head):
    """Compare two templates. Returns (changed, breaking_reasons, compatible_reasons)."""
    breaking, compatible = [], []

    if base.get("index_patterns") != head.get("index_patterns"):
        breaking.append("index_patterns changed")
    if ("data_stream" in base) != ("data_stream" in head):
        breaking.append("data_stream changed")
    if base.get("priority") != head.get("priority"):
        compatible.append("priority changed")

    base_fields = flatten_fields(base.get("template", {}).get("mappings", {}))
    head_fields = flatten_fields(head.get("template", {}).get("mappings", {}))
    for path in sorted(base_fields):
        if path not in head_fields:
            breaking.append(f"field removed: {path}")
        elif base_fields[path] != head_fields[path]:
            if updatable_difference(base_fields[path], head_fields[path]):
                compatible.append(f"field parameter changed: {path}")
            else:
                breaking.append(f"field changed: {path}")
    for path in sorted(head_fields):
        if path not in base_fields:
            compatible.append(f"field added: {path}")

    base_mappings = base.get("template", {}).get("mappings", {})
    head_mappings = head.get("template", {}).get("mappings", {})
    for key in sorted(set(base_mappings) | set(head_mappings)):
        if key not in STRUCTURAL_MAPPING_KEYS and base_mappings.get(key) != head_mappings.get(key):
            compatible.append(f"mapping setting changed: {key}")

    base_settings = flatten_settings(base.get("template", {}).get("settings"))
    head_settings = flatten_settings(head.get("template", {}).get("settings"))
    for key in sorted(set(base_settings) | set(head_settings)):
        if base_settings.get(key) != head_settings.get(key):
            if is_static_setting(key):
                breaking.append(f"static setting changed: {key}")
            else:
                compatible.append(f"dynamic setting changed: {key}")

    return bool(breaking or compatible), breaking, compatible


# ---- rules ----------------------------------------------------------------------------------


def evaluate(base, head, target, declared=None):
    """Apply the rules to one template.

    Returns (status, change, reasons): status is OK, WARN or FAIL; change is "new", "none",
    "compatible" or "breaking"; reasons is the list of lines to report. `declared` is the
    (schema_version, compat_version) pair from the module's mapping-settings.json, when the
    template belongs to a module.
    """
    reasons = []
    version, schema, compat = read_versions(head)
    for name, value in (("version", version), ("schema_version", schema), ("compat_version", compat)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return FAIL, "unknown", [f"{name} is missing or not a positive integer"]
    if version != schema:
        return FAIL, "unknown", [f"version ({version}) differs from schema_version ({schema})"]
    if compat > schema:
        return FAIL, "unknown", [f"compat_version ({compat}) is greater than schema_version ({schema})"]
    if declared is not None and (schema, compat) != declared:
        return FAIL, "unknown", [
            f"template carries {schema}/{compat} but mapping-settings.json declares "
            f"{declared[0]}/{declared[1]}: regenerate the module"
        ]

    if base is None:
        if schema != target:
            return FAIL, "new", [f"new template must carry schema_version {target}, found {schema}"]
        return OK, "new", [f"new template at schema_version {schema}"]

    changed, breaking, compatible = classify(base, head)
    _, base_schema, base_compat = read_versions(base)

    if not changed:
        if schema != base_schema or compat != base_compat:
            return WARN, "none", [
                f"versions changed ({base_schema}/{base_compat} to {schema}/{compat}) "
                "but the template did not"
            ]
        return OK, "none", ["unchanged"]

    change = "breaking" if breaking else "compatible"
    reasons.extend(breaking)
    reasons.extend(compatible)
    status = OK
    if schema != target:
        status = FAIL
        reasons.insert(0, f"template changed: schema_version must be {target}, found {schema}")
    if breaking and compat != schema:
        status = FAIL
        reasons.insert(0, f"breaking change: compat_version must be {schema}, found {compat}")
    if not breaking and compat != base_compat:
        status = FAIL
        reasons.insert(0, f"compatible change: compat_version must stay at {base_compat}, found {compat}")
    return status, change, reasons


# ---- reporting ------------------------------------------------------------------------------


def write_summary(rows, target):
    """Print the per-template report, as a Markdown table in the job summary when available."""
    lines = [
        f"### Schema versions (target release {target})",
        "",
        "| Template | Change | schema_version | compat_version | Result |",
        "|---|---|---|---|---|",
    ]
    for path, status, change, schema, compat, reasons in rows:
        detail = "<br>".join(reasons[:6]) + ("<br>..." if len(reasons) > 6 else "")
        lines.append(f"| `{path}` | {change} | {schema} | {compat} | {status}: {detail} |")
    text = "\n".join(lines) + "\n"

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    for path, status, change, _schema, _compat, reasons in rows:
        if status == OK and change == "none":
            continue
        print(f"[{status.upper()}] {path} ({change})")
        for reason in reasons:
            print(f"    {reason}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", help="git ref to compare against")
    parser.add_argument("--version", help="release the branch targets, as x.y.z")
    args = parser.parse_args()

    root = repository_root()
    base = fork_point(root, args.base or f"origin/{os.environ.get('BASE_BRANCH', 'main')}")
    if args.version:
        target_version = args.version
    else:
        with open(os.path.join(root, "VERSION.json"), encoding="utf-8") as handle:
            target_version = json.load(handle)["version"]
    target = release_number(target_version)

    modules = load_module_map(root)
    rows = []
    failed = False
    for path, module in list_templates(root, modules).items():
        with open(os.path.join(root, path), encoding="utf-8") as handle:
            head = json.load(handle)
        base_template = git_show(root, base, path)
        declared = None
        if module is not None:
            try:
                declared = load_versions(root, module)
            except ValueError as error:
                rows.append((path, FAIL, "unknown", "-", "-", [str(error)]))
                failed = True
                continue
        status, change, reasons = evaluate(base_template, head, target, declared)
        _, schema, compat = read_versions(head)
        rows.append((path, status, change, schema, compat, reasons))
        failed = failed or status == FAIL

    write_summary(rows, target_version)
    if failed:
        sys.exit("Error: some index templates do not carry the right schema versions")


if __name__ == "__main__":
    main()
