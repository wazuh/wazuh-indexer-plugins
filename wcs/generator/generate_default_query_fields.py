#!/usr/bin/env python3
"""
Derive the `index.query.default_field` list of a WCS index template from its own mapping.

`index.query.default_field` is the list of fields a `query_string` with no field qualifier
searches. Hand-written lists drift away from the mapping they are supposed to describe: they
keep names the mapping never had, name fields whose type cannot accept a text term (a
non-lenient `query_string` then throws a `query_shard_exception` instead of returning
results) and carry stray whitespace that stops an entry resolving at all.

This script rewrites the list from the mapping the same template declares, so all three
defects are impossible by construction:

  * only fields of the text family (`keyword`, `text`, `match_only_text`, `wildcard`) are
    kept, and only if they are indexed (`index: false` cannot be searched);
  * every entry is trimmed;
  * when a field exists both bare and under the `wazuh.` prefix, only the `wazuh.` one is
    kept: that is the branch the agent data actually populates.

How much of the mapping is used depends on whether the mapping is closed:

  * A closed mapping (`dynamic: strict` and no `dynamic_templates`) describes every field
    the index can ever hold, so the list is the full set of its searchable text fields.
    This is the case of the `wazuh-states-*` templates.
  * An open mapping (`strict_allow_templates`, `dynamic: true`/`false`, or any mapping with
    `dynamic_templates`) reaches far more fields than the mapping spells out - the
    `wazuh-events`/`wazuh-findings` streams reach over 1600 text fields through their
    dynamic templates. Listing them all would push a single-term query past the field
    expansion limit and make it needlessly expensive, so the curated list is kept and each
    of its entries is only resolved against the mapping: trimmed, moved to its `wazuh.`
    twin when that is the reachable one, and dropped when it resolves to nothing searchable.

The derived list is written to the module's index template under
`plugins/setup/src/main/resources/` and back to the `fields/template-settings.json` and
`fields/template-settings-legacy.json` the generator feeds to the ECS tooling, so the next
generation starts from the corrected list. Only the `query.default_field` array is
rewritten; the rest of every file is left byte for byte as it was.

Usage:
    python3 generate_default_query_fields.py <module|all> [--check] [--verbose]

    --check    report what would change and exit 1 if anything would, without writing
    --verbose  list the entries added and removed
"""

import argparse
import json
import os
import re
import sys

# Field types a text term can be queried against. A `default_field` entry of any other type
# makes a non-lenient query_string fail on the whole shard.
TEXT_FAMILY = frozenset({"keyword", "match_only_text", "text", "wildcard"})

# The branch the agent data is written to. Preferred over the bare name whenever both exist.
WAZUH_PREFIX = "wazuh."

SETTING = "query.default_field"

RESOURCES_PATH = "plugins/setup/src/main/resources"


def repository_root():
    """Walk up from this script until the repository root (the folder holding .github)."""
    path = os.path.dirname(os.path.realpath(__file__))
    while path != "/" and not os.path.isdir(os.path.join(path, ".github")):
        path = os.path.dirname(path)
    if path == "/":
        sys.exit("Error: Unable to find the repository root.")
    return path


def load_module_map(root):
    """Read the module -> index template map from wcs/module_list.txt."""
    module_list = os.path.join(root, "wcs", "module_list.txt")
    if not os.path.isfile(module_list):
        sys.exit(f"Error: Module list file not found at {module_list}")

    modules = {}
    with open(module_list) as handle:
        for line in handle:
            match = re.match(r"\s*\[([^\]]+)\]=(.*)$", line)
            if match:
                modules[match.group(1)] = match.group(2).strip().strip('"')
    if not modules:
        sys.exit(f"Error: No modules found in {module_list}")
    return modules


def flatten_properties(properties, prefix=""):
    """
    Flatten a mapping `properties` block into {"full.path": mapping_body}.

    Multi-fields are emitted under the path they are queried by (`file.path.text` for a
    `text` multi-field of `file.path`), not under the `fields` key that declares them.
    """
    flat = {}
    for name, body in (properties or {}).items():
        path = f"{prefix}{name}"
        if "properties" in body:
            flat.update(flatten_properties(body["properties"], f"{path}."))
        if body.get("type"):
            flat[path] = body
        for sub_name, sub_body in (body.get("fields") or {}).items():
            if sub_body.get("type"):
                flat[f"{path}.{sub_name}"] = sub_body
    return flat


def flatten_dynamic_templates(dynamic_templates):
    """
    Flatten the dynamic templates of a mapping into {"full.path": mapping_body}.

    Only rules whose `path_match` is a literal path are usable: a pattern holding a wildcard
    names a family of fields rather than one field, so it cannot go in `default_field`.
    """
    flat = {}
    for rule in dynamic_templates or []:
        for body in rule.values():
            path = body.get("path_match")
            mapping = body.get("mapping") or {}
            if path and "*" not in path and mapping.get("type"):
                flat[path] = mapping
    return flat


def is_searchable(body):
    """True when a text term can be queried against this field."""
    return body.get("type") in TEXT_FAMILY and body.get("index", True) is not False


def searchable_fields(mappings):
    """The set of field paths of the mapping a text term can be queried against."""
    # A static property overrides the dynamic template that would otherwise map the path.
    fields = flatten_dynamic_templates(mappings.get("dynamic_templates"))
    fields.update(flatten_properties(mappings.get("properties")))
    return {path for path, body in fields.items() if is_searchable(body)}


def is_closed(mappings):
    """
    True when the mapping describes every field the index can hold.

    Only a strict mapping with no dynamic templates is closed: any other `dynamic` value, and
    any dynamic template, lets in fields the `properties` block does not spell out.
    """
    return mappings.get("dynamic") == "strict" and not mappings.get("dynamic_templates")


def resolve(entry, searchable):
    """
    Resolve one curated entry to the field of the mapping it means, or None.

    The entry is trimmed, and its `wazuh.` twin wins over the bare name whenever the mapping
    has it: `agent.id` and `wazuh.agent.id` are both real fields of the event streams, but
    only the second is the one the agent data fills in.
    """
    name = entry.strip()
    if not name:
        return None
    if not name.startswith(WAZUH_PREFIX) and WAZUH_PREFIX + name in searchable:
        return WAZUH_PREFIX + name
    return name if name in searchable else None


def derive(mappings, current):
    """Derive the `default_field` list of a template from its mapping and its current list."""
    searchable = searchable_fields(mappings)

    if is_closed(mappings):
        selected = set(searchable)
    else:
        selected = set()
        for entry in current:
            resolved = resolve(entry, searchable)
            if resolved:
                selected.add(resolved)

    # Drop a bare name whose `wazuh.` twin is searchable too, so only the populated one is left.
    return sorted(path for path in selected if WAZUH_PREFIX + path not in searchable)


def find_setting_array(text):
    """
    Locate the `query.default_field` array in a JSON document, as text.

    Returns (indent, start, end) with the span of the array literal, or None when the
    document does not set it. The array is edited in place, as text, so that reformatting
    never leaks into the diff of files this script is not meant to reshape.
    """
    key = re.search(rf'^([ \t]*)"{re.escape(SETTING)}"\s*:\s*', text, re.MULTILINE)
    if not key or key.end() >= len(text) or text[key.end()] != "[":
        return None

    start = key.end()
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return key.group(1), start, index + 1
    raise ValueError(f"Unterminated {SETTING} array")


def declares_setting(document):
    """True when a template or a template-settings document sets `query.default_field`."""
    # The composable form nests the settings under `template`; the legacy form does not.
    block = document.get("template", document)
    return SETTING in ((block.get("settings") or {}).get("index") or {})


def render_array(entries, indent):
    """Render the array literal with the indentation of the key that holds it."""
    if not entries:
        return "[]"
    inner = indent + "  "
    body = ",\n".join(f"{inner}{json.dumps(entry)}" for entry in entries)
    return f"[\n{body}\n{indent}]"


def rewrite(path, entries, apply_changes):
    """
    Replace the `query.default_field` array of a JSON file with `entries`.

    Returns (changed, current) where `current` is the list the file held, or (False, None)
    when the file does not set `default_field` at all.
    """
    with open(path) as handle:
        text = handle.read()

    span = find_setting_array(text)
    if span is None:
        # A file that sets the list in a shape the text scan cannot reach (inline, or as a
        # bare string) would otherwise be reported as needing no change, and quietly keep a
        # list that is not the derived one.
        if declares_setting(json.loads(text)):
            raise ValueError(f"{path}: sets {SETTING} in a shape this script cannot rewrite")
        return False, None

    indent, start, end = span
    current = json.loads(text[start:end])
    if current == entries:
        return False, current

    updated = text[:start] + render_array(entries, indent) + text[end:]

    # Parse the result to be sure the surgery left valid JSON holding exactly the new list.
    json.loads(updated)
    _, new_start, new_end = find_setting_array(updated)
    if json.loads(updated[new_start:new_end]) != entries:
        raise ValueError(f"{path}: rewrite did not produce the derived list")

    if apply_changes:
        with open(path, "w") as handle:
            handle.write(updated)
    return True, current


def process_module(root, module, template_file, apply_changes, verbose):
    """Derive and write the `default_field` list of one module. Returns True when it changed."""
    # A module list entry that is already a repo-relative path names a template another plugin
    # consumes; a bare filename is one of the setup plugin's own resources.
    if not template_file.startswith("plugins/"):
        template_file = f"{RESOURCES_PATH}/{template_file}"
    template_path = os.path.join(root, template_file)
    if not os.path.isfile(template_path):
        print(f"Warning: Index template not found at {template_path}", file=sys.stderr)
        return False

    with open(template_path) as handle:
        template = json.load(handle)

    # The composable form nests the mapping under `template`; the legacy form does not.
    block = template.get("template", template)
    mappings = block.get("mappings") or {}
    settings = (block.get("settings") or {}).get("index") or {}
    current = settings.get(SETTING)

    if current is None:
        return False
    if not isinstance(current, list):
        print(
            f"Warning: {template_path} sets {SETTING} to a {type(current).__name__}, not a list",
            file=sys.stderr,
        )
        return False
    if not mappings:
        print(f"Warning: {template_path} sets {SETTING} but declares no mapping", file=sys.stderr)
        return False

    entries = derive(mappings, current)
    if not entries:
        print(
            f"Warning: {module}: no searchable field derived, leaving {SETTING} untouched",
            file=sys.stderr,
        )
        return False

    shape = "closed" if is_closed(mappings) else "open"
    print(f"Module: {module}")
    print(f"Index template: {os.path.relpath(template_path, root)}")
    print(f"Mapping: {shape} (dynamic={mappings.get('dynamic')})")
    print(f"{SETTING}: {len(current)} -> {len(entries)}")
    if verbose:
        removed = sorted(set(current) - set(entries))
        added = sorted(set(entries) - set(current))
        if removed:
            print("  removed: " + ", ".join(json.dumps(entry) for entry in removed))
        if added:
            print("  added:   " + ", ".join(added))

    changed = False
    targets = [template_path]
    for name in ("template-settings.json", "template-settings-legacy.json"):
        targets.append(os.path.join(root, "wcs", module, "fields", name))

    for target in targets:
        if not os.path.isfile(target):
            print(f"Skipping missing file: {os.path.relpath(target, root)}", file=sys.stderr)
            continue
        target_changed, target_current = rewrite(target, entries, apply_changes)
        if target_current is None:
            print(
                f"Skipping {os.path.relpath(target, root)}: does not set {SETTING}",
                file=sys.stderr,
            )
            continue
        if target_changed:
            changed = True
            verb = "Would update" if not apply_changes else "Updated"
            print(f"{verb} {os.path.relpath(target, root)}")

    if not changed:
        print("Already derived from the mapping. No changes.")
    print()
    return changed


def main():
    parser = argparse.ArgumentParser(
        description="Derive index.query.default_field from the mapping of a WCS index template."
    )
    parser.add_argument("module", help="Module to process, or 'all' for every module")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would change and exit 1 if anything would, without writing",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="list the entries added and removed"
    )
    args = parser.parse_args()

    root = repository_root()
    modules = load_module_map(root)

    if args.module == "all":
        selected = sorted(modules)
    elif args.module in modules:
        selected = [args.module]
    else:
        sys.exit(f"Error: Unknown module '{args.module}'. See {root}/wcs/module_list.txt")

    changed = []
    for module in selected:
        template_file = modules[module]
        if not template_file:
            continue
        if process_module(root, module, template_file, not args.check, args.verbose):
            changed.append(module)

    if args.check:
        if changed:
            print(f"{len(changed)} module(s) out of sync: {', '.join(changed)}", file=sys.stderr)
            return 1
        print("Every default_field list is derived from its mapping.")
        return 0

    print(f"Done. {len(changed)} module(s) updated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
