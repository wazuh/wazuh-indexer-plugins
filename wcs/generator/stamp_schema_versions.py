#!/usr/bin/env python3
"""
Stamp a WCS module's schema versions into its generated index template.

Every module declares two release numbers under `_meta.wazuh` in `fields/mapping-settings.json`:

  * `schema_version`: the release that last changed the mappings or settings of the template.
  * `compat_version`: the oldest `schema_version` whose indices can still be upgraded in
    place. It equals `schema_version` when the last change was breaking (a field removed, a
    field type changed, an analyzer changed, a static index setting changed).

A release number is the release version with one digit for the major and two digits each for
the minor and the patch, so that numeric order matches release order: 5.0.0 is 50000, 5.2.1 is
50201 and 5.10.14 is 51014.

The generator carries `_meta` into the mappings of the generated template as it is, so every
index created from the template inherits the two numbers in its own mapping metadata, where
the Setup plugin reads them on later boots. This script completes the generated template under
`plugins/setup/src/main/resources/` (or wherever `module_list.txt` sends it):

  * `schema_version` as the native `version` field of the composable index template, which
    the generator does not produce;
  * both under `template.mappings._meta.wazuh`, again, so that a template whose mappings were
    edited by hand still matches the module.

`generate_schema.sh` runs this for every regenerated module. Run it with `all` to stamp every
module, which is also how to check that none has drifted (`--check`).

Usage:
    python3 stamp_schema_versions.py <module|all> [--check]

    --check    report the templates that would change and exit 1 if any would, without writing
"""

import argparse
import json
import os
import re
import sys

VERSION_FILE = "mapping-settings.json"
META_KEY = "_meta"
META_WAZUH_KEY = "wazuh"
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
    pattern = re.compile(r"^\s*\[(?P<module>[^\]]+)\]=(?P<file>\S*)\s*$")
    with open(module_list, encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line)
            if match and match.group("file"):
                modules[match.group("module")] = match.group("file")
    return modules


def template_path(root, destination):
    """Resolve a module_list.txt destination to a path: bare names live under the setup resources."""
    if destination.startswith("plugins/"):
        return os.path.join(root, destination)
    return os.path.join(root, RESOURCES_PATH, destination)


def release_number(version):
    """Convert a release version such as 5.2.1 to its five-digit number, 50201."""
    match = re.fullmatch(r"(\d+)\.(\d{1,2})\.(\d{1,2})", version.strip())
    if not match:
        raise ValueError(f"'{version}' is not a release version of the form major.minor.patch")
    major, minor, patch = (int(part) for part in match.groups())
    return major * 10000 + minor * 100 + patch


def load_versions(root, module):
    """Read and validate the versions a module's mapping-settings.json declares under _meta.wazuh.

    Returns (schema_version, compat_version).
    """
    path = os.path.join(root, "wcs", module, "fields", VERSION_FILE)
    if not os.path.isfile(path):
        raise ValueError(f"module '{module}' has no fields/{VERSION_FILE}")
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    source = f"wcs/{module}/fields/{VERSION_FILE}"
    meta = data.get(META_KEY) if isinstance(data, dict) else None
    wazuh = meta.get(META_WAZUH_KEY) if isinstance(meta, dict) else None
    if wazuh is None:
        raise ValueError(f"{source}: declares no {META_KEY}.{META_WAZUH_KEY} object")
    return validate_versions(wazuh, f"{source}: {META_KEY}.{META_WAZUH_KEY}")


def validate_versions(data, source):
    """Check the shape of a versions object and return (schema_version, compat_version)."""
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected an object")
    for key in ("schema_version", "compat_version"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{source}: '{key}' must be a positive integer")
    schema, compat = data["schema_version"], data["compat_version"]
    if compat > schema:
        raise ValueError(
            f"{source}: compat_version ({compat}) cannot be greater than schema_version ({schema})"
        )
    return schema, compat


def stamp(template, schema, compat):
    """Write the versions into a template document in place. Returns True when it changed."""
    before = json.dumps(template, sort_keys=True)
    template["version"] = schema
    mappings = template.setdefault("template", {}).setdefault("mappings", {})
    meta = mappings.setdefault(META_KEY, {})
    meta[META_WAZUH_KEY] = {"schema_version": schema, "compat_version": compat}
    return json.dumps(template, sort_keys=True) != before


def stamp_module(root, module, destination, check):
    """Stamp one module's template. Returns True when the file changed or would change."""
    schema, compat = load_versions(root, module)
    path = template_path(root, destination)
    if not os.path.isfile(path):
        raise ValueError(f"module '{module}' has no generated template at {destination}")
    with open(path, encoding="utf-8") as handle:
        template = json.load(handle)

    changed = stamp(template, schema, compat)
    if changed and not check:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(template, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("module", help="module name as in wcs/module_list.txt, or 'all'")
    parser.add_argument("--check", action="store_true", help="report without writing; exit 1 on drift")
    args = parser.parse_args()

    root = repository_root()
    modules = load_module_map(root)
    if args.module != "all":
        if args.module not in modules:
            sys.exit(f"Error: module '{args.module}' is not in wcs/module_list.txt")
        modules = {args.module: modules[args.module]}

    drifted = []
    for module, destination in sorted(modules.items()):
        try:
            if stamp_module(root, module, destination, args.check):
                drifted.append(module)
                print(f"  - {module}: {'would change' if args.check else 'stamped'}")
            else:
                print(f"  - {module}: up to date")
        except ValueError as error:
            sys.exit(f"Error: {error}")

    if args.check and drifted:
        sys.exit(1)


if __name__ == "__main__":
    main()
