---
name: wcs-management
description: Maintain and create Wazuh Common Schema (WCS) modules under wcs/ in wazuh-indexer-plugins. Use when asked to add a field to a WCS module, change a module's index/template settings, create a new WCS module, or regenerate WCS index templates. Covers the module anatomy, the ECS-subset + custom-field YAML dialect, the 3-step Docker generator pipeline (update_module_list.sh, generate_schema.sh, count_and_update_total_fields.sh), and the out-of-tree wiring (SetupPlugin.java, module_list). Never hand-edit generated templates.
---

# WCS module management

The `wcs/` tree holds the Wazuh Common Schema: ~40 modules, each a folder of
hand-authored **inputs** (subset + custom fields + settings) whose OpenSearch
**index templates are generated**, never written by hand. This skill drives
three recurring tasks:

- **A** — add a field to an existing module
- **B** — change a module's settings
- **C** — create a new module

Companion file: `REFERENCE.md` — module anatomy, copy-paste YAML/JSON
templates, generator internals, README rules, and gotchas. Read it before
authoring field or settings files.

## Hard rule: never hand-edit generated files

Edit only the inputs. These are **generated** — the pipeline overwrites them,
so any manual edit is lost and wrong:

- `wcs/<module>/mappings/**` (the whole tree)
- `plugins/setup/src/main/resources/templates/**` (copied index templates)
- `plugins/content-manager/src/main/resources/mappings/internal-state-mapping.json`
- `wcs/<module>/docs/fields.csv`

You edit: `fields/subset.yml`, `fields/custom/*.yml`,
`fields/mapping-settings.json`, `fields/template-settings.json`,
`fields/template-settings-legacy.json`, and the hand-written `docs/README.md`.

## Locating a module

**The user normally gives the full module path and target location up front**
— e.g. "I want module `stateless/test `, output under
`wcs/stateless/test`". Take that as the module path directly (relative to
`wcs/`).

Only when the path is missing or ambiguous, resolve a plain name
("vulnerabilities", "cve", "packages") by globbing `wcs/**/fields/subset.yml`,
then list the matches and ask which one. Families for reference:

- `wcs/stateful/<...>` — state indices (`wazuh-states-*`); includes
  `stateful/inventory/*` and `stateful/fim/*`.
- `wcs/stateless/<...>` — data streams (events, metrics, active-responses).
- `wcs/content/{ioc,filters}`, `wcs/settings`, `wcs/cve`,
  `wcs/ai-assistant/sessions`, `wcs/internal-state`.

## Workflow A — add a field to an existing module

1. **Locate** the module.
2. **Classify the field** and pick where it goes:
   - **Custom field on an object that already has a `fields/custom/<object>.yml`**
     (e.g. adding to `state`, `wazuh`, `package`): append the field entry to
     that file. See `REFERENCE.md` for the entry shape.
   - **Custom field on a new object**: create `fields/custom/<object>.yml`
     **and** add that object to `fields/subset.yml` so the generator pulls it
     in.
   - **A plain ECS field already defined upstream in ECS**: add it to
     `fields/subset.yml` only (no custom file needed) — cherry-pick it under
     its object, or use `fields: "*"` to take the whole object.
3. If the object is one that gets remapped under `wazuh.*` (see the `reusable`
   mechanism in `REFERENCE.md`, e.g. `agent`), follow the existing object's
   pattern rather than inventing a new mapping.
4. **Regenerate** — run the pipeline (steps 2 + 3 of "Regeneration", below).
   No `module_list` change is needed for an existing module.
5. **Verify**: the field appears in the generated
   `plugins/setup/.../resources/templates/...json` and in
   `wcs/<module>/docs/fields.csv`.

## Workflow B — change a module's settings

Settings live in two files that must stay **in sync** — same values, but two
shapes (composable vs legacy). See `REFERENCE.md` for the exact difference
(`priority` + nested `template.settings` vs `order` + top-level `settings`).

1. **Locate** the module.
2. Edit `fields/template-settings.json` **and**
   `fields/template-settings-legacy.json` with the requested change (index
   settings, `query.default_field`, `index_patterns`, priority/order, …).
3. If the change is a mapping-level setting (`dynamic`, `date_detection`),
   edit `fields/mapping-settings.json` instead/also.
4. Do **not** hand-set `mapping.total_fields.limit` /
   `nested_fields.limit` / `index.max_docvalue_fields_search` — step 3 of the
   pipeline computes those.
5. **Regenerate** (steps 2 + 3). **Verify** the setting in the generated
   template.

## Workflow C — create a new module

1. **Copy the closest existing module** as a base (same family — a state
   module for a new state index, etc.). Rename the folder to the new module
   name. **Delete** the copied `mappings/` tree and `docs/fields.csv` (those
   regenerate).
2. Edit the inputs for the new module:
   - `fields/subset.yml` — set `name:` and the ECS/custom objects to include.
   - `fields/custom/*.yml` — the custom fields, grouped by object.
   - `fields/template-settings.json` + `-legacy.json` — set `index_patterns`,
     priority/order, index settings, `query.default_field`.
   - `fields/mapping-settings.json` — usually
     `{ "dynamic": "strict", "date_detection": false }`.
3. Write a short `docs/README.md` per the **README rules** in `REFERENCE.md`
   (WCS not ECS, short, link to `fields.csv`; use `wcs/cve/docs/README.md` as
   the model).
4. **Add** `event-generator/event_generator.py` (hyphen dir) based on a
   sibling module's generator.
5. **Wire it in.** Two separate touch points — treat them differently:
   - **`wcs/generator/update_module_list.sh`** — *required for generation, not
     optional.* `stateful/inventory/*` and `stateful/fim/*` are auto
     directory-scanned; every other family needs an entry in the relevant
     `map_*_module` function. Without this the generator (step 1 below) never
     sees the module, so the template can't be produced. Always do this when
     you generate.
   - **`plugins/setup/src/main/java/com/wazuh/setup/SetupPlugin.java`** — this
     is the runtime-install registration (the "code"). Do it **by default**,
     but **the user may opt out** ("only create the template, I'll do the
     code"). Register the index with the matching type — `StateIndex` for
     `wazuh-states-*`, `StreamIndex` for streams.

   If it is unclear whether the user wants the `SetupPlugin.java` change, ask
   before editing Java. The `update_module_list.sh` entry is not up for debate
   when the goal is to generate a template.
6. **Regenerate** — full pipeline including step 1, and **stage changes in
   git** before step 2 (see the caveat below).
7. **Verify**: module present in `wcs/module_list.txt`; index template
   generated and copied under `plugins/setup/.../resources/templates/`;
   `docs/fields.csv` created. (If `SetupPlugin.java` was wired, confirm it
   compiles — but that step is optional, so it's not a success criterion when
   the user opted out.)

## Regeneration

Run from anywhere in the repo (scripts self-locate the root). Requires Docker,
Docker Compose, `jq`, `python3` (all present on this machine).

```bash
# 1. ONLY when adding/removing a module — rescan wcs/ into module_list.txt
bash wcs/generator/update_module_list.sh

# 2. Generate templates for modified modules and copy them into place
bash wcs/generator/generate_schema.sh          # add -f to force ALL modules

# 3. Fix field-count limits in the generated templates
bash wcs/generator/count_and_update_total_fields.sh all --apply
#    or a single module:
bash wcs/generator/count_and_update_total_fields.sh <module> --apply
```

**Critical caveats:**

- `generate_schema.sh` detects what to build via
  `git diff --name-only origin/main`. Your edits must be in the working tree,
  and — per the generator's own troubleshooting note — for a **new** module
  the `update_module_list.sh` output (and the new files) must be **staged in
  git** or the generator will not see the module.
- Step 3 (`count_and_update_total_fields.sh`) runs **after** generation; it
  recomputes and fixes the `total_fields` / `nested_fields` /
  `max_docvalue_fields_search` limits that otherwise cause template errors.
- Run `count_and_update_total_fields.sh <module>` (no `--apply`) first to see
  proposed limits as a dry run.

## Success check

- New/changed fields appear in
  `plugins/setup/src/main/resources/templates/<...>.json` and in
  `wcs/<module>/docs/fields.csv`.
- Limits in the template reflect the field count (step 3 ran).
- For a new module: it is in `wcs/module_list.txt`. (Registration in
  `SetupPlugin.java` is optional — only check it when the user asked for the
  wiring.)

Leave the changes uncommitted for the user to review. Do not commit or push
unless asked.
