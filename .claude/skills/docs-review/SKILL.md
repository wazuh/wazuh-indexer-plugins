---
name: docs-review
description: Audit the wazuh-indexer-plugins mdBook documentation (docs/) for coverage gaps, staleness against source code, structural/navigation issues, and style inconsistency. Produces a written findings report — it does not rewrite prose. Use when asked to review, audit, or assess the Wazuh Indexer technical documentation.
---

# Wazuh Indexer documentation review

Audits `wazuh-indexer-plugins/docs/` — the mdBook site covering the Development
Guide and Reference Manual for the Wazuh Indexer ecosystem (Setup, Content
Manager, Security Analytics, Notifications, Alerting, Reporting, Security,
WCS).

This skill produces a **findings report**, not doc edits. Rewriting is a
separate, later phase, driven by the style guide this skill's output feeds
into (see "Related artifacts" below) — don't fold rewriting into this skill.

**Status:** a full audit + module-by-module rewrite has already been done
once using this process (Content Manager, Security Analytics, Alerting,
Setup, Notifications, Reporting, Common Utils), including two follow-up
correction passes, plus targeted ad-hoc fixes since (docs/dev/ tree-wide
style sweep, Setup's ISM policy and schema.md corrections, Content
Manager's blue/green swap diagram, the logtest transport-action refactor,
Security Analytics' enrichment performance rewrite). Re-running this skill
now is a **regression/drift check**
against an already-conforming corpus, not a first pass — expect most
findings to be new drift (new content added since the last pass) or missed
spots, not the original backlog. See "Related artifacts" for what's already
fixed vs. what was intentionally deferred.

## Related artifacts

- **Style guide**: `.claude/skills/docs-review/STYLE_GUIDE.md`, checked into
  this repo alongside this skill. Produced from a prior run of this skill's
  findings; defines the actual rules — heading case, terminology,
  register-per-track, table-vs-list, versioning caveats, etc. When this
  skill's style/consistency pass (step 4) finds something, check it against
  the style guide first: if the guide already has a rule, this is a plain
  violation to report; if it doesn't, that's a signal the guide needs a new
  rule, not just a one-off fix — propose the addition in the findings report
  rather than editing `STYLE_GUIDE.md` directly (see "Explicitly out of
  scope" below).
- Known **deferred, not missing**: `ref/glossary.md` is intentionally still
  an empty stub (the style guide decided its contents but populating it was
  never executed) — don't re-report this as a fresh finding, just note it's
  still open. Alerting has no `troubleshooting.md` and Security Analytics has
  no `api.md` — both are known, previously-flagged gaps, not new content-gap
  findings, unless something has changed about the plugin's surface since.

## Scope reminder

The doc tree lives at `wazuh-indexer-plugins/docs/`. Related source lives in
sibling repos/dirs referenced by the top-level CLAUDE.md: the
`content-manager` plugin, `wazuh-indexer-security-analytics`, and the WCS
schema tooling in `wcs/`. Treat source code and `openapi.yml` as ground
truth; treat docs as the thing being checked.

## Process

Work through these passes in order. Each pass builds on the last — don't
skip to styling before structure/coverage is understood, and don't start
rewriting mid-audit.

### 1. Inventory the doc tree

- Read `docs/SUMMARY.md` — this is the navigation source of truth for the
  mdBook build.
- `find docs -name '*.md'` and diff against what's actually linked from
  `SUMMARY.md`. Flag:
  - **Orphaned files**: exist on disk, not reachable from `SUMMARY.md`.
  - **Broken links**: entries in `SUMMARY.md` pointing at files that don't
    exist.
  - **Stub pages**: files linked from `SUMMARY.md` with only a heading and
    no body (e.g. a page that's just `# Glossary`).
- Note the two top-level tracks (Development Guide, Reference Manual) and
  whether a topic that appears in one has a natural counterpart missing in
  the other.

### 2. Cross-check coverage against source

Documentation "coverage" can't be judged from the docs alone — verify against
the actual plugin surface:

- Enumerate real plugins/modules from source (`plugins/*/` in
  wazuh-indexer-plugins, the security-analytics repo, `wcs/module_list.txt`)
  and check each has a Reference Manual entry under `ref/modules/`.
- For plugins with a REST API (`openapi.yml`, `RestPost/Put/Delete*Action`
  classes), check the documented endpoint list against the actual
  registered handlers — look for undocumented endpoints or documented
  endpoints that no longer exist.
  - Consider delegating this cross-check to a subagent (Explore or
    general-purpose) per plugin, since it means reading source alongside
    docs — parallelizable across plugins.
- Check settings tables (e.g. `ref/modules/*/configuration.md`) against
  `PluginSettings`-style source classes for missing or renamed settings.
- Check documented **mechanisms and call chains** against source, not just
  endpoint lists and settings values — e.g. "REST handler validates and
  calls Service X directly" is a claim about architecture, and a refactor
  (a new transport-action layer, a concurrency model changing from
  per-item to per-batch) can make it wrong even though every class/method
  name it mentions still technically exists. This class of staleness found
  real bugs in `content-manager-logtest.md` (REST handlers used to
  validate; a `transport/` layer now does) and
  `security-analytics.md` (enrichment concurrency was documented as
  per-finding; it's now per-batch). A stale mechanism description is worse
  than a stale setting value — it misleads a contributor about where to
  make a change, not just what a number is.
- Flag version-sensitive claims that may be stale for 5.0 (e.g. mentions of
  Filebeat, Wazuh Manager doing analysis/detection — these moved to the
  Indexer in 5.0 per `ref/description.md`).

### 3. Structural and navigational review

- Heading hierarchy: does each page start at `#`/`##` consistently, or do
  some jump levels?
- Table of contents depth in `SUMMARY.md` — are nesting levels consistent
  for equivalent content (e.g. every module having Architecture/
  Configuration/API Reference/Troubleshooting, or a deliberate and
  documented exception)?
- Cross-linking: do related pages link to each other (e.g. dev guide page
  linking to its reference manual counterpart), or does content duplicate
  instead of link?
- Placement: is a piece of content in the right track? (Reference Manual =
  user/operator-facing; Development Guide = contributor-facing.) Flag
  content that reads like implementation notes sitting in the Reference
  Manual, or vice versa.

### 4. Style and consistency audit

A style guide now exists (see "Related artifacts" above) — use it as the
checklist for this pass instead of surfacing open-ended variation from
scratch. For each rule in the guide, spot-check a sample of pages per module
and report violations directly (not "here's inconsistency, go decide a
rule" — that phase is done).

Specific, known bug patterns to actively grep for, each of which was found
and fixed at least once already, meaning they're the kind of thing that
creeps back in with new edits:

- **Bolded pseudo-headings**: `grep -rn '^\*\*[A-Z][a-zA-Z]* [A-Z][a-zA-Z ]*\*\*$'` —
  multi-word bold text alone on its own line, standing in for a real heading
  (`**Request Body**`, `**Example Request**`). Single-word bold labels
  preceding one short block (`**Example**`, `**Events**`) are fine and not
  the same pattern — see the style guide's heading rule for the distinction.
- **`SAP` abbreviation**: `grep -rln '\bSAP\b'` — should be "Security
  Analytics" or "the Security Analytics plugin" everywhere, including inside
  Mermaid diagram participant identifiers/labels.
- **Tables that should be lists**: any table whose description column
  routinely holds a full sentence (settings references, field references) —
  check against the style guide's table-vs-list rule, remembering the
  page-level-summary-table exception and the `{{#include}}` anchor
  preservation constraint.
- **Unprefixed temporary fields in check/detection examples**: `grep -rn
  '"tmp_[a-z_.]*":' ` or similar — a field that looks decoder-internal
  (`tmp_json.*`) but isn't prefixed with `_` will fail real Engine
  validation; this is a functional bug in an example, not just style.
- **`author` (or similar) field type drift**: when an example shows a field
  as an object in one place and a string in another for the same schema,
  that's a factual bug, not a style question — verify against the actual
  `openapi.yml`/request-model source, don't assume either version is right.
- **Numeric/config claims embedded in prose or diagrams, not just settings
  tables**: a settings-table-only cross-check misses a hardcoded value
  repeated in a "Policy details" bullet list or a sequence-diagram label
  (e.g. `dev/plugins/setup.md` had "25 GB" and ISM template "Priority: 50"
  baked into prose describing each policy, contradicting the actual `20gb`
  / `priority: 0` in the policy JSON). Grep for the same numeric/setting
  value across the whole page, not just its one settings-table row.
- **Diagram branch completeness**: an existing Mermaid sequence/state
  diagram can go stale not by showing wrong content, but by silently
  omitting a whole branch a refactor added (e.g. `content-manager.md`'s
  sync-pipeline diagram modeled Initialization and Update but never had a
  branch for the plan-change/shadow-swap path, even after that path was
  fully documented in prose elsewhere on the same page). Check that every
  `alt`/`opt` branch named in surrounding prose actually appears in the
  diagram, and vice versa.
- Heading case (Title Case vs sentence case) — should now be consistently
  sentence case; flag any remaining Title Case as a miss, not as neutral
  variation to weigh.
- Terminology drift against the style guide's terminology table (§2) —
  same concept, different names across pages.
- Voice/register: class or method names appearing in a Reference Manual
  page is a hard violation now (style guide §3), not a judgment call.
- Length/depth imbalance between sibling pages, and duplication of the same
  workflow/table across multiple files — still worth flagging if found, since
  these weren't mechanically fixed everywhere, only where explicitly noticed.

### 5. Write the findings report

Produce a single report (ask the user where — default to a scratchpad file
or an Artifact if it'll be shared) organized by the four passes above, not
by file. For each finding:

- What/where (file + line or section).
- Why it matters (confusing to a reader, factually stale, inconsistent with
  N other pages, etc.) — cite the other pages when flagging inconsistency.
- Suggested fix, but phrased as a recommendation, not an applied edit.

Do not edit any `docs/` files during this skill. Stop after the report and
let the user decide what to prioritize and how to stage the rewrite.

## Explicitly out of scope for this skill

- Rewriting prose or restructuring `SUMMARY.md` — that's the rewrite phase,
  which now has its own style guide to follow (see "Related artifacts"); this
  skill only ever produces the findings report that phase consumes.
- Amending the style guide itself. If this skill's audit surfaces a pattern
  the guide doesn't cover (not just a violation of an existing rule), name it
  as a proposed new rule in the findings report and let the user decide
  whether to add it — don't silently expand the guide's scope mid-audit.
- Editing generated files (there are none under `docs/`, but if source-code
  cross-checks touch `wcs/**/mappings/` or `plugins/setup/.../templates/`,
  those are generated — never edit them; see top-level CLAUDE.md).
