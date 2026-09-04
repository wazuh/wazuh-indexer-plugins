# Wazuh Indexer documentation style guide

Applies to `wazuh-indexer-plugins/docs/` (Reference Manual + Development Guide).
All open questions are now resolved — every rule below is **Decided**.

**Application status:** the module-by-module rewrite (Content Manager,
Security Analytics, Alerting, Setup, Notifications, Reporting, Common Utils)
has been applied at least once across the corpus, including two follow-up
correction passes (bold-pseudo-heading → real headings, SAP → Security
Analytics terminology, table → list conversion for settings/field
references, and the `case-management.md` schema update). This guide isn't
purely aspirational anymore — most of the corpus already conforms. Known gaps
still open: `ref/glossary.md` is still an empty stub (see §2), and any module
not explicitly listed above hasn't had a dedicated conformance pass. Treat
new findings against these rules as regressions or missed spots, not as
"the guide hasn't been applied yet."

**Core split**: the Development Guide is for people working on the code
(architecture, class/method names, extension points, environment setup). The
Reference Manual is a user guide — it documents behavior, capabilities, and
APIs, and never names implementation details. Every rule below should be read
in light of that split.

## 1. Headings

- **Decided — sentence case.** Only the first word and proper nouns/glossary
  entries are capitalized. "Update check service", not "Update Check Service".
- **Decided — capitalization exceptions.** Plugin/product names (Content
  Manager, Ruleset Management, Security Analytics, Wazuh Engine, Wazuh
  Dashboard, Wazuh CTI) and
  glossary-entry acronyms (IoC, KVDB, CVE, RBAC, WCS, ISM) keep their
  natural casing wherever they appear, including mid-heading.
- **Decided — "Actions" and "Workflows" are capitalized when referring to
  GitHub Actions / GitHub Workflows specifically** (the CI/CD feature and its
  YAML definitions under `.github/workflows/`), same treatment as a product
  name — e.g. "Workflows and Actions", "Both Actions and Workflows follow the
  same pattern". Use lowercase only for the generic English sense of the word
  (a generic "workflow" describing a process, not a GitHub Actions workflow
  file). This surfaced in `dev/index.md`'s "Workflows and Actions" section.
- **Decided — bolded pseudo-headings become real headings.** Bold text used as
  a section label inside prose (`**Request Body**`, `**Example Request**`,
  `**Status Codes**`) is a heading in every way except markup — mdBook renders
  it as a bold run-in line, not a navigable section, and it still needs the
  sentence-case treatment. Convert every instance to a real `###`/`####`
  heading at the appropriate depth: `**Request Body**` → `### Request body`,
  `**Example Request**` → `### Example request`, `**Status Codes**` → `###
  Status codes`. This was found throughout the API reference pages (e.g.
  `content-manager/api.md`, `setup/api-reference.md`) — sweep all of them, not
  just the one that was flagged. Single-word bold labels preceding one short
  block (`**Example**`, `**Events**`) are a different, lower-priority pattern
  — not the same violation, and not required to become a heading.
- **Decided — depth cap: `#` page title + up to 3 subheading levels
  (`##`/`###`/`####`).** My recommendation on *how* to enforce it: treat
  hitting `####` as a signal to stop nesting and switch to a table, definition
  list, or a single prose section instead of a 5th heading level. This is what
  makes the "prefer longer sections over many tiny ones" principle (#5 below)
  self-enforcing rather than a rule people forget under deadline pressure. The
  clearest violator in the current corpus is `dev/plugins/content-manager.md`'s
  test-scenario catalog, which uses `####` per resource/operation
  (~20 headings) — that should become one table with a "Resource / Operation"
  column instead.
- **Decided — one `#` per file**, matching the page title in
  `SUMMARY.md`. Never use `#` again inside the body.

## 2. Terminology and glossary

- **Decided — start populating `ref/glossary.md`.** It's currently a stub
  (`# Glossary`, no content) despite being linked from `SUMMARY.md`, and
  **remains unpopulated as of the module-by-module rewrite pass** — this rule
  was decided but not yet executed; treat it as an open action item, not
  something already done. Proposed initial entries, seeded from terms the
  audit found used inconsistently across files:

  | Term | Expansion | Notes |
  |---|---|---|
  | IoC | Indicator of Compromise | |
  | KVDB | Key-Value Database | audit found "Data Base" (two words) used once — standardize to one word |
  | CVE | Common Vulnerabilities and Exposures | |
  | CTI | Cyber Threat Intelligence | |
  | RBAC | Role-Based Access Control | |
  | WCS | Wazuh Common Schema | |
  | ISM | Index State Management | |
  | UDS | Unix Domain Socket | |
  | CUD | Create, Update, Delete | audit found this both spelled out and abbreviated inconsistently — pick one per the rule below |

- **Decided — first-use-per-page expansion rule.** Every acronym is
  written in full on first use within a page, with the acronym in parentheses,
  even if it's already in the glossary — e.g. "Indicator of Compromise (IoC)"
  — then the acronym alone for the rest of that page. The glossary is a lookup
  aid for readers who land mid-page, not a substitute for in-page clarity.
- **Decided — one canonical name per concept, enforced via the
  glossary/terminology table above.** Concretely from the audit: use "CUD" once
  defined per page rather than alternating with "create/update/delete"; use
  "routing policy" (not "Engine routing policy" or bare "policy") for the
  Content Manager concept.
- **Decided — "Wazuh Manager" is the correct name, not "Wazuh Server".** Fix
  the stray link fragment in `ref/modules/setup/index.md` (`wazuh-server.html`)
  that pointed at upstream docs using the other name — either find/link the
  correct upstream page or drop the link if none exists under the right name.
- **Decided — never "SAP".** "SAP" is an internal shorthand that reads as an
  unrelated acronym (the enterprise software) to anyone landing on a page
  without prior context. Spell the plugin's name out every time, in both
  tracks and inside Mermaid participant labels. Do not add "SAP" to the
  glossary — the point is to stop using the abbreviation, not to define it.
  Which name to spell out is track-dependent; see the next rule.
- **Decided — the Security Analytics plugin is named per track: "Ruleset
  Management" in the Reference Manual, "Security Analytics" in the
  Development Guide.** The plugin was renamed to Ruleset Management in the
  Wazuh Dashboard; the rename is presentational only, and the code, repository
  (`wazuh-indexer-security-analytics`), settings prefix
  (`plugins.security_analytics.*`), API base path
  (`/_plugins/_security_analytics/`), index patterns (`.opensearch-sap-*`) and
  action namespaces (`cluster:admin/*/securityanalytics/*`) all keep the old
  name. That split follows the §3 register rule: the Reference Manual uses the
  name a user sees in the product, the Development Guide uses the name a
  contributor sees in the source. Concretely:
  - **Reference Manual** (`ref/`): "Ruleset Management", or "the Ruleset
    Management plugin" when a plugin-vs-concept distinction matters. The
    module lives at `ref/modules/ruleset-management/`.
  - **Development Guide** (`dev/`): "Security Analytics", matching the code.
  - **The upstream OpenSearch product keeps its own name** — "the OpenSearch
    Security Analytics plugin" — everywhere, including in the Reference
    Manual, since renaming it would misname a third-party product. Watch for
    this when doing a bulk find-and-replace.
  - **Literal identifiers are never renamed** in either track: settings keys,
    API paths, index/alias names, role and action names, and repository names
    keep `security_analytics` / `securityanalytics` / `sap` as they appear in
    the product.
  - **Both entry pages carry a naming note** — `ref/modules/ruleset-management/index.md`
    and `dev/plugins/security-analytics.md` each open with a short blockquote
    explaining that the two names describe the same plugin, and cross-link to
    each other. Keep those notes in sync if either name changes again.
- **Decided — plugins refer to themselves by title-cased product
  name in prose** ("the Content Manager plugin", "the Notifications plugin"),
  reserving the literal package name (`wazuh-indexer-reporting`) for
  installation/build contexts only (package lists, build commands).

## 3. Register per track

- **Decided — no class, method, or internal transport-action names in the
  Reference Manual, ever.** This is a hard boundary, not a judgment call: the
  Reference Manual is strictly a user guide, and the Development Guide is
  strictly for people working on the code. Anything at implementation-detail
  level belongs in the Development Guide, cross-linked from the Reference page
  if useful. Concretely: `ref/modules/ruleset-management/index.md` naming
  `WazuhEnrichedFindingService` / `TransportCorrelateFindingAction` /
  `SUBSCRIBE_FINDINGS_ACTION`, and `ref/modules/content-manager/index.md` giving
  the literal Unix socket path, both move to their respective `dev/` pages.
- **Decided — Reference Manual pages are not tutorials.** No
  click-by-click dashboard walkthroughs with screenshots in `ref/`. The
  Reporting module's `ref/modules/reporting/index.md` is the clearest violator
  today (a full "click Create channel..." walkthrough) — that content moves to
  a "how-to"/tutorial doc, either under `dev/` or a new `guide/`-style location
  if Reference Manual readers need it too, rather than living inside the
  reference page itself.
- **Decided — Development Guide can be as implementation-detailed as
  needed** (class names, method names, sequence diagrams of internal calls),
  but stays architecture/extension-point focused rather than becoming a
  step-by-step environment-provisioning runbook. `dev/plugins/reporting.md`'s
  full Vagrant walkthrough is the outlier to fix here — likely belongs in
  `dev/setup.md` or a dedicated "local environment" doc, not the Reporting
  plugin's dev guide.

## 4. Structure

- **Decided — prefer extending existing pages over creating new ones** when a
  topic is related to what's already there. Concretely: don't split a module's
  `index.md` further just to satisfy the heading-depth cap — restructure within
  the existing page set (index/architecture/configuration/api/troubleshooting)
  first, and only propose a new page when a topic doesn't fit any existing one
  and is substantial enough to need its own navigation entry.
- **Decided — every module gets the same page skeleton unless there's
  a stated reason not to**: `index.md`, `architecture.md`, `configuration.md`,
  `api.md` (only if the module has a REST API), `troubleshooting.md`. Today
  Reporting has only `index.md` and Ruleset Management has no `api.md` despite
  having a REST-driven API — both should be brought to the common skeleton
  during the rewrite rather than treated as acceptable variation.
- **Decided — one page's content stays owned by one module**, even
  when it also matters to another. Cross-link instead of duplicating. This
  directly targets the audit's finding that promotion workflow, space model,
  and system-index tables are independently described in 2-3 files per module
  and drift out of sync with each other. Concretely: `dev/plugins/content-manager.md`
  should link to `ref/modules/content-manager/index.md`'s System Indices table
  rather than maintaining its own copy.

## 5. Formatting mechanics

- **Decided — inline code formatting**: backtick every setting key,
  index/alias name, file path, HTTP method+path, field name, and literal
  value, with no exceptions — this matches what most of the corpus already
  does and needs nothing extra to remember.
- **Decided — tables**: sentence-case column headers (`| Setting |
  Description |`, not `| SETTING | DESCRIPTION |` or a mix), minimal
  alignment-dash padding (`---`, not stretched to match column width — purely
  cosmetic in rendered output, but keeps diffs small), and always include a
  Description column for reference tables of settings/indices/endpoints.
- **Decided — prefer bulleted lists over tables, especially for settings.**
  mdBook's default table rendering is cramped and doesn't wrap long
  description text well, so wide tables (many columns, or a description column
  with full sentences) read poorly. Settings documentation in particular
  should use a list, one bullet per setting, in this shape (see the Modifiers
  section of `ref/modules/ruleset-management/rules.md` for the pattern this is
  based on):
  ```
  - **`plugins.content_manager.max_bulk_bytes`** (Long, default `5242880` /
    5 MB, range 1048576–104857600) — maximum request body size, in bytes,
    for a single bulk indexing request.
  ```
  Tables are still fine for genuinely tabular data with short, uniform cell
  content (status code → meaning, index → alias mapping, HTTP method → path).
  The line is: if a column would routinely hold a full sentence, use a list
  instead.
  - **Exception — a page-level summary/index table stays a table** even when
    every other table on the page becomes a list. `notifications/api.md` keeps
    one "Summary table" at the end (endpoint → method → one-line description)
    because it's a genuinely tabular index a reader scans top-to-bottom, not a
    settings/field reference read top-to-bottom as prose. When a page has both
    a detailed per-item reference (convert to list) and a compact
    all-items-at-a-glance table, keep the latter and convert only the former.
  - **Constraint — preserve mdBook `{{#include}}` anchor comments untouched
    during table→list conversion.** Some settings tables are wrapped in
    `<!-- // ANCHOR: settings-table -->` / `<!-- // ANCHOR_END: settings-table
    -->` markers (e.g. `content-manager/configuration.md`,
    `ruleset-management/configuration.md`) and transcluded elsewhere via
    `{{#include path:anchor-name}}` (see `ref/configuration/plugin-settings.md`
    and `ref/getting-started/installation.md`). Converting the table to a list
    is fine — mdBook includes the anchor's content verbatim regardless of
    markup — but the anchor comment lines themselves must stay exactly where
    they are, or the include breaks silently (renders empty, no build error).
    Always `grep -rn "path/to/file.md:anchor-name"` across `docs/` before and
    after editing a file with anchors to confirm every includer still
    resolves.
- **Decided — diagrams**: use Mermaid (already configured via
  `book.toml` / `mermaid-init.js`, and already used in
  `dev/plugins/content-manager.md`) instead of ASCII art, for any workflow with
  3+ participants (e.g. User → Indexer → Engine). Single-component numbered
  steps can stay as a prose list.
- **Decided — API examples**: `curl -sk -u admin:admin` against
  `https://<host>:9200` (use `127.0.0.1` as the placeholder host, not
  `localhost` — pick one and it's this one, since it's the majority form in
  the corpus) is already the de facto convention — formalize it as the
  standard rather than letting each page reinvent it. Every example should be
  a complete, copy-pasteable command (method, URL, headers, body) — no partial
  fragments.
- **Decided — every API example must be verified against the plugin's
  `openapi.yml` (or the actual REST handler/request-model source if no spec
  exists) before being written or edited, not just written to "look
  plausible."** This isn't optional polish: a real audit of
  `content-manager/api.md` found `metadata.author` documented as an object
  (`{"name": ..., "email": ..., "url": ...}`) in several examples when the
  spec defines it as a plain string everywhere, and found two endpoints
  documented with the wrong required-fields list. Both bugs had been sitting
  in "working" documentation, presumably because the examples looked
  reasonable rather than because anyone checked them against the schema.
  Concretely: grep the target schema/model for every field name in an example
  and confirm both the field's presence and its type before treating an
  example as correct, and re-check on every edit — a fix to one example can
  leave a sibling example (create vs. update, JSON vs. YAML) with the same bug
  unfixed.
- **Decided — fields referenced in Engine `check`/`detection` expressions that
  aren't part of the Wazuh Common Schema (WCS) must be prefixed with an
  underscore** (e.g. `_tmp_json.event.action`, not `tmp_json.event.action`) to
  mark them as intentionally temporary/decoder-internal. An unprefixed
  non-WCS field is rejected by the Engine with a real validation error ("Field
  '...' is not defined in WCS schema and is not a temporary field") — this bit
  multiple examples across `content-manager/api.md` and
  `content-manager/rule-testing.md` before being caught, so treat any bare
  `tmp_*`-looking field name in a check/detection example as a bug to verify,
  not a stylistic choice. See
  `content-manager/troubleshooting.md#engine-validation-rejects-a-temporary-field`
  for the full explanation to link to when this comes up.
- **Decided — no emoji in headings or body text.**
  `dev/plugins/content-manager.md`'s `## 🧪 Testing` is the only occurrence in
  the corpus and should be removed as part of that file's rewrite.
- **Decided — long API reference pages get an in-page section list near the
  top.** Once a page covers more than ~4 distinct endpoint groups (e.g.
  Subscription management, Content updates, Content management, Logtest,
  Promotion), add a short bulleted list of links right after the intro
  paragraph so a reader can jump to the section they need instead of
  scrolling. Use mdBook's automatic heading anchors (lowercase, hyphenated) —
  no manual `<a name>` tags needed.
- **Decided — link the OpenAPI spec from the corresponding API reference
  page.** Where a plugin ships an `openapi.yml`, the Reference Manual's API
  page for that plugin should link to it (e.g. via the GitHub blob URL, as
  `dev/plugins/content-manager.md` already does) so readers who want the full
  machine-readable schema know where to find it. The prose reference page
  remains the primary content; the spec is a supplementary link, not a
  replacement.

## 6. Versioning

- **Decided — no version markers for shipped, stable-branch behavior.** All
  documentation in this tree describes 5.0.0; there's no prior version's docs
  to disambiguate against, so "Introduced in 5.0" / "as of 5.0" notes are
  unnecessary noise for anything actually merged. Write everything in the
  present tense as current behavior. (This resolves the earlier ambiguity
  around whether Ruleset Management enriched findings was shipped or planned —
  it's shipped, and the docs should just say so plainly with no version
  caveat.)
- **Decided — exception: an explicit status caveat is required when a page
  documents a change that has not yet merged into the stable branch.**
  `ruleset-management/case-management.md` and the case-management section of
  `dev/plugins/security-analytics.md` document a schema revision (`comment` →
  `comments` array, plus `title`/`description`/`severity`/`priority`/`tlp`)
  that exists only as a design doc at the time of writing, not in shipped
  code. These pages open with a blockquote status note naming the source
  design doc and stating plainly that it isn't merged yet. This is not the
  same thing as the banned "Introduced in 5.0" marker — that pattern
  disambiguates between two *shipped* versions, which this repo doesn't need.
  This caveat instead disambiguates *shipped* from *not-yet-shipped*, which is
  a real and necessary distinction. Use it sparingly, only when a page's
  primary subject is genuinely unmerged — don't add speculative "may change"
  hedging to normal shipped-behavior pages.

