# Documentation review

The `docs-review` skill audits `docs/` — the mdBook site covering the Development Guide and Reference Manual — for coverage gaps, staleness against source code, structural and navigation issues, and style inconsistency.

The skill produces a findings report; it does not rewrite prose itself. Rewriting is a separate, later phase driven by the style guide below.

## Process

The audit runs in five passes, each building on the last:

1. Inventory the doc tree against `SUMMARY.md` — orphaned files, broken links, stub pages.
2. Cross-check coverage against source — plugins, REST endpoints, settings, and documented mechanisms or call chains, not just names that still technically exist.
3. Review structure and navigation — heading hierarchy, table-of-contents depth, cross-linking, and whether content sits in the right track.
4. Audit style and consistency against the style guide below, including a set of known bug patterns (bolded pseudo-headings, stale numeric claims baked into prose or diagrams, incomplete diagram branches) that have recurred since the last pass.
5. Write the findings report.

## Related artifacts

- [`SKILL.md`](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/.claude/skills/docs-review/SKILL.md) — the full instructions, including the known bug patterns to grep for and what's already fixed versus intentionally deferred (for example, `ref/glossary.md` is a known-empty stub).
- [`STYLE_GUIDE.md`](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/.claude/skills/docs-review/STYLE_GUIDE.md) — the actual rules produced from a prior audit (heading case, terminology, table-vs-list, register per track, and more). This is the checklist the style pass runs against.

## Usage

Invoke with `/docs-review` when asked to review, audit, or assess the Wazuh Indexer documentation. A full audit and module-by-module rewrite has already been done once; re-running the skill is a regression/drift check against an already-conforming corpus, not a first pass.
