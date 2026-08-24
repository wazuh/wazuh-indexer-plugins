# Claude Code skills

Wazuh Indexer development is assisted by [Claude Code](https://docs.claude.com/en/docs/claude-code) skills: packaged, versioned instructions that live under `.claude/skills/<name>/` in this repository. A skill captures a process or a body of domain knowledge that's too detailed to keep in a contributor's head, too easily forgotten between sessions, or too specific to belong in the top-level `CLAUDE.md`.

## Structure

Each skill is a directory containing:

- `SKILL.md` — required. Frontmatter with a `name` and a `description` (used to match the skill to a task automatically), followed by the actual instructions.
- Related artifacts — optional supporting files referenced from `SKILL.md`, such as a style guide or a settings catalog, kept alongside the skill so they version together with it.

A skill is invoked automatically when a task matches its `description`, or explicitly by name (for example, `/docs-review`).

## Available skills

- **[Documentation review](docs-review.md)** — audits the mdBook documentation tree for coverage gaps, staleness against source, and style violations.
- **[Performance tuning](perf-tuning.md)** — reduces or validates Wazuh Indexer's memory, CPU, and GC footprint via settings and index/shard topology changes.

When you add a new skill under `.claude/skills/`, add a corresponding page here so it stays discoverable outside of Claude Code itself.
