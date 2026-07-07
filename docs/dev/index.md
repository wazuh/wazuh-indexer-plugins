# Development documentation

Under this section, you will find the development documentation of Wazuh Indexer. This documentation contains instructions to compile, run, test and package the source code. Moreover, you will find instructions to set up a development environment in order to get started at developing the Wazuh Indexer.

This documentation assumes basic knowledge of certain tools and technologies, such as Docker, Bash (Linux) or Git.

Before you start coding, read the sections below: they cover how to open good pull requests and how our GitHub Actions behave when you do. Getting this right up front saves CI minutes and review cycles for everyone.

## Pull Requests

These are the standard procedures for creating, updating, and reviewing Pull Requests across the Wazuh Indexer repositories.

### Lifecycle

```
┌──────────┐    ┌──────────────┐    ┌─────────────────┐    ┌───────┐
│  Draft   │───▶│ Local build  │───▶│ Ready for       │───▶│ Merge │
│  PR      │    │ & test       │    │ review (CI runs)│    │       │
└──────────┘    └──────────────┘    └─────────────────┘    └───────┘
```

Every Pull Request **must** start in **Draft** status. Workflows do not run on Draft PRs — this is enforced across all repositories to avoid wasting GitHub Actions minutes on work in progress — so use Draft status freely while iterating on your changes.

Before marking the PR as ready, **build** the project successfully and **run the tests** locally to verify they pass. This prevents avoidable CI failures that waste runner time and delay reviews. Once everything is complete and locally validated, click **"Ready for review"** and move the linked issue to **Pending review**. This is the moment workflows are triggered for the first time.

To address review feedback, push new commits on top of the branch and re-request review once you have resolved all comments. Avoid amending or rebasing published commits during review, and if CI fails after pushing, investigate and fix it before requesting re-review. When the PR is approved and CI passes, it can be merged. Use **squash merge** for single-purpose PRs to keep a clean history.

### Body template

Use the following template when creating a Pull Request:

```markdown
## Description

<!-- Brief description of the changes and the reasoning behind them. -->

Resolves #<issue_number>

## Checklist

- [ ] ...
```

Always link the related issue with `Resolves #<number>` so it auto-closes on merge, and describe **why** rather than just **what** — the diff already shows what changed, so the description should explain the motivation.

### Reviewing a PR

Start from the linked issue to understand the context and acceptance criteria, then read the description and checklist before reading the code. Focus your feedback on correctness, clarity, and maintainability, and use GitHub's suggestion feature for small fixes to speed up the process. Approve only when you are confident the changes are correct and complete.

### Changelog

Every PR is expected to include a changelog entry. The `5_codequality_changelog.yml` workflow enforces this. Apply the **`skip-changelog`** label to bypass the check when the linked issue belongs to a **private repository**, or when the PR is linked to a public issue but genuinely does not require a changelog update.

### Best practices

- **Keep PRs small and focused.** One issue per PR whenever possible.
- **Write descriptive commit messages.** They should explain _why_, not just _what_.
- **Do not trigger CI unnecessarily.** Keep PRs in Draft until ready, and validate locally first.

## Workflows and Actions

This section defines the naming conventions and operational rules for the GitHub Actions and Workflows used across the Wazuh Indexer repositories.

### Naming convention

Both Actions and Workflows follow the same pattern:

```
<major>_<prefix>_<target>
```

| Component  | Description |
|------------|-------------|
| **Major**  | Product major version (e.g. `4`, `5`). |
| **Prefix** | Category prefix from the use cases below. |
| **Target** | The action target: a component, module, subsystem, tool, language, etc. |

The prefix is drawn from the following set of use cases:

| Use case | Prefix | Target | Example |
|----------|--------|--------|---------|
| Code analysis (static/dynamic) | `codeanalysis` | Code analysis tool | `4_codeanalysis_coverity` |
| Linter / auto-docs | `codelinter` | Linter | `5_codelinter_clangformat` |
| Code quality (groups `codeanalysis` + `codelinter`) | `codequality` | Repository | `5_codequality_changelog` |
| Unit tests | `testunit` | Module | `5_testunit_engine` |
| Component tests | `testcomponent` | Component/module | `5_testcomponent_indexerconnector` |
| Integration tests | `testintegration` | Module | `4_testintegration_cluster` |
| Package builder | `builderpackage` | Subsystem | `4_builderpackage_server` |
| Precompiled object builder | `builderprecompiled` | Subsystem | `5_builderprecompiled_agent` |
| Version bumping | `bumper` | Repository | `5_bumper_repository` |

For workflows triggered on PR or push events, append `_onpush` to the name to distinguish them from their `workflow_dispatch` counterparts:

```
5_builderpackage_indexer.yml          ← workflow_dispatch (manual)
5_builderpackage_indexer_onpush.yml   ← PR / push trigger (automatic)
```

When composing jobs from Actions, a single job step **cannot** mix Actions with different prefixes, and steps **must** use matrices whenever possible.

### Runners

Two types of runners are available:

| Runner | Type | Usage |
|--------|------|-------|
| **Default** | GitHub-hosted | All workflows unless there is a justified reason to use the dedicated runner. |
| **Dedicated** | Self-hosted | Reserved for resource-intensive workflows only. Currently used exclusively by `5_builderpackage_indexer` (the full package builder). |

**Always prefer the default runner.** The dedicated runner is a shared, limited resource — use it only when the workflow genuinely requires the extra capacity (e.g. the full product builder).

### Draft PR enforcement

All PR workflows **must** be configured to skip Draft PRs, so that no CI minutes are consumed on work-in-progress PRs. This is enforced by adding the following condition to every PR-triggered workflow:

```yaml
on:
  pull_request:
    types: [opened, synchronize, ready_for_review]

jobs:
  <job_name>:
    if: ${{ !github.event.pull_request.draft }}
```
