# Naming Conventions for Workflows and Actions

This document defines the naming conventions for GitHub Actions and Workflows used across the Wazuh Indexer repositories.

## Naming convention

Both Actions and Workflows follow the same pattern:

```
<major>_<prefix>_<target>
```

| Component  | Description |
|------------|-------------|
| **Major**  | Product major version (e.g. `4`, `5`). |
| **Prefix** | Category prefix from the use cases below. |
| **Target** | The action target: a component, module, subsystem, tool, language, etc. |

### Prefixes

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

## Actions

### Job rules

- A job step **cannot** contain Actions with different prefixes.
- A job step **must** use matrices whenever possible.

## Workflows

For workflows triggered on PR or push events, append `_onpush` to the name to distinguish them from their `workflow_dispatch` counterparts:

```
5_builderpackage_indexer.yml          ← workflow_dispatch (manual)
5_builderpackage_indexer_onpush.yml   ← PR / push trigger (automatic)
```

## Runners

Two types of runners are available:

| Runner | Type | Usage |
|--------|------|-------|
| **Default** | GitHub-hosted | All workflows unless there is a justified reason to use the dedicated runner. |
| **Dedicated** | Self-hosted | Reserved for resource-intensive workflows only. Currently used exclusively by `5_builderpackage_indexer` (the full package builder). |

**Always prefer the default runner.** The dedicated runner is a shared, limited resource, use it only when the workflow genuinely requires the extra capacity (e.g. full product builder).

## Draft PR enforcement

All PR workflows **must** be configured to skip Draft PRs. This is enforced by adding the following condition to every PR-triggered workflow:

```yaml
on:
  pull_request:
    types: [opened, synchronize, ready_for_review]

jobs:
  <job_name>:
    if: ${{ !github.event.pull_request.draft }}
```

This ensures no CI minutes are consumed on work-in-progress PRs. See [Pull Requests](pull-requests.md) for the full PR lifecycle.
