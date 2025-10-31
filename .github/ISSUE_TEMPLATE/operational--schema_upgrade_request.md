---
name: Migrate the Wazuh Common Schema to a new version of the ECS
about: Used by the Indexer team to upgrade the Wazuh Common Schema to a new version of the ECS.
title: Support ECS vX.Y.Z
labels: level/task, request/operational, type/maintenance
assignees: ""
---

## Description

The Wazuh Common Schema is currently based on the ECS vX.Y.Z. A new version of the ECS has been released: vX.Y.Z.

## Plan

In order to migrate the WCS to the new ECS version, we need to:

- [ ] Analyze the changes introduced in the new ECS version (breaking changes, new fields, etc.).
- [ ] Upgrade the tooling used to generate the WCS schema to support the new ECS version. (ref: `ECS_VERSION`)
- [ ] Regenerate the WCS schema (stateless and stateful).
