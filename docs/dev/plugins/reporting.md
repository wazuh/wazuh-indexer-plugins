# Wazuh Indexer Reporting plugin — development guide

This document describes the Reporting plugin's structure and REST surface. For setting up a local test environment (Vagrant + Mailpit) to exercise the plugin end to end, see [Reporting test environment](./reporting-test-environment.md).

## Overview

The `wazuh-indexer-reporting` plugin is a Wazuh fork of the OpenSearch `reports-scheduler` plugin. It manages report definitions (what to generate and on what schedule) and report instances (individual generation runs), and integrates with the Job Scheduler plugin for scheduled reports and the Notifications plugin for email delivery.

## Plugin structure

The plugin registers as an OpenSearch `Plugin`, `ActionPlugin`, `SystemIndexPlugin`, and `JobSchedulerExtension`. Report definitions and instances are persisted in two system indices:

| Index | Purpose |
| --- | --- |
| `.opendistro-reports-definitions` | Stores report definitions (source, trigger schedule, delivery options). |
| `.opendistro-reports-instances` | Stores individual report generation runs and their status. |

## REST handlers

All routes are registered under a base URI (with a legacy alias for backwards compatibility) and grouped by concern:

| Handler | Concern |
| --- | --- |
| `ReportDefinitionRestHandler` | Create, update, get, and delete a single report definition. |
| `ReportDefinitionListRestHandler` | List/search report definitions. |
| `ReportInstanceRestHandler` | Get a report instance and update its status. |
| `ReportInstanceListRestHandler` | List/search report instances. |
| `OnDemandReportRestHandler` | Trigger on-demand report generation, including in-context report creation. |
| `ReportStatsRestHandler` | Expose plugin metrics/counters. |

## Scheduling

`ReportDefinitionJobRunner` and `ReportDefinitionJobParser` integrate with the OpenSearch Job Scheduler plugin to run report definitions on their configured schedule, alongside the on-demand generation path exposed via the REST API.

## Security

`UserAccessManager` and `SecurityAccess` enforce RBAC on report definitions and instances, consistent with the rest of the Wazuh Indexer's Security plugin integration.

## Notification delivery

Report delivery (e.g., emailing a generated report) goes through the [Notifications](../../ref/modules/notifications/index.md) plugin rather than implementing its own delivery transport.
