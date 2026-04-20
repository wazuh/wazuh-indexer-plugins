# Logtest Architecture and Developer Guide

## Component Overview

The logtest flow involves three layers:

```
RestPostLogtestAction               →  LogtestService  →  EngineService + SecurityAnalyticsService
RestPostLogtestNormalizationAction  →       ↑                    ↑
RestPostLogtestDetectionAction      →       ↑                    ↑
       (REST handlers)                (Orchestration)       (External services)
```

### RestPostLogtestAction (combined)

**Path**: `rest/service/RestPostLogtestAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest`. Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required field `space`.
3. Validates that `space` is `"test"` or `"standard"`.
4. Extracts the optional `integration` field (if present) and strips it from the Engine payload.
5. Delegates to `LogtestService.executeLogtest(integrationId, space, enginePayload)`.
   If `integrationId` is `null`, only engine normalization is performed.

The handler does **not** interact with indices or external services directly, all business logic is in the service.

### RestPostLogtestNormalizationAction

**Path**: `rest/service/RestPostLogtestNormalizationAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest/normalization`. Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required field `space`.
3. Validates that `space` is `"test"` or `"standard"`.
4. Strips the `integration` field if present (not used for normalization).
5. Delegates to `LogtestService.executeNormalization(enginePayload)`.

### RestPostLogtestDetectionAction

**Path**: `rest/service/RestPostLogtestDetectionAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest/detection`. Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required fields `space`, `integration`, and `input`.
3. Validates that `space` is `"test"` or `"standard"`.
4. Validates that `input` is a JSON object (not a string or array).
5. Delegates to `LogtestService.executeDetection(integrationId, space, inputEvent)`.

### LogtestService

**Path**: `cti/catalog/service/LogtestService.java`

The orchestrator. Provides three public entry points:

- **`executeLogtest()`** — Full combined flow (normalization + detection)
- **`executeNormalization()`** — Engine-only: forwards payload to `EngineService.logtest()` and returns the response directly with `parseMessageAsJson()`
- **`executeDetection()`** — SAP-only: looks up integration, fetches rule IDs/bodies, evaluates via `SecurityAnalyticsService.evaluateRules()`, and returns the SAP result

The full logtest flow:

1. **No-integration shortcut** — If `integrationId` is `null`, delegates to `executeEngineOnly()`: runs the Engine normalization and returns the result with `detection.status: "skipped"` and `reason: "No integration provided"`. Steps 2–5 below are skipped.
2. **Integration lookup** — Queries `.cti-integrations` for a document matching `document.id == integrationId` and `space.name == space`. Returns 400 if not found.
3. **Engine processing** — Sends the event payload to the Wazuh Engine via `EngineService.logtest()`. Extracts the normalized event from the `output` field. The engine result fields (`output`, `asset_traces`, `validation`) are included directly in the response (no wrapper).
4. **Rule fetching** — Extracts rule IDs from the integration's `document.rules` array, then fetches rule bodies from `.cti-rules` by `document.id`, filtered by the same space.
5. **SAP evaluation** — Passes the normalized event JSON and rule bodies to `SecurityAnalyticsService.evaluateRules()`.
6. **Response building** — Combines engine and SAP results into a single JSON response under the keys `normalization` and `detection`.

**Error handling**:
- If the Engine fails (HTTP error or exception), SAP evaluation is **skipped** and the response includes `status: "skipped"` with the reason.
- If no integration is provided, detection is skipped (normalization-only mode).
- If the integration has no rules, SAP returns `rules_evaluated: 0, rules_matched: 0` with success status.
- If SAP evaluation returns unparseable JSON, the SAP result is `status: "error"`.

### SecurityAnalyticsService / EventMatcher

The SAP evaluation happens in the `security-analytics`:

- **`SecurityAnalyticsServiceImpl.evaluateRules()`** — Parses Sigma rule YAML strings into `SigmaRule` objects, then delegates to `EventMatcher`.
- **`EventMatcher.evaluate()`** — Flattens the normalized event JSON into dot-notation keys, then evaluates each rule's detection conditions against the flat map. Returns a JSON result string.

The `EventMatcher` handles:
- Field-equals-value conditions (exact match, case-insensitive)
- Keyword (value-only) conditions (searches all event fields)
- Wildcards (`*` for multi-char, `?` for single-char) via cached compiled regex patterns
- String modifiers: `contains`, `startswith`, `endswith`
- Explicit regex (`re` modifier)
- CIDR subnet matching (IPv4 and IPv6)
- Boolean, numeric (gt, gte, lt, lte), null, and string comparisons
- Composite conditions: AND, OR, NOT
- List values (any element matching counts as a match)

Match results use a nested `rule` object per match entry:
```json
{
  "rule": { "id": "...", "title": "...", "level": "...", "tags": [...] },
  "matched_conditions": [...]
}
```

## Data Flow

```
Client request
    │
    ▼
RestPostLogtestAction (combined)
    │  validates request
    │  strips "integration" field
    ▼
LogtestService.executeLogtest(integrationId, space, payload)
    │
    ├──► [if integrationId == null]
    │       → executeEngineOnly(payload)
    │       → returns normalization + detection: { status: "skipped" }
    │
    ├──► client.prepareSearch(".cti-integrations")
    │       → finds integration in given space (test or standard)
    │       → extracts rule IDs from document.rules
    │
    ├──► engineService.logtest(payload)
    │       → sends to Wazuh Engine socket
    │       → receives normalized event
    │       → extracts "output" node as normalized event JSON
    │
    ├──► client.prepareSearch(".cti-rules")
    │       → fetches rule bodies by document.id + space filter
    │
    ├──► securityAnalytics.evaluateRules(normalizedEventJson, ruleBodies)
    │       → parses YAML → SigmaRule objects
    │       → EventMatcher flattens event + evaluates conditions
    │       → returns JSON result
    │
    └──► builds combined response
            { normalization: {...}, detection: {...} }
```

### Split Endpoints

In addition to the combined flow, there are two dedicated endpoints that execute normalization and detection independently:

```
RestPostLogtestNormalizationAction           RestPostLogtestDetectionAction
    │  validates: space                          │  validates: space, integration, input
    │  strips integration field                  │
    ▼                                            ▼
LogtestService.executeNormalization(payload)  LogtestService.executeDetection(id, space, input)
    │                                            │
    └──► engineService.logtest(payload)          ├──► client.prepareSearch(".cti-integrations")
         → returns engine response directly      │       → finds integration
                                                 ├──► extractRuleIds() + fetchRuleBodies()
                                                 │       → fetches rule content from .cti-rules
                                                 └──► securityAnalytics.evaluateRules(inputJson, ruleBodies)
                                                         → returns SAP result directly
```

**Key differences from the combined endpoint:**
- **Normalization** returns the raw Engine response (no detection wrapper). The `integration` field is stripped if present but has no effect on behavior.
- **Detection** accepts a pre-normalized event as the `input` JSON object. It does not call the Engine — it goes straight to integration lookup → rule fetch → SAP evaluation.

## Index Dependencies

| Index | Usage | Query |
| --- | --- | --- |
| `.cti-integrations` | Look up integration by ID in the given space | `document.id == X AND space.name == {space}` |
| `.cti-rules` | Fetch rule bodies by document IDs in the given space | `document.id IN [...] AND space.name == {space}` |

Both indices must exist and have `document.id` mapped as `keyword` for term queries to work.

## Testing

### Unit Tests

| Test class | Covers |
| --- | --- |
| `RestPostLogtestActionTests` | Request validation for combined endpoint (empty body, invalid JSON, missing fields, wrong space, delegation to service) |
| `RestPostLogtestNormalizationActionTests` | Request validation for normalization endpoint (empty body, invalid JSON, missing space, invalid space, delegation, integration stripping) |
| `RestPostLogtestDetectionActionTests` | Request validation for detection endpoint (empty body, invalid JSON, missing fields, invalid space, non-object input, delegation) |
| `LogtestServiceTests` | Orchestration logic (integration lookup, engine errors, rule fetching, SAP evaluation, response structure) |
| `EventMatcherTests` | Sigma rule evaluation (field matching, wildcards, numerics, booleans, nulls, AND/OR/NOT conditions) |

### Integration Tests

| Test class | Covers |
| --- | --- |
| `LogtestIT` | End-to-end REST workflow against a live test cluster (request validation, integration lookup, promote + logtest, response structure) |

Integration tests extend `ContentManagerRestTestCase` and run against a real OpenSearch cluster. Since the Wazuh Engine is not available in the test environment, engine-dependent tests validate graceful error handling (engine error → SAP skipped).


## Adding New Logtest Features

### Supporting a new validation field

1. Add the field constant to `Constants.java`.
2. Add validation logic in the relevant handler(s): `RestPostLogtestAction`, `RestPostLogtestNormalizationAction`, and/or `RestPostLogtestDetectionAction`.
3. Add unit tests in the corresponding test classes.
4. Add integration test in `LogtestIT`.

### Supporting a new Engine response field

1. Update `LogtestService.executeEngine()` to extract the field.
2. Include it in the `normalization` map within `buildCombinedResponse()`.
3. Add unit test scenarios in `LogtestServiceTests`.
4. Update the API docs (`api.md`) response fields table.

### Extending SAP evaluation

1. Modify `EventMatcher.matchValue()` to handle new `SigmaType` subclasses.
2. Add test cases in `EventMatcherTests`.
3. Update the Sigma rules doc (`sigma-rules.md`) if new detection modifiers are supported.

