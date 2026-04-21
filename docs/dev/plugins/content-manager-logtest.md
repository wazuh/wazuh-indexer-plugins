# Logtest Architecture and Developer Guide

## Component Overview

The logtest flow involves three layers:

```
RestPostLogtestAction  →  LogtestService  →  EngineService + SecurityAnalyticsService
       (REST)              (Orchestration)       (External services)
```

### RestPostLogtestAction

**Path**: `rest/service/RestPostLogtestAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest`. Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required field `space`.
3. Validates that `space` is `"test"` or `"standard"`.
4. Extracts the optional `integration` field (if present) and strips it from the Engine payload.
5. Delegates to `LogtestService.executeLogtest(integrationId, space, enginePayload)`.
   If `integrationId` is `null`, only engine normalization is performed.

The handler does **not** interact with indices or external services directly, all business logic is in the service.

### LogtestService

**Path**: `cti/catalog/service/LogtestService.java`

The orchestrator. Executes the full logtest flow:

1. **No-integration shortcut** — If `integrationId` is `null`, delegates to `executeEngineOnly()`: runs the Engine normalization and returns the result with `detection.status: "skipped"` and `reason: "No integration provided"`. Steps 2–5 below are skipped.
2. **Integration lookup** — Queries `wazuh-threatintel-integrations` for a document matching `document.id == integrationId` and `space.name == space`. Returns 400 if not found.
3. **Engine processing** — Sends the event payload to the Wazuh Engine via `EngineService.logtest()`. Extracts the normalized event from the `output` field. The engine result fields (`output`, `asset_traces`, `validation`) are included directly in the response (no wrapper).
4. **Rule fetching** — Extracts rule IDs from the integration's `document.rules` array, then fetches rule bodies from `wazuh-threatintel-rules` by `document.id`, filtered by the same space.
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
RestPostLogtestAction
    │  validates request
    │  strips "integration" field
    ▼
LogtestService.executeLogtest(integrationId, space, payload)
    │
    ├──► [if integrationId == null]
    │       → executeEngineOnly(payload)
    │       → returns normalization + detection: { status: "skipped" }
    │
    ├──► client.prepareSearch("wazuh-threatintel-integrations")
    │       → finds integration in given space (test or standard)
    │       → extracts rule IDs from document.rules
    │
    ├──► engineService.logtest(payload)
    │       → sends to Wazuh Engine socket
    │       → receives normalized event
    │       → extracts "output" node as normalized event JSON
    │
    ├──► client.prepareSearch("wazuh-threatintel-rules")
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

## Index Dependencies

| Index | Usage | Query |
| --- | --- | --- |
| `wazuh-threatintel-integrations` | Look up integration by ID in the given space | `document.id == X AND space.name == {space}` |
| `wazuh-threatintel-rules` | Fetch rule bodies by document IDs in the given space | `document.id IN [...] AND space.name == {space}` |

Both indices must exist and have `document.id` mapped as `keyword` for term queries to work.

## Testing

### Unit Tests

| Test class | Covers |
| --- | --- |
| `RestPostLogtestActionTests` | Request validation (empty body, invalid JSON, missing fields, wrong space, delegation to service) |
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
2. Add validation logic in `RestPostLogtestAction.handleRequest()`.
3. Add unit test in `RestPostLogtestActionTests`.
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

