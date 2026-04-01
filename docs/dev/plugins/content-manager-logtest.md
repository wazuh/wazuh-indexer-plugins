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
2. Validates required fields (`integration`, `space`).
3. Validates that `space` is exactly `"test"`.
4. Strips the `integration` field from the payload (it's not part of the Engine request).
5. Delegates to `LogtestService.executeLogtest(integrationId, enginePayload)`.

The handler does **not** interact with indices or external services directly, all business logic is in the service.

### LogtestService

**Path**: `cti/catalog/service/LogtestService.java`

The orchestrator. Executes the full logtest flow:

1. **Integration lookup** — Queries `.cti-integrations` for a document matching `document.id == integrationId` and `space.name == "test"`. Returns 400 if not found.
2. **Engine processing** — Sends the event payload to the Wazuh Engine via `EngineService.logtest()`. Extracts the normalized event from the `output` field.
3. **Rule fetching** — Extracts rule IDs from the integration's `document.rules` array, then fetches rule bodies from `.cti-rules` by `document.id`.
4. **SAP evaluation** — Passes the normalized event JSON and rule bodies to `SecurityAnalyticsService.evaluateRules()`.
5. **Response building** — Combines engine and SAP results into a single JSON response.

**Error handling**:
- If the Engine fails (HTTP error or exception), SAP evaluation is **skipped** and the response includes `status: "skipped"` with the reason.
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
- Boolean, numeric, null, and string comparisons
- Composite conditions: AND, OR, NOT
- List values (any element matching counts as a match)

## Data Flow

```
Client request
    │
    ▼
RestPostLogtestAction
    │  validates request
    │  strips "integration" field
    ▼
LogtestService.executeLogtest(integrationId, payload)
    │
    ├──► client.prepareSearch(".cti-integrations")
    │       → finds integration in test space
    │       → extracts rule IDs from document.rules
    │
    ├──► engineService.logtest(payload)
    │       → sends to Wazuh Engine socket
    │       → receives normalized event
    │       → extracts "output" node as normalized event JSON
    │
    ├──► client.prepareSearch(".cti-rules")
    │       → fetches rule bodies by document.id
    │
    ├──► securityAnalytics.evaluateRules(normalizedEventJson, ruleBodies)
    │       → parses YAML → SigmaRule objects
    │       → EventMatcher flattens event + evaluates conditions
    │       → returns JSON result
    │
    └──► builds combined response
            { engine_result: {...}, security_analytics_result: {...} }
```

## Index Dependencies

| Index | Usage | Query |
| --- | --- | --- |
| `.cti-integrations` | Look up integration by ID in test space | `document.id == X AND space.name == "test"` |
| `.cti-rules` | Fetch rule bodies by document IDs | `document.id IN [...]` |

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
2. Include it in the `engine_result` map within `buildCombinedResponse()` or `buildMatchEntry()`.
3. Add unit test scenarios in `LogtestServiceTests`.
4. Update the API docs (`api.md`) response fields table.

### Extending SAP evaluation

1. Modify `EventMatcher.matchValue()` to handle new `SigmaType` subclasses.
2. Add test cases in `EventMatcherTests`.
3. Update the Sigma rules doc (`sigma-rules.md`) if new detection modifiers are supported.

