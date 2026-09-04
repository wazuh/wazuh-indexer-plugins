# Logtest architecture and developer guide

## Component overview

The logtest flow involves four layers: a thin REST handler, a transport action that owns request validation, an orchestration service, and the external services it calls.

```
RestPostLogtestAction               →  TransportLogtestAction               →  LogtestService  →  EngineService + SecurityAnalyticsService
RestPostLogtestNormalizationAction  →  TransportLogtestNormalizationAction  →       ↑                    ↑
RestPostLogtestDetectionAction      →  TransportLogtestDetectionAction      →       ↑                    ↑
       (REST handlers)                      (Validation)                     (Orchestration)       (External services)
```

REST handlers no longer validate requests or contain any business logic — that responsibility moved to the transport action layer. This is a plugin-wide pattern, not specific to logtest: every REST handler in `rest/service/` delegates to a same-named `Transport*Action` via `client.execute()`, per `AbstractContentAction`'s own javadoc ("Business logic has been moved to transport actions; REST handlers now delegate to the transport layer via `client.execute()`").

### RestPostLogtestAction (combined)

**Path**: `rest/service/RestPostLogtestAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest`. Before dispatch it enforces the request-body size cap via `PayloadValidations.validateLogtestBodySize(...)` — a body larger than `plugins.content_manager.logtest.max_body_bytes` is rejected with **413** at the REST layer, before parsing (see [Request size limit and concurrency](#request-size-limit-and-concurrency)). Otherwise it reads the raw request body into a `LogtestRequest` and calls `client.execute(LogtestAction.INSTANCE, logtestRequest, listener)`. It performs no field-level validation and does not interact with indices or external services directly.

### TransportLogtestAction

**Path**: `transport/TransportLogtestAction.java`

The validation and dispatch layer for the combined endpoint. Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required field `space`.
3. Validates that `space` is not `"draft"`.
4. Extracts the optional `integration` field (if present) and strips it from the Engine payload.
5. Delegates to `LogtestService.executeLogtest(integrationId, space, enginePayload)`.
   If `integrationId` is `null`, only engine normalization is performed.

### RestPostLogtestNormalizationAction

**Path**: `rest/service/RestPostLogtestNormalizationAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest/normalization`. Enforces the body-size cap (413) the same way as the combined handler, then reads the request body and calls `client.execute(LogtestNormalizationAction.INSTANCE, ...)`. No field-level validation.

### TransportLogtestNormalizationAction

**Path**: `transport/TransportLogtestNormalizationAction.java`

Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required field `space`.
3. Validates that `space` is not `"draft"`.
4. Strips the `integration` field if present (not used for normalization).
5. Delegates to `LogtestService.executeNormalization(enginePayload)`.

### RestPostLogtestDetectionAction

**Path**: `rest/service/RestPostLogtestDetectionAction.java`

The REST handler for `POST /_plugins/_content_manager/logtest/detection`. Enforces the body-size cap (413) the same way as the combined handler, then reads the request body and calls `client.execute(LogtestDetectionAction.INSTANCE, ...)`. No field-level validation.

### TransportLogtestDetectionAction

**Path**: `transport/TransportLogtestDetectionAction.java`

Responsibilities:

1. Validates the request has content and is valid JSON.
2. Validates the required fields `space`, `integration`, and `input`.
3. Validates that `space` is not `"draft"`.
4. Validates that `input` is a JSON object (not a string or array).
5. Delegates to `LogtestService.executeDetection(integrationId, space, inputEvent)`.

All three transport actions run this work on the dedicated `content_manager_logtest` thread pool rather than the transport thread (see [Request size limit and concurrency](#request-size-limit-and-concurrency)).

### Request size limit and concurrency

The logtest endpoints are deliberately reachable by low-privilege accounts. To keep that surface from being used to exhaust the indexer's heap, two independent controls bound the work each request can cause:

- **Body-size cap (413).** Every logtest REST handler checks the raw request-body length against `plugins.content_manager.logtest.max_body_bytes` (default 1 MiB; dynamic; range 1 KiB–16 MiB) before parsing or dispatching, via the shared `PayloadValidations.validateLogtestBodySize(...)` helper. An oversized body is rejected with **413 `REQUEST_ENTITY_TOO_LARGE`** and the message `logtest payload exceeds the maximum allowed size of <N> bytes.`, and the offending account and size are logged at `WARN`. This removes the input-to-response amplification the endpoint would otherwise permit, since the input is bounded before any work happens.
- **Bounded thread pool (429).** The three transport actions offload execution onto a dedicated `FixedExecutorBuilder` pool named `content_manager_logtest` (size `max(1, allocatedProcessors / 2)`, queue 100), registered in `ContentManagerPlugin.getExecutorBuilders(...)`. This keeps the blocking Engine-socket call off the transport threads, and when the bounded queue is full excess requests are shed with **429 `TOO_MANY_REQUESTS`** (`logtest is busy: too many concurrent requests. Please retry later.`) instead of accumulating on the heap. Worst-case in-flight payload is bounded to roughly `(pool size + queue) * max_body_bytes`.

### LogtestService

**Path**: `cti/catalog/service/LogtestService.java`

The orchestrator. Provides three public entry points:

- **`executeLogtest()`** — Full combined flow (normalization + detection)
- **`executeNormalization()`** — Engine-only: forwards payload to `EngineService.logtest()` and returns the response directly with `parseMessageAsJson()`
- **`executeDetection()`** — Security Analytics-only: looks up integration, fetches rule IDs/bodies, evaluates via `SecurityAnalyticsService.evaluateRules()`, and returns the result

The full logtest flow:

1. **No-integration shortcut** — If `integrationId` is `null`, delegates to `executeEngineOnly()`: runs the Engine normalization and returns the result with `detection.status: "skipped"` and `reason: "No integration provided"`. Steps 2–5 below are skipped.
2. **Integration lookup** — Queries `wazuh-threatintel-integrations` for a document matching `document.id == integrationId` and `space.name == space`. Returns 400 if not found.
3. **Engine processing** — Sends the event payload to the Wazuh Engine via `EngineService.logtest()`. Extracts the normalized event from the `output` field. The engine result fields (`output`, `asset_traces`, `validation`) are included directly in the response (no wrapper).
4. **Rule fetching** — Extracts rule IDs from the integration's `document.rules` array, then fetches rule bodies from `wazuh-threatintel-rules` by `document.id`, filtered by the same space.
5. **Security Analytics evaluation** — Passes the normalized event JSON and rule bodies to `SecurityAnalyticsService.evaluateRules()`.
6. **Response building** — Combines engine and Security Analytics results into a single JSON response under the keys `normalization` and `detection`.

**Error handling**:
- If the Engine fails (HTTP error or exception), Security Analytics evaluation is **skipped** and the response includes `status: "skipped"` with the reason.
- If no integration is provided, detection is skipped (normalization-only mode).
- If the integration has no rules, Security Analytics returns `rules_evaluated: 0, rules_matched: 0` with success status.
- If Security Analytics evaluation returns unparseable JSON, the result is `status: "error"`.

### SecurityAnalyticsService / EventMatcher

The Security Analytics evaluation happens in the `security-analytics` repository:

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

## Data flow

```
Client request
    │
    ▼
RestPostLogtestAction (combined)
    │  reads body into LogtestRequest, no validation
    │  client.execute(LogtestAction.INSTANCE, ...)
    ▼
TransportLogtestAction
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

### Split endpoints

In addition to the combined flow, there are two dedicated endpoints that execute normalization and detection independently:

```
RestPostLogtestNormalizationAction           RestPostLogtestDetectionAction
    │  no validation, delegates via client.execute()  │  no validation, delegates via client.execute()
    ▼                                            ▼
TransportLogtestNormalizationAction          TransportLogtestDetectionAction
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
                                                         → returns Security Analytics result directly
```

#### Key differences from the combined endpoint
- **Normalization** returns the raw Engine response (no detection wrapper). The `integration` field is stripped if present but has no effect on behavior.
- **Detection** accepts a pre-normalized event as the `input` JSON object. It does not call the Engine — it goes straight to integration lookup → rule fetch → Security Analytics evaluation.

## Index dependencies

| Index | Usage | Query |
| --- | --- | --- |
| `wazuh-threatintel-integrations` | Look up integration by ID in the given space | `document.id == X AND space.name == {space}` |
| `wazuh-threatintel-rules` | Fetch rule bodies by document IDs in the given space | `document.id IN [...] AND space.name == {space}` |

Both indices must exist and have `document.id` mapped as `keyword` for term queries to work.

## Testing

### Unit tests

| Test class | Covers |
| --- | --- |
| `TransportLogtestActionTests` | Request validation for combined endpoint (empty body, invalid JSON, missing fields, wrong space, delegation to service) |
| `TransportLogtestNormalizationActionTests` | Request validation for normalization endpoint (empty body, invalid JSON, missing space, invalid space, delegation, integration stripping) |
| `TransportLogtestDetectionActionTests` | Request validation for detection endpoint (empty body, invalid JSON, missing fields, invalid space, non-object input, delegation) |
| `LogtestServiceTests` | Orchestration logic (integration lookup, engine errors, rule fetching, Security Analytics evaluation, response structure) |
| `EventMatcherTests` | Sigma rule evaluation (field matching, wildcards, numerics, booleans, nulls, AND/OR/NOT conditions) |

### Integration tests

| Test class | Covers |
| --- | --- |
| `LogtestIT` | End-to-end REST workflow against a live test cluster (request validation, integration lookup, promote + logtest, response structure) |

Integration tests extend `ContentManagerRestTestCase` and run against a real OpenSearch cluster. Since the Wazuh Engine is not available in the test environment, engine-dependent tests validate graceful error handling (engine error → Security Analytics skipped).


## Adding new logtest features

### Supporting a new validation field

1. Add the field constant to `Constants.java`.
2. Add validation logic in the relevant transport action(s): `TransportLogtestAction`, `TransportLogtestNormalizationAction`, and/or `TransportLogtestDetectionAction`. The REST handlers themselves need no changes — they only read the body and dispatch.
3. Add unit tests in the corresponding test classes.
4. Add integration test in `LogtestIT`.

### Supporting a new Engine response field

1. Update `LogtestService.executeEngine()` to extract the field.
2. Include it in the `normalization` map within `buildCombinedResponse()`.
3. Add unit test scenarios in `LogtestServiceTests`.
4. Update the API docs (`api.md`) response fields table.

### Extending Security Analytics evaluation

1. Modify `EventMatcher.matchValue()` to handle new `SigmaType` subclasses.
2. Add test cases in `EventMatcherTests`.
3. Update the Sigma rules doc ([Sigma Rules](../../ref/modules/security-analytics/rules.md)) if new detection modifiers are supported.

