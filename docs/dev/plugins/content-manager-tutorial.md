# Tutorial: Adding a REST Endpoint to the Content Manager Plugin

This tutorial walks through adding a new REST endpoint to the Content Manager plugin, using a concrete example: **a GET endpoint to retrieve a single rule by ID**.

By the end, you will have a working `GET /_plugins/_content_manager/rules/{id}` endpoint that fetches a rule document from the `.cti-rules` index.

---

## Prerequisites

- Development environment set up (see [Setup](../setup.md))
- The project compiles: `./gradlew :wazuh-indexer-content-manager:compileJava`

---

## Step 1: Add the URI Constant

If your endpoint uses a new base URI, add it to `PluginSettings`. In this case, rules already have `RULES_URI`, and our GET endpoint uses the same base path with an `{id}` parameter, so no changes are needed.

The existing constant in `PluginSettings.java`:

```java
public static final String RULES_URI = PLUGINS_BASE_URI + "/rules";
```

Our endpoint will match `/_plugins/_content_manager/rules/{id}` using the same base URI.

---

## Step 2: Create the Handler Class

Create a new file at:

```
plugins/content-manager/src/main/java/com/wazuh/contentmanager/rest/service/RestGetRuleAction.java
```

```java
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * GET /_plugins/_content_manager/rules/{id}
 *
 * Retrieves a single rule document by its ID from the .cti-rules index.
 */
public class RestGetRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestGetRuleAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // A short identifier for log output and debugging.
    private static final String ENDPOINT_NAME = "content_manager_rule_get";

    // A unique name used by OpenSearch's named route system for access control.
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_get";

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Define the route. The {id} path parameter is automatically extracted
     * by OpenSearch and available via request.param("id").
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.RULES_URI + "/{id}")
                        .method(RestRequest.Method.GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare and execute the request. This method is called by the
     * OpenSearch REST framework for each incoming request.
     *
     * @param request the incoming REST request
     * @param client  the node client for index operations
     * @return a RestChannelConsumer that writes the response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // Extract the {id} path parameter.
        String id = request.param(Constants.KEY_ID);

        return channel -> {
            try {
                // Validate the ID parameter is present.
                if (id == null || id.isBlank()) {
                    channel.sendResponse(new BytesRestResponse(
                            RestStatus.BAD_REQUEST,
                            "application/json",
                            "{\"error\": \"Missing required parameter: id\"}"));
                    return;
                }

                // Use ContentIndex to retrieve the document.
                ContentIndex index = new ContentIndex(client, Constants.INDEX_RULES, null);
                JsonNode document = index.getDocument(id);

                if (document == null) {
                    channel.sendResponse(new BytesRestResponse(
                            RestStatus.NOT_FOUND,
                            "application/json",
                            "{\"error\": \"Rule not found: " + id + "\"}"));
                    return;
                }

                // Return the document as JSON.
                String responseBody = MAPPER.writeValueAsString(document);
                channel.sendResponse(new BytesRestResponse(
                        RestStatus.OK,
                        "application/json",
                        responseBody));

            } catch (Exception e) {
                log.error("Failed to retrieve rule [{}]: {}", id, e.getMessage(), e);
                channel.sendResponse(new BytesRestResponse(
                        RestStatus.INTERNAL_SERVER_ERROR,
                        "application/json",
                        "{\"error\": \"Internal server error: " + e.getMessage() + "\"}"));
            }
        };
    }
}
```

### Key Concepts

- **`getName()`** — Returns a short identifier used in logs and debugging.
- **`routes()`** — Defines the HTTP method and URI pattern. Uses `NamedRoute.Builder` which requires a `uniqueName` for OpenSearch's access control system.
- **`prepareRequest()`** — The core method. Returns a `RestChannelConsumer` lambda that executes asynchronously and writes the response to the channel.
- **Path parameters** — `{id}` in the route path is automatically parsed. Access it with `request.param("id")`.

---

## Step 3: Register the Handler

Open `ContentManagerPlugin.java` and add the new handler to `getRestHandlers()`:

```java
@Override
public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster) {
    return List.of(
            // ... existing handlers ...

            // Rule endpoints
            new RestPostRuleAction(),
            new RestPutRuleAction(),
            new RestDeleteRuleAction(),
            new RestGetRuleAction(),  // <-- Add the new handler

            // ... remaining handlers ...
    );
}
```

Make sure to add the import at the top of the file:

```java
import com.wazuh.contentmanager.rest.service.RestGetRuleAction;
```

---

## Step 4: Build and Verify

Compile the plugin to check for errors:

```bash
./gradlew :wazuh-indexer-content-manager:compileJava
```

If compilation succeeds, run the full build (including tests):

```bash
./gradlew :wazuh-indexer-content-manager:build
```

---

## Step 5: Test the Endpoint

### Manual Testing

Start a local cluster (see [tools/test-cluster](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools/test-cluster)) and test:

```bash
# Create a rule first (so there's something to fetch)
curl -X POST "https://localhost:9200/_plugins/_content_manager/rules" \
  -H "Content-Type: application/json" \
  -u admin:admin --insecure \
  -d '{
    "integration": "<integration-id>",
    "resource": {
      "title": "Test Rule"
    }
  }'

# The response returns the UUID. Use it to fetch:
curl -X GET "https://localhost:9200/_plugins/_content_manager/rules/<uuid>" \
  -u admin:admin --insecure
```

### Writing a Unit Test

Create a test file at:

```
plugins/content-manager/src/test/java/com/wazuh/contentmanager/rest/service/RestGetRuleActionTests.java
```

At minimum, test that `getName()` and `routes()` return expected values:

```java
package com.wazuh.contentmanager.rest.service;

import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;

public class RestGetRuleActionTests extends OpenSearchTestCase {

    public void testGetName() {
        RestGetRuleAction action = new RestGetRuleAction();
        assertEquals("content_manager_rule_get", action.getName());
    }

    public void testRoutes() {
        RestGetRuleAction action = new RestGetRuleAction();
        assertEquals(1, action.routes().size());
        assertEquals(RestRequest.Method.GET, action.routes().get(0).getMethod());
        assertTrue(action.routes().get(0).getPath().contains("/rules/{id}"));
    }
}
```

Run:

```bash
./gradlew :wazuh-indexer-content-manager:test
```

---

## Summary

To add a new REST endpoint to the Content Manager plugin:

1. **Create the handler class** — Extend `BaseRestHandler` (for simple endpoints) or one of the abstract classes (`AbstractCreateAction`, `AbstractUpdateAction`, `AbstractDeleteAction`) for standard CUD.
2. **Define routes** — Use `NamedRoute.Builder` with a unique name.
3. **Implement logic** — Override `prepareRequest()` (or `executeRequest()` if extending the abstract hierarchy).
4. **Register** — Add the instance to `ContentManagerPlugin.getRestHandlers()`.
5. **Build and test** — `./gradlew :wazuh-indexer-content-manager:compileJava` then `./gradlew :wazuh-indexer-content-manager:test`.

For content CUD endpoints that need Draft space validation, Engine sync, and hash updates, extend `AbstractContentAction` or one of its children instead of `BaseRestHandler` directly.
