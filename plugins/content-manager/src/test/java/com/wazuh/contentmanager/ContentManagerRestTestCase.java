/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.WarningsHandler;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Base class for Content Manager REST integration tests.
 *
 * <p>Provides shared helper methods for making REST requests, parsing responses, managing test
 * resources, and making assertions on Content Manager index documents.
 *
 * <p>Follows the OpenSearch plugin integration test pattern using {@link OpenSearchRestTestCase}.
 * Each test class extending this base runs against a real OpenSearch test cluster with the Content
 * Manager plugin installed.
 */
public abstract class ContentManagerRestTestCase extends OpenSearchRestTestCase {

    protected static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Prevents the test framework from deleting all indices after each test. The Content Manager
     * plugin requires persistent indices (in particular {@code .cti-policies}) to function. The
     * default behaviour would wipe them between tests, forcing costly re-creation and causing race
     * conditions with the plugin's internal validation.
     */
    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    // ========================
    // Test Setup
    // ========================

    /**
     * Seeds the test environment by ensuring the policies index exists.
     *
     * <p>The Content Manager plugin requires the {@code .cti-policies} index with policy documents
     * for all spaces before any REST endpoint can be used. In production this index is created by the
     * CTI synchronization process, but in test clusters we must seed it manually.
     *
     * <p>This method is a separate {@code @Before} method (not a {@code setUp()} override) to
     * guarantee it runs after the parent's {@code initClient()} has initialized the REST client.
     *
     * @throws IOException if the setup requests fail
     */
    @Before
    public void seedPoliciesIndex() throws IOException {
        ensureRequiredIndicesExist();
    }

    /**
     * Creates a resource index with the hidden setting if it does not already exist. These indices
     * are normally created during CTI catalog sync but the plugin's validation code requires them.
     * Mappings ensure that key fields are of type {@code keyword} so that term queries work correctly
     * (dynamic mapping would otherwise create {@code text} fields).
     */
    private void ensureIndexExists(String indexName) throws IOException {
        // spotless:off
        String body = """
                {
                    "settings": {"index": {"hidden": true, "number_of_replicas": 0}},
                    "mappings": {
                        "dynamic": "true",
                        "properties": {
                            "document": {
                                "properties": {
                                    "id":       {"type": "keyword"},
                                    "title":    {"type": "keyword"},
                                    "decoders": {"type": "keyword"},
                                    "rules":    {"type": "keyword"},
                                    "kvdbs":    {"type": "keyword"}
                                }
                            },
                            "space": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "hash": {
                                        "properties": {
                                            "sha256": {"type": "keyword"}
                                        }
                                    }
                                }
                            },
                            "hash": {
                                "properties": {
                                    "sha256": {"type": "keyword"}
                                }
                            }
                        }
                    }
                }
                """;
        // spotless:on
        try {
            makeRequest("PUT", "/" + indexName, body);
        } catch (ResponseException e) {
            // 400 resource_already_exists_exception is expected on subsequent tests
            if (e.getResponse().getStatusLine().getStatusCode() != 400) {
                throw e;
            }
        }
    }

    /**
     * Creates all required indices and seeds policy documents. Policy documents are always re-seeded
     * using deterministic document IDs so that tests which modify the draft policy (e.g. PUT policy
     * tests) do not corrupt state for tests that read initial values.
     */
    private void ensureRequiredIndicesExist() throws IOException {
        // Ensure resource indices exist (plugin validation needs them)
        ensureIndexExists(Constants.INDEX_INTEGRATIONS);
        ensureIndexExists(Constants.INDEX_DECODERS);
        ensureIndexExists(Constants.INDEX_RULES);
        ensureIndexExists(Constants.INDEX_KVDBS);
        ensureIndexExists(Constants.INDEX_IOCS);
        ensureIndexExists(Constants.INDEX_FILTERS);

        // Create the policies index if it does not exist
        // spotless:off
        String indexBody = """
                {
                    "mappings": {
                        "dynamic": "true",
                        "properties": {
                            "document": {
                                "properties": {
                                    "id": { "type": "keyword" },
                                    "root_decoder": { "type": "keyword" },
                                    "date": { "type": "date" },
                                    "modified": { "type": "date" },
                                    "author": { "type": "keyword" },
                                    "description": { "type": "text" },
                                    "references": { "type": "keyword" },
                                    "documentation": { "type": "keyword" },
                                    "integrations": { "type": "keyword" },
                                    "filters": { "type": "keyword" },
                                    "enrichments": { "type": "keyword" },
                                    "title": { "type": "keyword" }
                                }
                            },
                            "hash": {
                                "type": "object",
                                "properties": {
                                    "sha256": { "type": "keyword" }
                                }
                            },
                            "space": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "keyword" },
                                    "hash": {
                                        "type": "object",
                                        "properties": {
                                            "sha256": { "type": "keyword" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """;
        // spotless:on
        try {
            makeRequest("PUT", Constants.INDEX_POLICIES, indexBody);
        } catch (ResponseException e) {
            // Index may already exist — 400 resource_already_exists_exception is OK
            if (e.getResponse().getStatusLine().getStatusCode() != 400) {
                throw e;
            }
        }

        // Always re-seed policy documents using deterministic IDs so they overwrite
        // any modifications made by prior tests (e.g. PUT policy tests).
        String documentId = "00000000-0000-0000-0000-000000000000";
        String date = "2025-01-01T00:00:00Z";
        String hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String[] spaces = {"draft", "test", "custom", "standard"};

        for (String space : spaces) {
            // spotless:off
            String doc = String.format(Locale.ROOT, """
                    {
                        "document": {
                            "id": "%s",
                            "title": "Custom policy",
                            "date": "%s",
                            "modified": "%s",
                            "root_decoder": "",
                            "integrations": [],
                            "filters": [],
                            "enrichments": [],
                            "author": "Wazuh Inc.",
                            "description": "Custom policy",
                            "documentation": "",
                            "references": ["https://wazuh.com"]
                        },
                        "hash": {
                            "sha256": "%s"
                        },
                        "space": {
                            "name": "%s",
                            "hash": {
                                "sha256": "%s"
                            }
                        }
                    }
                    """, documentId, date, date, hash, space, hash);
            // spotless:on
            makeRequest(
                    "PUT",
                    String.format(
                            Locale.ROOT, "%s/_doc/policy-%s?refresh=true", Constants.INDEX_POLICIES, space),
                    doc);
        }
    }

    // ========================
    // REST Request Helpers
    // ========================

    /**
     * Makes a REST request with a JSON entity body.
     *
     * @param method HTTP method (GET, POST, PUT, DELETE)
     * @param endpoint Target endpoint URI
     * @param jsonEntity JSON string for the request body (may be null)
     * @param params Query parameters
     * @return the HTTP Response
     * @throws IOException on communication error
     */
    protected Response makeRequest(
            String method, String endpoint, String jsonEntity, Map<String, String> params)
            throws IOException {
        Request request = new Request(method, endpoint);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
        request.setOptions(options);

        if (params != null) {
            params.forEach(request::addParameter);
        }

        if (jsonEntity != null) {
            request.setJsonEntity(jsonEntity);
        }

        return client().performRequest(request);
    }

    /**
     * Makes a REST request with default empty params.
     *
     * @param method HTTP method
     * @param endpoint Target endpoint URI
     * @param jsonEntity JSON string for the request body
     * @return the HTTP Response
     * @throws IOException on communication error
     */
    protected Response makeRequest(String method, String endpoint, String jsonEntity)
            throws IOException {
        return makeRequest(method, endpoint, jsonEntity, Collections.emptyMap());
    }

    /**
     * Makes a REST request without body.
     *
     * @param method HTTP method
     * @param endpoint Target endpoint URI
     * @return the HTTP Response
     * @throws IOException on communication error
     */
    protected Response makeRequest(String method, String endpoint) throws IOException {
        return makeRequest(method, endpoint, null, Collections.emptyMap());
    }

    // ========================
    // Response Parsing Helpers
    // ========================

    /**
     * Parses the HTTP response body as a JSON map using Jackson.
     *
     * @param response the HTTP response
     * @return parsed JSON as Map
     * @throws IOException on parsing error
     */
    protected Map<String, Object> parseResponseAsMap(Response response) throws IOException {
        try (InputStream is = response.getEntity().getContent()) {
            return MAPPER.readValue(is, new TypeReference<>() {});
        }
    }

    /**
     * Parses the HTTP response body as a Jackson JsonNode.
     *
     * @param response the HTTP response
     * @return parsed JSON node
     * @throws IOException on parsing error
     */
    protected JsonNode responseAsJson(Response response) throws IOException {
        try (InputStream is = response.getEntity().getContent()) {
            return MAPPER.readTree(is);
        }
    }

    /**
     * Gets the HTTP status code from a response.
     *
     * @param response the HTTP response
     * @return integer status code
     */
    protected int getStatusCode(Response response) {
        return response.getStatusLine().getStatusCode();
    }

    // ========================
    // Index Operations
    // ========================

    /**
     * Refreshes an index to make recently indexed documents searchable.
     *
     * @param indexName name of the index to refresh
     * @throws IOException on communication error
     */
    protected void refreshIndex(String indexName) throws IOException {
        makeRequest("POST", indexName + "/_refresh");
    }

    /**
     * Searches an index with the given query JSON.
     *
     * @param indexName target index
     * @param queryJson JSON query (full search body)
     * @return search response as JsonNode
     * @throws IOException on communication error
     */
    protected JsonNode searchIndex(String indexName, String queryJson) throws IOException {
        refreshIndex(indexName);
        Response response = makeRequest("GET", indexName + "/_search", queryJson);
        return responseAsJson(response);
    }

    /**
     * Searches an index for documents matching a term query.
     *
     * @param indexName target index
     * @param field field to filter on
     * @param value expected value
     * @return search response as JsonNode
     * @throws IOException on communication error
     */
    protected JsonNode searchByTerm(String indexName, String field, String value) throws IOException {
        // spotless:off
        String query = """
                {
                    "query": {
                        "term": {
                            "%s": "%s"
                        }
                    }
                }
                """;
        query = String.format(Locale.ROOT, query, field, value);
        // spotless:on
        return searchIndex(indexName, query);
    }

    /**
     * Gets all documents from an index.
     *
     * @param indexName target index
     * @return search response as JsonNode
     * @throws IOException on communication error
     */
    protected JsonNode getAllDocuments(String indexName) throws IOException {
        return searchIndex(indexName, "{\"query\":{\"match_all\":{}}}");
    }

    /**
     * Gets a specific document by ID from an index.
     *
     * @param indexName target index
     * @param documentId document ID
     * @return document as JsonNode, or null if not found
     * @throws IOException on communication error
     */
    protected JsonNode getDocument(String indexName, String documentId) throws IOException {
        try {
            Response response = makeRequest("GET", indexName + "/_doc/" + documentId);
            return responseAsJson(response);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Checks whether a document exists in a given index.
     *
     * @param indexName target index
     * @param documentId document ID
     * @return true if the document exists
     * @throws IOException on communication error
     */
    protected boolean documentExists(String indexName, String documentId) throws IOException {
        JsonNode doc = getDocument(indexName, documentId);
        return doc != null && doc.path("found").asBoolean(false);
    }

    // ========================
    // Draft Policy Helpers
    // ========================

    /**
     * Retrieves the draft space policy document.
     *
     * @return the draft policy document source as JsonNode
     * @throws IOException on communication error
     */
    protected JsonNode getDraftPolicy() throws IOException {
        JsonNode searchResult = searchByTerm(Constants.INDEX_POLICIES, "space.name", "draft");
        JsonNode hits = searchResult.path("hits").path("hits");
        assertTrue("Draft policy should exist", hits.size() > 0);
        return hits.get(0).path("_source");
    }

    /**
     * Retrieves the policy document for a given space.
     *
     * @param spaceName space name (draft, test, custom, standard)
     * @return the policy document source as JsonNode
     * @throws IOException on communication error
     */
    protected JsonNode getPolicy(String spaceName) throws IOException {
        JsonNode searchResult = searchByTerm(Constants.INDEX_POLICIES, "space.name", spaceName);
        JsonNode hits = searchResult.path("hits").path("hits");
        assertTrue("Policy for space '" + spaceName + "' should exist", hits.size() > 0);
        return hits.get(0).path("_source");
    }

    /**
     * Gets the draft policy's space hash.
     *
     * @return the SHA-256 space hash string
     * @throws IOException on communication error
     */
    protected String getDraftPolicySpaceHash() throws IOException {
        JsonNode policy = getDraftPolicy();
        return policy
                .path(Constants.KEY_SPACE)
                .path(Constants.KEY_HASH)
                .path(Constants.KEY_SHA256)
                .asText();
    }

    /**
     * Gets the draft policy's document hash.
     *
     * @return the SHA-256 document hash string
     * @throws IOException on communication error
     */
    protected String getDraftPolicyDocumentHash() throws IOException {
        JsonNode policy = getDraftPolicy();
        return policy.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
    }

    /**
     * Gets the list of integration IDs from the draft policy.
     *
     * @return list of integration ID strings
     * @throws IOException on communication error
     */
    protected List<String> getDraftPolicyIntegrations() throws IOException {
        JsonNode policy = getDraftPolicy();
        JsonNode integrations = policy.path(Constants.KEY_DOCUMENT).path(Constants.KEY_INTEGRATIONS);
        return MAPPER.convertValue(integrations, new TypeReference<>() {});
    }

    // ========================
    // Resource Creation Helpers
    // ========================

    /**
     * Creates an integration in draft space and returns its generated ID.
     *
     * @param title the integration title
     * @return the generated integration ID
     * @throws IOException on communication error
     */
    protected String createIntegration(String title) throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "%s",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Integration test resource.",
                        "documentation": "test-doc",
                        "references": ["https://wazuh.com"],
                        "enabled": true
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, title);
        // spotless:on

        Response response = makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), getStatusCode(response));

        Map<String, Object> body = parseResponseAsMap(response);
        String id = (String) body.get("message");
        assertNotNull("Integration ID should not be null", id);
        return id;
    }

    /**
     * Creates a decoder linked to an integration in draft space and returns its generated ID.
     *
     * @param integrationId the parent integration ID
     * @return the generated decoder ID
     * @throws IOException on communication error
     */
    protected String createDecoder(String integrationId) throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "enabled": true,
                        "metadata": {
                            "author": {"name": "Wazuh, Inc."},
                            "compatibility": "All wazuh events.",
                            "description": "Test decoder for integration tests.",
                            "module": "test",
                            "references": ["https://wazuh.com"],
                            "title": "Test decoder",
                            "versions": ["Wazuh 5.*"]
                        },
                        "name": "decoder/test-decoder/0",
                        "check": [{"tmp_json.event.action": "string_equal(\\"test\\")"}],
                        "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        Response response = makeRequest("POST", PluginSettings.DECODERS_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), getStatusCode(response));

        Map<String, Object> body = parseResponseAsMap(response);
        String id = (String) body.get("message");
        assertNotNull("Decoder ID should not be null", id);
        return id;
    }

    /**
     * Creates a rule linked to an integration in draft space and returns its generated ID.
     *
     * @param integrationId the parent integration ID
     * @param integrationTitle the integration title (used as SAP log type category)
     * @return the generated rule ID
     * @throws IOException on communication error
     */
    protected String createRule(String integrationId, String integrationTitle) throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "title": "Test Rule %s",
                        "description": "A rule for integration tests.",
                        "author": "Tester",
                        "sigma_id": "test-sigma",
                        "references": ["https://wazuh.com"],
                        "enabled": true,
                        "status": "experimental",
                        "logsource": {
                            "product": "%s",
                            "category": "%s"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test_event"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, integrationId, integrationTitle, integrationTitle, integrationTitle);
        // spotless:on

        Response response = makeRequest("POST", PluginSettings.RULES_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), getStatusCode(response));

        Map<String, Object> body = parseResponseAsMap(response);
        String id = (String) body.get("message");
        assertNotNull("Rule ID should not be null", id);
        return id;
    }

    /**
     * Creates a KVDB linked to an integration in draft space and returns its generated ID.
     *
     * @param integrationId the parent integration ID
     * @return the generated KVDB ID
     * @throws IOException on communication error
     */
    protected String createKvdb(String integrationId) throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "name": "test-kvdb",
                        "enabled": true,
                        "author": "Wazuh Inc.",
                        "content": {"key1": "value1", "key2": "value2"},
                        "description": "KVDB for integration tests.",
                        "documentation": "test-doc",
                        "references": ["https://wazuh.com"],
                        "title": "Test KVDB"
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        Response response = makeRequest("POST", PluginSettings.KVDBS_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), getStatusCode(response));

        Map<String, Object> body = parseResponseAsMap(response);
        String id = (String) body.get("message");
        assertNotNull("KVDB ID should not be null", id);
        return id;
    }

    // ========================
    // Cleanup Helpers
    // ========================

    /**
     * Deletes all draft resources from a given index.
     *
     * @param indexName the target index
     * @throws IOException on communication error
     */
    protected void deleteAllDraftResources(String indexName) throws IOException {
        // spotless:off
        String query = """
                {
                    "query": {
                        "term": {
                            "space.name": "draft"
                        }
                    }
                }
                """;
        // spotless:on
        try {
            makeRequest("POST", indexName + "/_delete_by_query?refresh=true", query);
        } catch (ResponseException e) {
            // Index might not exist yet, that's fine
            if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                throw e;
            }
        }
    }

    /**
     * Deletes a single resource via the Content Manager API.
     *
     * @param endpoint resource endpoint (e.g. INTEGRATIONS_URI)
     * @param resourceId the resource ID
     * @return the response
     * @throws IOException on communication error
     */
    protected Response deleteResource(String endpoint, String resourceId) throws IOException {
        return makeRequest("DELETE", endpoint + "/" + resourceId);
    }

    // ========================
    // Assertion Helpers
    // ========================

    /**
     * Asserts that a document exists in the given index and is in draft space.
     *
     * @param indexName target index
     * @param resourceId resource ID (document.id field)
     * @throws IOException on communication error
     */
    protected void assertResourceExistsInDraft(String indexName, String resourceId)
            throws IOException {
        refreshIndex(indexName);
        // spotless:off
        String query = """
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"document.id": "%s"}},
                                {"term": {"space.name": "draft"}}
                            ]
                        }
                    }
                }
                """;
        query = String.format(Locale.ROOT, query, resourceId);
        // spotless:on
        JsonNode result = searchIndex(indexName, query);
        long totalHits = result.path("hits").path("total").path("value").asLong(0);
        assertTrue(
                "Resource " + resourceId + " should exist in draft space of " + indexName, totalHits > 0);
    }

    /**
     * Asserts that a document does NOT exist in the given index (in draft space).
     *
     * @param indexName target index
     * @param resourceId resource ID (document.id field)
     * @throws IOException on communication error
     */
    protected void assertResourceNotInDraft(String indexName, String resourceId) throws IOException {
        refreshIndex(indexName);
        // spotless:off
        String query = """
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"document.id": "%s"}},
                                {"term": {"space.name": "draft"}}
                            ]
                        }
                    }
                }
                """;
        query = String.format(Locale.ROOT, query, resourceId);
        // spotless:on
        JsonNode result = searchIndex(indexName, query);
        long totalHits = result.path("hits").path("total").path("value").asLong(0);
        assertEquals(
                "Resource " + resourceId + " should NOT exist in draft space of " + indexName,
                0,
                totalHits);
    }

    /**
     * Gets the source document for a resource by its document.id and space.
     *
     * @param indexName target index
     * @param resourceId the document.id value
     * @param spaceName the space name
     * @return the _source as JsonNode, or null if not found
     * @throws IOException on communication error
     */
    protected JsonNode getResourceByDocumentId(String indexName, String resourceId, String spaceName)
            throws IOException {
        refreshIndex(indexName);
        // spotless:off
        String query = """
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"document.id": "%s"}},
                                {"term": {"space.name": "%s"}}
                            ]
                        }
                    }
                }
                """;
        query = String.format(Locale.ROOT, query, resourceId, spaceName);
        // spotless:on
        JsonNode result = searchIndex(indexName, query);
        JsonNode hits = result.path("hits").path("hits");
        if (hits.size() == 0) {
            return null;
        }
        return hits.get(0).path("_source");
    }

    /**
     * Asserts a document has a non-empty hash.sha256 field.
     *
     * @param source the document _source as JsonNode
     * @param resourceDescription description for the assertion message
     */
    protected void assertHashPresent(JsonNode source, String resourceDescription) {
        String hash = source.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText("");
        assertFalse(resourceDescription + " should have a non-empty hash.sha256 field", hash.isEmpty());
    }

    /**
     * Asserts that the space.name field matches the expected value.
     *
     * @param source the document _source as JsonNode
     * @param expectedSpace expected space name
     */
    protected void assertSpaceName(JsonNode source, String expectedSpace) {
        assertEquals(expectedSpace, source.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText());
    }

    /**
     * Asserts that a resource ID exists in an integration's sub-resource list.
     *
     * @param integrationId the integration document.id
     * @param listField field name (decoders, rules, or kvdbs)
     * @param resourceId resource ID to look for
     * @throws IOException on communication error
     */
    protected void assertResourceInIntegrationList(
            String integrationId, String listField, String resourceId) throws IOException {
        JsonNode integration =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        assertNotNull("Integration " + integrationId + " should exist", integration);
        JsonNode list = integration.path(Constants.KEY_DOCUMENT).path(listField);
        assertTrue("List '" + listField + "' should be an array", list.isArray());
        boolean found = false;
        for (JsonNode element : list) {
            if (element.asText().equals(resourceId)) {
                found = true;
                break;
            }
        }
        assertTrue(
                "Resource " + resourceId + " should be in integration's " + listField + " list", found);
    }

    /**
     * Asserts that a resource ID does NOT exist in an integration's sub-resource list.
     *
     * @param integrationId the integration document.id
     * @param listField field name (decoders, rules, or kvdbs)
     * @param resourceId resource ID that should be absent
     * @throws IOException on communication error
     */
    protected void assertResourceNotInIntegrationList(
            String integrationId, String listField, String resourceId) throws IOException {
        JsonNode integration =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        if (integration == null) return; // Integration was deleted, resource is implicitly unlinked
        JsonNode list = integration.path(Constants.KEY_DOCUMENT).path(listField);
        if (!list.isArray()) return;
        for (JsonNode element : list) {
            assertNotEquals(
                    "Resource " + resourceId + " should NOT be in integration's " + listField + " list",
                    resourceId,
                    element.asText());
        }
    }

    /**
     * Asserts that a resource exists in a given space.
     *
     * @param indexName target index
     * @param resourceId the document.id
     * @param spaceName the expected space name
     * @throws IOException on communication error
     */
    protected void assertResourceExistsInSpace(String indexName, String resourceId, String spaceName)
            throws IOException {
        JsonNode source = getResourceByDocumentId(indexName, resourceId, spaceName);
        assertNotNull("Resource " + resourceId + " should exist in space '" + spaceName + "'", source);
    }
}
