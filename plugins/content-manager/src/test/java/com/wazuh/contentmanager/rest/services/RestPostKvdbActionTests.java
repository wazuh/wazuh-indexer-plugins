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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPostKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb creation requests, proper handling of Kvdb data, and appropriate HTTP
 * response codes for successful Kvdb creation and validation errors.
 */
public class RestPostKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostKvdbAction action;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String KVDB_PAYLOAD =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"description\": \"Example KVDB description\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_WITH_ID =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"description\": \"Example KVDB description\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_MISSING_INTEGRATION =
            "{"
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"description\": \"Example KVDB description\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        // Initialize PluginSettings singleton - it will persist across all tests
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestPostKvdbAction(this.service);
    }

    /** Test successful KVDB creation returns 201 Created and updates integration. */
    public void testPostKvdbSuccess() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert - Verify response status and message (per spec, success returns just ID)
        assertEquals(RestStatus.CREATED, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertNotNull(actualResponse.getMessage());
        assertFalse(actualResponse.getMessage().isEmpty());

        // Verify engine validation was called with correct payload
        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();

        // validateResource receives the resource node
        assertTrue(captured.hasNonNull("id"));

        // Check Metadata
        assertNotNull(captured.get("date").asText());
    }

    /** Test that providing a resource ID on creation returns 400 Bad Request. */
    public void testPostKvdbWithIdReturns400() throws IOException {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD_WITH_ID, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_INVALID_REQUEST_BODY, Constants.KEY_ID),
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing integration field returns 400 Bad Request. */
    public void testPostKvdbMissingIntegrationReturns400() throws IOException {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD_MISSING_INTEGRATION, null);

        // Act
        RestResponse response = this.action.handleRequest(request, null);
        BytesRestResponse bytesRestResponse = response.toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_INTEGRATION),
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPostKvdbEngineUnavailableReturns500() throws IOException {
        // Arrange
        this.action = new RestPostKvdbAction(null);
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPostKvdbMissingBodyReturns400() throws IOException {
        // Arrange
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing integration returns 400 Bad Request. */
    public void testPostKvdbIntegrationNotFoundReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithMissingIntegration();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Integration [integration-1] not found"));
    }

    /** Test that integration without space field returns 400 Bad Request. */
    public void testPostKvdbIntegrationWithoutDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithIntegrationWithoutDocument();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Integration [integration-1] not found"));
    }

    /** Test that integration with invalid space returns 400 Bad Request. */
    public void testPostKvdbIntegrationInvalidDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithIntegrationInvalidDocument();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Integration [integration-1] not found"));
    }

    private RestRequest buildRequest(String payload, String kvdbId) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        if (kvdbId != null) {
            builder.withParams(Map.of("id", kvdbId, "kvdb_id", kvdbId));
        }
        return builder.build();
    }

    private RestResponse parseResponse(BytesRestResponse response) {
        JsonNode node = FixtureFactory.from(response.content().utf8ToString());
        return new RestResponse(node.get("message").asText(), node.get("status").asInt());
    }

    private Client buildClientForIndex() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock KVDB exists check
        GetResponse kvdbGetResponse = mock(GetResponse.class);
        when(kvdbGetResponse.isExists()).thenReturn(true);
        Map<String, Object> kvdbSource = new HashMap<>();
        Map<String, Object> kvdbSpace = new HashMap<>();
        kvdbSpace.put("name", "draft");
        kvdbSource.put("space", kvdbSpace);
        when(kvdbGetResponse.getSourceAsMap()).thenReturn(kvdbSource);

        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(kvdbGetResponse);

        // Mock Integration response (for linking)
        GetResponse integrationGetResponse = mock(GetResponse.class);
        when(integrationGetResponse.isExists()).thenReturn(true);

        Map<String, Object> integrationSource = new HashMap<>();

        // 1. Space info (for validateDocumentInSpace)
        Map<String, Object> space = new HashMap<>();
        space.put("name", "draft");
        integrationSource.put("space", space);

        // 2. Document info (for linkResourceToIntegration) - FIX: Added missing document field
        Map<String, Object> docMap = new HashMap<>();
        docMap.put("kvdbs", new ArrayList<String>()); // Initialize list
        integrationSource.put("document", docMap);

        when(integrationGetResponse.getSourceAsMap()).thenReturn(integrationSource);

        // General get (used by validateDocumentInSpace and linkResourceToIntegration)
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(integrationGetResponse);

        return client;
    }

    private Client buildClientWithMissingIntegration() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithIntegrationWithoutDocument() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        // Source without document field
        Map<String, Object> source = new HashMap<>();
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithIntegrationInvalidDocument() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        // Source with space field but not a Map (invalid type)
        Map<String, Object> source = new HashMap<>();
        source.put("space", "invalid-space-type");
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    /**
     * Checks that date and modified cannot be added without it failing
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostKvdb_forbiddenFields() throws IOException {
        String basePayload = KVDB_PAYLOAD;
        String[] fields = {"date", "modified"};

        for (String field : fields) {
            ObjectNode root = (ObjectNode) mapper.readTree(basePayload);
            ObjectNode resource = (ObjectNode) root.get("resource");
            resource.put(field, "2020-01-01");

            RestRequest request = buildRequest(root.toString(), null);
            BytesRestResponse response = this.action.handleRequest(request, null).toBytesRestResponse();

            assertEquals(RestStatus.BAD_REQUEST, response.status());
            RestResponse actual = parseResponse(response);
            assertTrue(
                    actual.getMessage().contains("Invalid request body."));
        }
    }

    /**
     * Checks that if the mandatory fields are missing then there is an error
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostKvdb_missingMandatoryFields() throws IOException {
        String[] fields = {Constants.KEY_TITLE, Constants.KEY_AUTHOR, "content"};

        for (String field : fields) {
            ObjectNode root = (ObjectNode) mapper.readTree(KVDB_PAYLOAD);
            ObjectNode resource = (ObjectNode) root.get("resource");
            resource.remove(field);

            RestRequest request = buildRequest(root.toString(), null);
            BytesRestResponse response = this.action.handleRequest(request, null).toBytesRestResponse();

            assertEquals(RestStatus.BAD_REQUEST, response.status());
            RestResponse actual = parseResponse(response);
            if (field.equals("content")) {
                assertTrue(actual.getMessage().contains("Missing [content] field."));
            } else {
                assertTrue(actual.getMessage().contains("Missing [" + field + "] field."));
            }
        }
    }

    /**
     * Checks that if not present description, documentation and references take empty values
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostKvdb_optionalFieldsDefaults() throws Exception {
        // Arrange
        ObjectNode root = (ObjectNode) mapper.readTree(KVDB_PAYLOAD);
        ObjectNode resource = (ObjectNode) root.get("resource");
        resource.remove("description");
        resource.remove("documentation");
        resource.remove("references");

        RestRequest request = buildRequest(root.toString(), null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);

        Client client = buildClientForIndex();
        this.action.setPolicyHashService(mock(PolicyHashService.class));

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.CREATED, bytesRestResponse.status());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();

        assertTrue(captured.has("description"));
        assertEquals("", captured.get("description").asText());
        assertTrue(captured.has("documentation"));
        assertEquals("", captured.get("documentation").asText());
        assertTrue(captured.has("references"));
        assertTrue(captured.get("references").isArray());
        assertEquals(0, captured.get("references").size());
    }
}
