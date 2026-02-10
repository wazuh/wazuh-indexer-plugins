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

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
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
 * Unit tests for the {@link RestPutKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for updating new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb update requests, proper handling of Kvdb data, and appropriate HTTP response
 * codes for successful Kvdb update errors.
 */
public class RestPutKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPutKvdbAction action;
    private final ObjectMapper mapper = new ObjectMapper();

    // Valid payload with all mandatory fields for PUT
    private static final String KVDB_PAYLOAD =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"description\": \"Example KVDB description\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"},"
                    + "  \"documentation\": \"docs\","
                    + "  \"references\": []"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_WITH_ID_MISMATCH =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"different-uuid-12345\","
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"description\": \"desc\","
                    + "  \"content\": {\"key\": \"value\"},"
                    + "  \"documentation\": \"\","
                    + "  \"references\": []"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_MISSING_RESOURCE =
            "{" + "\"integration\": \"integration-1\"" + "}";

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        // Initialize PluginSettings singleton - it will persist across all tests
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized, ignore
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestPutKvdbAction(this.service);
    }

    /**
     * Test successful KVDB update returns 200 OK.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutKvdbSuccess() throws Exception {
        // Arrange
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, kvdbId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);
        Client client = this.buildClientForIndex(true);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().startsWith("KVDB updated successfully with ID:"));

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", captured.get("id").asText());
    }

    /** Test that missing KVDB ID returns 400 Bad Request. */
    public void testPutKvdbMissingIdReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("KVDB ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPutKvdbMissingBodyReturns400() {
        // Arrange
        String kvdbId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing resource field returns 400 Bad Request. */
    public void testPutKvdbMissingResourceReturns400() {
        // Arrange
        String kvdbId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(KVDB_PAYLOAD_MISSING_RESOURCE, kvdbId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that KVDB ID mismatch returns 400 Bad Request. */
    public void testPutKvdbIdMismatchReturns400() {
        // Arrange
        String kvdbId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(KVDB_PAYLOAD_WITH_ID_MISMATCH, kvdbId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Resource ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test that KVDB not found returns 404 Not Found.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutKvdbNotFoundReturns404() throws Exception {
        // Arrange
        String kvdbId = "d_non-existent-12345";
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, kvdbId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);
        Client client = this.buildClientForIndex(false);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPutKvdbEngineUnavailableReturns500() {
        // Arrange
        this.action = new RestPutKvdbAction(null);
        String kvdbId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(KVDB_PAYLOAD, kvdbId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
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

    private Client buildClientForIndex(boolean kvdbExists) throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock KVDB exists check with space information
        GetResponse kvdbGetResponse = mock(GetResponse.class);
        when(kvdbGetResponse.isExists()).thenReturn(kvdbExists);
        if (kvdbExists) {
            Map<String, Object> source = new java.util.HashMap<>();
            Map<String, Object> document = new java.util.HashMap<>();
            document.put("date", "2020-01-01T00:00:00Z");
            document.put("enabled", true);
            source.put("document", document);
            Map<String, Object> space = new java.util.HashMap<>();
            space.put("name", "draft");
            source.put("space", space);

            when(kvdbGetResponse.getSourceAsMap()).thenReturn(source);
        } else {
            when(kvdbGetResponse.getSourceAsMap()).thenReturn(null);
        }

        // Return this mock for simple get (exists check, getDocument)
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(kvdbGetResponse);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(kvdbGetResponse);

        return client;
    }
}
