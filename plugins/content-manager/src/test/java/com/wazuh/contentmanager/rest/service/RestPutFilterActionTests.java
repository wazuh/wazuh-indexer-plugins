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
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mockito.ArgumentCaptor;
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

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPutFilterAction} class. This test suite validates the REST API
 * endpoint responsible for updating new Filters.
 *
 * <p>Tests verify Filter update requests, proper handling of Filter data, and appropriate HTTP
 * response codes for successful Filter update errors.
 */
public class RestPutFilterActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPutFilterAction action;
    private static final String FILTER_PAYLOAD = """
        {
          "space": "draft",
          "resource": {
            "name": "filter/prefilter/0",
            "enabled": true,
            "metadata": {
              "description": "Default filter to allow all events (for default ruleset)",
              "author": {
                "email": "info@wazuh.com",
                "name": "Wazuh, Inc.",
                "url": "https://wazuh.com"
              }
            },
            "check": "$host.os.platform == 'ubuntu'",
            "type": "pre-filter"
          }
        }
        """;

    private static final String FILTER_PAYLOAD_WITH_ID_MISMATCH = """
        {
          "space": "draft",
          "resource": {
            "id": "different-uuid-12345",
            "name": "filter/prefilter/0",
            "enabled": true,
            "metadata": {
              "description": "Default filter to allow all events (for default ruleset)",
              "author": {
                "email": "info@wazuh.com",
                "name": "Wazuh, Inc.",
                "url": "https://wazuh.com"
              }
            },
            "check": "$host.os.platform == 'ubuntu'",
            "type": "pre-filter"
          }
        }
        """;

    private static final String FILTER_PAYLOAD_MISSING_RESOURCE =
        "{" + "\"type\": \"pre-filter\"" + "}";

    /**
     * Initialize PluginSettings singleton once for all tests.
     */
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
        this.action = new RestPutFilterAction(this.service);
    }

    /**
     * Test successful filter update returns 200 OK.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutFilterSuccess() throws Exception {
        // Arrange
        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
            .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        BytesRestResponse bytesRestResponse =
            this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().startsWith("Filter updated successfully with ID:"));

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", captured.get("id").asText());

        verify(policyHashService).calculateAndUpdate(anyList());
    }

    /**
     * Test that missing filter ID returns 400 Bad Request.
     */
    public void testPutFilterMissingIdReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
            this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
            new RestResponse("Filter ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test that missing request body returns 400 Bad Request.
     */
    public void testPutFilterMissingBodyReturns400() {
        // Arrange
        String filterId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
            new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withParams(Map.of("id", filterId))
                .build();

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

    /**
     * Test that missing resource field returns 400 Bad Request.
     */
    public void testPutFilterMissingResourceReturns400() {
        // Arrange
        String filterId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_MISSING_RESOURCE, filterId);

        // Act
        BytesRestResponse bytesRestResponse =
            this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
            new RestResponse(
                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE),
                RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test that filter ID mismatch returns 400 Bad Request.
     */
    public void testPutFilterIdMismatchReturns400() {
        // Arrange
        String filterId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_WITH_ID_MISMATCH, filterId);

        // Act
        BytesRestResponse bytesRestResponse =
            this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
        assertEquals(
            String.format(Locale.ROOT, Constants.E_400_INVALID_REQUEST_BODY, Constants.KEY_ID),
            this.parseResponse(bytesRestResponse).getMessage());
        verify(this.service, never()).validateResource(anyString(), any(JsonNode.class));
    }

    /**
     * Test that filter not found returns 404 Not Found.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutFilterNotFoundReturns404() throws Exception {
        // Arrange
        String filterId = "d_non-existent-12345";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithNonExistentFilter();

        // Act
        BytesRestResponse bytesRestResponse =
            this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("filter [" + filterId + "] not found"));
    }

    /**
     * Test that null engine service returns 500 Internal Server Error.
     */
    public void testPutFilterEngineUnavailableReturns500() {
        // Arrange
        this.action = new RestPutFilterAction(null);
        String filterId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);

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

    private RestRequest buildRequest(String payload, String filterId) {
        FakeRestRequest.Builder builder =
            new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(payload), XContentType.JSON);
        if (filterId != null) {
            builder.withParams(Map.of("id", filterId, "filter_id", filterId));
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

        // Mock ContentIndex.exists() - filter exists
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
            .thenReturn(existsResponse);

        // Mock validateFilterSpace - filter exists and is in draft space
        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(true);
        when(spaceResponse.getSourceAsMap()).thenReturn(Map.of("space", Map.of("name", "draft")));
        // Mock getSourceAsString for ContentIndex.getDocument()
        when(spaceResponse.getSourceAsString())
            .thenReturn(
                "{\"space\": {\"name\": \"draft\"}, \"document\": {\"metadata\": {\"author\": {\"date\": \"2023-01-01\"}}}}");

        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        return client;
    }

    private Client buildClientWithNonExistentFilter() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock ContentIndex.exists() - filter does not exist
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
            .thenReturn(existsResponse);

        // Mock validateFilterSpace - filter does not exist
        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        return client;
    }
}
