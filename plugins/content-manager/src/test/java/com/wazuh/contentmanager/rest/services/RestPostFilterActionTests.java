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
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RestPostFilterActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostFilterAction action;

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

    private static final String FILTER_PAYLOAD_WITH_ID = """
        {
          "space": "draft",
          "resource": {
            "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
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
        this.action = new RestPostFilterAction(this.service);
    }

    /**
     * Test successful filter creation returns 201 Created.
     *
     * @throws Exception When an error occurs
     */
    public void testPostFilterSuccess() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(FILTER_PAYLOAD);

        // Mock wazuh engine validation with proper JSON response
        RestResponse engineResponse = mock(RestResponse.class);
        when(engineResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(engineResponse.getMessage()).thenReturn(
            """
                    {
                      "status": "OK",
                      "error": null
                    }
                """
        );
        // spotless:on

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
            .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert - per spec, success returns 201 with just the ID
        assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        // Message should be the generated ID (UUID format)
        assertNotNull(actualResponse.getMessage());
        assertFalse(actualResponse.getMessage().isEmpty());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();

        assertEquals("filter/prefilter/0", captured.get("name").asText());
        assertTrue(captured.hasNonNull("id"));

        JsonNode metadata = captured.get("metadata");
        assertNotNull(metadata.get("author").get("date").asText());
    }

    /**
     * Test that providing a resource ID on creation returns 400 Bad Request.
     */
    public void testPostFilterWithIdReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_WITH_ID);

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
            new RestResponse(
                String.format(Locale.ROOT, Constants.E_400_INVALID_REQUEST_BODY, Constants.KEY_ID),
                RestStatus.BAD_REQUEST.getStatus());
        assertEquals(expectedResponse, actualResponse);
        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test that null engine service returns 500 Internal Server Error.
     */
    public void testPostFilterEngineUnavailableReturns500() {
        // Arrange
        this.action = new RestPostFilterAction(null);
        RestRequest request = this.buildRequest(FILTER_PAYLOAD);

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
            new RestResponse(
                Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Test that missing request body returns 400 Bad Request.
     */
    public void testPostFilterMissingBodyReturns400() {
        // Arrange
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
            new RestResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());

        assertEquals(expectedResponse, actualResponse);
    }

    private RestRequest buildRequest(String payload) {
        FakeRestRequest.Builder builder =
            new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(payload), XContentType.JSON);
        return builder.build();
    }

    private Client buildClientForIndex() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> document = new HashMap<>();
        document.put("filters", new ArrayList<>());
        Map<String, Object> source = new HashMap<>();
        source.put("document", document);
        Map<String, Object> space = new HashMap<>();
        space.put("name", "draft");
        source.put("space", space);
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }
}
