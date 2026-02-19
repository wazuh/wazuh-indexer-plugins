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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.junit.Assert;
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

import java.io.IOException;
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

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized
        }
    }

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = spy(new RestPutFilterAction(this.service));
        this.action.setPolicyHashService(mock(SpaceService.class));
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutFilterSuccess() throws Exception {
        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
            .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(filterId, actualResponse.getMessage());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        Assert.assertEquals(filterId, payloadCaptor.getValue().get("id").asText());
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * payload contains a different ID. The ID in the payload should be ignored and the path ID used.
     * The expected response is: {200, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutFilterIdInPayloadIsIgnored() throws Exception {
        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_WITH_ID_MISMATCH, filterId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
            .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(filterId, actualResponse.getMessage());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        // Verify that the path ID was preferred over the payload ID
        Assert.assertEquals(filterId, payloadCaptor.getValue().get("id").asText());
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * filter ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutFilterMissingIdReturns400() throws IOException {
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, null);
        RestResponse actualResponse = this.action.executeRequest(request, null);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains(Constants.KEY_ID));
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * request body is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutFilterMissingBodyReturns400() throws IOException {
        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
            new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withParams(Map.of("id", filterId))
                .build();

        RestResponse actualResponse = this.action.executeRequest(request, null);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * resource field is missing. The expected response is: {400, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutFilterMissingResourceReturns400() throws Exception {
        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_MISSING_RESOURCE, filterId);
        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains(Constants.KEY_RESOURCE));
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when the
     * filter is not found. The expected response is: {404, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutFilterNotFoundReturns404() throws Exception {
        String filterId = "11111111-1111-1111-1111-111111111111";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);
        Client client = this.buildClientWithNonExistentFilter();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(Constants.E_404_RESOURCE_NOT_FOUND, actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPutFilterAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutFilterEngineUnavailableReturns500() throws Exception {
        this.action = spy(new RestPutFilterAction(null));
        this.action.setPolicyHashService(mock(SpaceService.class));

        String filterId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(FILTER_PAYLOAD, filterId);
        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("Internal Server Error."));
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

    private Client buildClientForIndex() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
            .thenReturn(existsResponse);

        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(true);
        when(spaceResponse.getSourceAsMap()).thenReturn(Map.of("space", Map.of("name", "draft")));
        when(spaceResponse.getSourceAsString())
            .thenReturn(
                "{\"space\": {\"name\": \"draft\"}, \"document\": {\"metadata\": {\"author\": {\"date\": \"2023-01-01\"}}}}");

        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        return client;
    }

    private Client buildClientWithNonExistentFilter() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
            .thenReturn(existsResponse);

        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        return client;
    }
}
