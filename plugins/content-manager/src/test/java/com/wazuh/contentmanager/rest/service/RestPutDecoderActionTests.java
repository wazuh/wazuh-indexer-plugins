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
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPutDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for updating new CTI Decoders.
 *
 * <p>Tests verify Decoder update requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder update errors.
 */
public class RestPutDecoderActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPutDecoderAction action;
    private static final String DECODER_PAYLOAD =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"resource\": {"
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_WITH_ID_MISMATCH =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"resource\": {"
                    + "  \"id\": \"different-uuid-12345\","
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_MISSING_RESOURCE =
            "{" + "\"type\": \"decoder\"" + "}";

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
        this.action = spy(new RestPutDecoderAction(this.service));
        this.action.setPolicyHashService(mock(SpaceService.class));
        this.action.setIntegrationService(mock(IntegrationService.class));
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutDecoderSuccess() throws Exception {
        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(decoderId, actualResponse.getMessage());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        Assert.assertEquals(decoderId, payloadCaptor.getValue().get("id").asText());
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * payload contains a different ID. The ID in the payload should be ignored and the path ID used.
     * The expected response is: {200, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutDecoderIdInPayloadIsIgnored() throws Exception {
        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_WITH_ID_MISMATCH, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());

        when(this.service.validateResource(anyString(), any(JsonNode.class)))
                .thenReturn(engineResponse);

        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(decoderId, actualResponse.getMessage());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validateResource(anyString(), payloadCaptor.capture());
        // Verify that the path ID was preferred over the payload ID
        Assert.assertEquals(decoderId, payloadCaptor.getValue().get("id").asText());
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutDecoderMissingIdReturns400() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, null);
        RestResponse actualResponse = this.action.executeRequest(request, null);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains(Constants.KEY_ID));
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * request body is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutDecoderMissingBodyReturns400() throws IOException {
        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        RestResponse actualResponse = this.action.executeRequest(request, null);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * resource field is missing. The expected response is: {400, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutDecoderMissingResourceReturns400() throws Exception {
        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_MISSING_RESOURCE, decoderId);
        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains(Constants.KEY_RESOURCE));
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder is not found. The expected response is: {404, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutDecoderNotFoundReturns404() throws Exception {
        String decoderId = "11111111-1111-1111-1111-111111111111";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);
        Client client = this.buildClientWithNonExistentDecoder();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(Constants.E_404_RESOURCE_NOT_FOUND, actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPutDecoderAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutDecoderEngineUnavailableReturns500() throws Exception {
        this.action = spy(new RestPutDecoderAction(null));
        this.action.setPolicyHashService(mock(SpaceService.class));
        this.action.setIntegrationService(mock(IntegrationService.class));

        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);
        Client client = this.buildClientForIndex();

        RestResponse actualResponse = this.action.executeRequest(request, client);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("Internal Server Error."));
    }

    private RestRequest buildRequest(String payload, String decoderId) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        if (decoderId != null) {
            builder.withParams(Map.of("id", decoderId, "decoder_id", decoderId));
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

    private Client buildClientWithNonExistentDecoder() throws Exception {
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
