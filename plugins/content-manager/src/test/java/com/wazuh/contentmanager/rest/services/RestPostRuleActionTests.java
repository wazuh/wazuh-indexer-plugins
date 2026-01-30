/*
 * Copyright (C) 2026, Wazuh Inc.
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

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostRuleAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Rules.
 *
 * <p>Tests verify Rule creation requests, proper handling of Rule data, and appropriate HTTP
 * response codes for successful Rule creation and validation errors.
 */
public class RestPostRuleActionTests extends OpenSearchTestCase {

    private RestPostRuleAction action;
    private Client client;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.action = new RestPostRuleAction();
    }

    /**
     * Test the {@link RestPostRuleAction#handleRequest(RestRequest, Client)} method when the request
     * is complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException
     */
    public void testPostRule201() throws IOException {
        // Arrange
        // spotless:off
        String jsonRule = """
            {
              "integration_id": "integration-1",
              "author": "Florian Roth (Nextron Systems)",
              "description": "Detects a core dump of a crashing Nginx worker process.",
              "detection": {
                "condition": "selection",
                "selection": {
                  "event.original": [
                    "exited on signal 6 (core dumped)"
                  ]
                }
              },
              "logsource": {
                "product": "nginx"
              },
              "title": "Nginx Core Dump"
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        ActionFuture<WIndexRuleResponse> sapFuture = mock(ActionFuture.class);
        when(sapFuture.actionGet())
                .thenReturn(new WIndexRuleResponse("new-rule-id", 1L, RestStatus.CREATED));
        doReturn(sapFuture)
                .when(this.client)
                .execute(eq(WIndexCustomRuleAction.INSTANCE), any(WIndexCustomRuleRequest.class));

        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        doReturn(indexFuture).when(this.client).index(any(IndexRequest.class));

        GetResponse getResponse = mock(GetResponse.class);

        org.opensearch.action.get.GetRequestBuilder getRequestBuilder =
                mock(org.opensearch.action.get.GetRequestBuilder.class);
        doReturn(getRequestBuilder).when(this.client).prepareGet(anyString(), anyString());
        when(getRequestBuilder.setFetchSource(anyBoolean())).thenReturn(getRequestBuilder);
        when(getRequestBuilder.get()).thenReturn(getResponse);

        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> docMap = new HashMap<>();
        docMap.put("rules", Collections.emptyList());
        when(getResponse.getSourceAsMap()).thenReturn(Map.of("document", new HashMap<>(docMap)));
        when(getResponse.getSourceAsString()).thenReturn("{\"document\": {\"rules\": []}}");

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.CREATED, response.status());

        verify(this.client, times(1))
                .execute(eq(WIndexCustomRuleAction.INSTANCE), any(WIndexCustomRuleRequest.class));

        // Verify 2 index calls:
        // 1. Indexing the rule in .cti-rules
        // 2. Updating the integration in .cti-integrations
        verify(this.client, times(2)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPostRuleAction#handleRequest(RestRequest, Client)} method when the rule has
     * not been created, because the integration_id field is missing in the payload. The expected
     * response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostRule400_MissingIntegrationId() throws IOException {
        // Arrange
        // spotless:off
        String jsonRule = """
            {
              "title": "Rule without integration ID",
              "logsource": { "product": "test" }
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("Integration ID is required"));
    }

    /**
     * Test the {@link RestPostRuleAction#handleRequest(RestRequest, Client)} method when the rule has
     * not been created, because there is an id field is in the payload. The expected response is:
     * {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostRule400_IdInPayload() throws IOException {
        // Arrange
        // spotless:off
        String jsonRule = """
            {
              "id": "should-not-be-here",
              "integration_id": "integration-1",
              "title": "Rule with ID"
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(
                response.content().utf8ToString().contains("ID must not be provided during creation"));
    }

    /**
     * Test the {@link RestPostRuleAction#handleRequest(RestRequest, Client)} method when the rule has
     * not been created, because there integration from the integration_id field doesn't exist. The
     * expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostRule400_IntegrationNotFound() throws IOException {
        // Arrange
        // spotless:off
        String jsonRule = """
            {
              "integration_id": "missing-integration",
              "title": "Rule",
              "logsource": { "product": "test" }
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        GetResponse getResponse = mock(GetResponse.class);
        org.opensearch.action.get.GetRequestBuilder getRequestBuilder =
                mock(org.opensearch.action.get.GetRequestBuilder.class);

        doReturn(getRequestBuilder).when(this.client).prepareGet(anyString(), anyString());
        when(getRequestBuilder.setFetchSource(anyBoolean())).thenReturn(getRequestBuilder);
        when(getRequestBuilder.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(false);

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("does not exist"));
    }

    /**
     * Test the {@link RestPostRuleAction#handleRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException
     */
    public void testPostRule500() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenThrow(new RuntimeException("Unexpected error"));

        BytesRestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }
}
