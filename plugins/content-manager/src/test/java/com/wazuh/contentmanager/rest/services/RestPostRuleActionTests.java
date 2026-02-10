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
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
              "type": "rule",
              "integration_id": "integration-1",
              "resource": {
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

        Map<String, Object> spaceMap = new HashMap<>();
        spaceMap.put("name", "draft");

        Map<String, Object> sourceMap = new HashMap<>();
        sourceMap.put("document", docMap);
        sourceMap.put("space", spaceMap);

        when(getResponse.getSourceAsMap()).thenReturn(sourceMap);
        when(getResponse.getSourceAsString())
                .thenReturn("{\"document\": {\"rules\": []}, \"space\": {\"name\": \"draft\"}}");

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.CREATED.getStatus(), response.getStatus());

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
              "type": "rule",
              "resource": {
                  "title": "Rule without integration ID",
                  "logsource": { "product": "test" }
              }
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(
                String.format(Locale.ROOT, Constants.E_400_FIELD_IS_REQUIRED, "integration_id"),
                response.getMessage());
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
              "type": "rule",
              "integration_id": "integration-1",
              "resource": {
                  "id": "should-not-be-here",
                  "title": "Rule with ID"
              }
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
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
              "type": "rule",
              "integration_id": "missing-integration",
              "resource": {
                  "title": "Rule",
                  "logsource": { "product": "test" }
              }
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
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("not found"));
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

        RestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
