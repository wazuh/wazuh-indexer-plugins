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

import org.opensearch.action.get.GetRequestBuilder;
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

/** Unit tests for the {@link RestPutRuleAction} class. */
public class RestPutRuleActionTests extends OpenSearchTestCase {

    private RestPutRuleAction action;
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
        this.action = new RestPutRuleAction();
    }

    /**
     * Test the {@link RestPutRuleAction#handleRequest(RestRequest, Client)} method when the request
     * is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testPutRule200() throws IOException {
        // Arrange
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";

        // spotless:off
        String jsonRule = """
            {
              "type": "rule",
              "resource": {
                  "author": "Florian Roth",
                  "description": "Updated Description.",
                  "detection": {
                    "condition": "selection",
                    "selection": {
                      "event.original": [
                        "exited on signal 6"
                      ]
                    }
                  },
                  "enabled": true,
                  "level": "medium",
                  "logsource": {
                    "product": "nginx"
                  },
                  "title": "Nginx Core Dump Updated"
              }
            }
            """;
        // spotless:on

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        GetRequestBuilder getRequestBuilder = mock(GetRequestBuilder.class);
        GetResponse getResponse = mock(GetResponse.class);
        doReturn(getRequestBuilder).when(this.client).prepareGet(anyString(), anyString());
        when(getRequestBuilder.setFetchSource(any(String[].class), any()))
                .thenReturn(getRequestBuilder);
        when(getRequestBuilder.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> docMap = new HashMap<>();
        docMap.put("date", "2021-05-31");
        when(getResponse.getSourceAsMap()).thenReturn(Map.of("document", docMap));
        when(getResponse.getSourceAsString()).thenReturn("{\"document\": {\"date\": \"2021-05-31\"}}");

        ActionFuture<WIndexRuleResponse> sapFuture = mock(ActionFuture.class);
        when(sapFuture.actionGet()).thenReturn(new WIndexRuleResponse(ruleId, 2L, RestStatus.OK));
        doReturn(sapFuture)
                .when(this.client)
                .execute(eq(WIndexCustomRuleAction.INSTANCE), any(WIndexCustomRuleRequest.class));

        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        doReturn(indexFuture).when(this.client).index(any(IndexRequest.class));

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK, response.status());
        verify(this.client, times(1))
                .execute(eq(WIndexCustomRuleAction.INSTANCE), any(WIndexCustomRuleRequest.class));
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutRuleAction#handleRequest(RestRequest, Client)} method when the rule has
     * not been updated (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPutRule400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        BytesRestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /**
     * Test the {@link RestPutRuleAction#handleRequest(RestRequest, Client)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutRule500() throws IOException {
        // Arrange
        String ruleId = "some-id";
        // Ensure structure is valid so validation passes and exception is hit
        String jsonRule = "{\"resource\": {}, \"type\": \"rule\"}";

        // Mock
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        doThrow(new RuntimeException("Simulated error"))
                .when(this.client)
                .prepareGet(anyString(), anyString());

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }
}
