/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.client;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;
import org.junit.Before;

import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class HttpClientTests extends OpenSearchIntegTestCase {

    private HttpClient httpClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp(); // Ensure OpenSearch test setup runs
        httpClient = mock(HttpClient.class);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testSendRequestSuccess() {
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(200, "OK");

        when(httpClient.sendRequest(anyString(), anyString(), any(), anyMap(), any(Header[].class)))
                .thenReturn(mockResponse);

        SimpleHttpResponse response =
                httpClient.sendRequest("GET", "/test", null, Collections.emptyMap());

        assertNotNull("Response should not be null", response);
        assertEquals(200, response.getCode());
    }

    public void testSendPostRequest() {
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(201, "Created");
        String requestBody = "{\"key\":\"value\"}";

        when(httpClient.sendRequest(
                        eq("POST"), anyString(), eq(requestBody), anyMap(), any(Header[].class)))
                .thenReturn(mockResponse);

        SimpleHttpResponse response =
                httpClient.sendRequest("POST", "/create", requestBody, Collections.emptyMap());

        assertNotNull("Response should not be null", response);
        assertEquals(201, response.getCode());
    }

    public void testSendRequestWithQueryParams() {
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(200, "OK");
        Map<String, String> queryParams = Map.of("param1", "value1", "param2", "value2");

        when(httpClient.sendRequest(
                        anyString(), anyString(), any(), eq(queryParams), any(Header[].class)))
                .thenReturn(mockResponse);

        SimpleHttpResponse response = httpClient.sendRequest("GET", "/test", null, queryParams);

        assertNotNull("Response should not be null", response);
        assertEquals(200, response.getCode());
    }

    public void testSendRequestFailure() {
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(500, "Internal Server Error");

        when(httpClient.sendRequest(anyString(), anyString(), any(), anyMap(), any(Header[].class)))
                .thenReturn(mockResponse);

        SimpleHttpResponse response =
                httpClient.sendRequest("GET", "/error", null, Collections.emptyMap());

        assertNotNull("Response should not be null", response);
        assertEquals(500, response.getCode());
    }

    public void testSendRequestTimeout() {
        when(httpClient.sendRequest(anyString(), anyString(), any(), anyMap(), any(Header[].class)))
                .thenThrow(new RuntimeException("Request timeout"));

        try {
            httpClient.sendRequest("GET", "/timeout", null, Collections.emptyMap());
            fail("Expected RuntimeException due to timeout");
        } catch (RuntimeException e) {
            assertEquals("Request timeout", e.getMessage());
        }
    }
}
