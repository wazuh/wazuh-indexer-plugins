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

import java.net.URI;
import java.util.Collections;

import org.mockito.*;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class HttpClientTests extends OpenSearchIntegTestCase {

    private static final URI TEST_URI = URI.create("https://example.com");
    private HttpClient httpClient;

    @Before
    @Override
    public void setUp() {
        httpClient = new HttpClient(TEST_URI);
    }

    @After
    @Override
    public void tearDown() {
        HttpClient.stopHttpAsyncClient();
    }

    void testSendRequest_Success() {
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(200, "OK");
        HttpClient spyHttpClient = Mockito.spy(httpClient);

        doReturn(mockResponse)
                .when(spyHttpClient)
                .sendRequest(anyString(), anyString(), anyString(), anyMap(), any(Header[].class));

        SimpleHttpResponse response =
                spyHttpClient.sendRequest("GET", "/test", null, Collections.emptyMap());
        assertNotNull(response);
        assertEquals(200, response.getCode());
    }

    void testSendRequest_Failure() {
        HttpClient spyHttpClient = Mockito.spy(httpClient);
        doThrow(new RuntimeException("Request failed"))
                .when(spyHttpClient)
                .sendRequest(anyString(), anyString(), anyString(), anyMap(), any(Header[].class));

        assertThrows(
                RuntimeException.class,
                () -> spyHttpClient.sendRequest("GET", "/test", null, Collections.emptyMap()));
    }
}
