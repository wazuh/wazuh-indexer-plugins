package com.wazuh.contentmanager.client;

import static org.mockito.Mockito.*;

import java.net.URI;
import java.util.Collections;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.junit.After;
import org.junit.Before;
import org.mockito.*;
import org.opensearch.test.OpenSearchIntegTestCase;


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

        SimpleHttpResponse response = spyHttpClient.sendRequest("GET", "/test", null, Collections.emptyMap());
        assertNotNull(response);
        assertEquals(200, response.getCode());
    }

    void testSendRequest_Failure() {
        HttpClient spyHttpClient = Mockito.spy(httpClient);
        doThrow(new RuntimeException("Request failed"))
                .when(spyHttpClient)
                .sendRequest(anyString(), anyString(), anyString(), anyMap(), any(Header[].class));

        assertThrows(RuntimeException.class, () -> spyHttpClient.sendRequest("GET", "/test", null, Collections.emptyMap()));
    }
}
