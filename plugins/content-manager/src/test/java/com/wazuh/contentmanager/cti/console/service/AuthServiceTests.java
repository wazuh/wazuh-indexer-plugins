package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Token;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.opensearch.test.OpenSearchTestCase;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import static org.mockito.Mockito.*;

public class AuthServiceTests extends OpenSearchTestCase {
    private AuthService authService;
    @Mock private ApiClient mockClient;


    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Mock CTI Console API Client
        this.mockClient = mock(ApiClient.class);

        // Create service and replace its client with the mock
        // Note: This creates a real ApiClient internally first, which needs to be closed
        this.authService = new AuthServiceImpl();
        this.authService.setClient(mockClient);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Close the service to properly shut down the HTTP client
        if (this.authService != null) {
            this.authService.close();
        }
    }

    /**
     * On success:
     *  - token must not be null
     *  - token.access_token must be a valid string (not null, not empty)
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetTokenSuccess() throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response = "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";
        when(this.mockClient.getToken(anyString(), anyString()))
            .thenReturn(SimpleHttpResponse.create(200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Token token = this.authService.getToken("anyClientID", "anyDeviceCode");

        // Token must not be null
        assertNotNull(token);

        // access_token must be a valid string (not null, not empty)
        assertNotNull(token.getAccessToken());
        assertFalse(token.getAccessToken().isEmpty());
    }

    /**
     * Possible failures
     *  - CTI replies with an error
     *  - CTI unreachable
     * in these cases, the method is expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetTokenFailure() throws ExecutionException, InterruptedException, TimeoutException {
        Token token;
        String response = "{\"error\": \"invalid_request\", \"error_description\": \"Missing or invalid parameter: client_id\"}";

        // When CTI replies with an error code, token must be null. No exception raised
        when(this.mockClient.getToken(anyString(), anyString()))
            .thenReturn(SimpleHttpResponse.create(400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        token = this.authService.getToken("anyClientID", "anyDeviceCode");
        assertNull(token);

        // When CTI does not reply, token must be null and exceptions are raised.
        when(this.mockClient.getToken(anyString(), anyString())).thenThrow(ExecutionException.class);
        token = this.authService.getToken("anyClientID", "anyDeviceCode");
        assertNull(token);
    }


    /**
     * On success:
     *  - token must not be null
     *  - token.access_token must be a valid string (not null, not empty)
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenSuccess() throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response = "{\"access_token\": \"https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF\", \"issued_token_type\": \"urn:wazuh:params:oauth:token-type:signed_url\", \"expires_in\": 300}";
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
            .thenReturn(SimpleHttpResponse.create(200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Token token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");

        // Token must not be null
        assertNotNull(token);

        // access_token must be a valid string (not null, not empty)
        assertNotNull(token.getAccessToken());
        assertFalse(token.getAccessToken().isEmpty());
    }

    /**
     * Possible failures
     *  - CTI replies with an error
     *  - CTI unreachable
     * in these cases, the method is expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenFailure() throws ExecutionException, InterruptedException, TimeoutException {
        Token token;
        String response = "{\"error\": \"invalid_target\", \"error_description\": \"The resource parameter refers to an invalid endpoint\"}";

        // When CTI replies with an error code, token must be null. No exception raised
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
            .thenReturn(SimpleHttpResponse.create(400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");
        assertNull(token);

        // When CTI does not reply, token must be null and exceptions are raised.
        when(this.mockClient.getResourceToken(any(Token.class), anyString())).thenThrow(ExecutionException.class);
        token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");
        assertNull(token);
    }
}
