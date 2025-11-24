package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthService;
import com.wazuh.contentmanager.cti.console.service.AuthServiceImpl;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.cti.console.service.PlansServiceImpl;
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

public class CtiConsoleTests extends OpenSearchTestCase {
    private CtiConsole console;
    private AuthService authService;
    private PlansService plansService;
    @Mock
    private ApiClient mockClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Mock CTI Console API Client
        this.mockClient = mock(ApiClient.class);

        // Create service and replace its client with the mock
        // Note: This creates a real ApiClient internally first, which needs to be closed
        this.authService = new AuthServiceImpl();
        this.plansService = new PlansServiceImpl();
        this.authService.setClient(mockClient);
        this.plansService.setClient(mockClient);

        this.console = new CtiConsole();
        this.console.setAuthService(this.authService);
        this.console.setPlansService(this.plansService);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        this.authService.close();
        this.plansService.close();
    }

    /**
     * When the auth service is successful obtaining a permanent token from the CTI Console, it must invoke
     * the onTokenChange() method for all its listeners (CtiConsole). As a result, the token from the CtiConsole
     * instances are updated / initialized.
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    @Test
    public void testOnTokenChanged() throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response = "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";
        when(this.mockClient.getToken(anyString(), anyString()))
            .thenReturn(SimpleHttpResponse.create(200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Token tokenA = this.authService.getToken("anyClientID", "anyDeviceCode");

        // Ensure onTokenChanged is invoked, and the token in the CtiConsole instance is updated.
        Token tokenB = this.console.getToken();
        assertEquals(tokenA, tokenB);
    }

    /**
     * Tests the token retrieval mechanism with wait/notify synchronization.
     * The test verifies that the calling thread properly waits for the token to be obtained
     * through the polling mechanism and is notified when the token becomes available.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    @Test
    public void testGetToken() throws ExecutionException, InterruptedException, TimeoutException {
        String responsePending = "{\"error\": \"authorization_pending\"}";
        String response = "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";

        // Mock responses: 3 pending, success on 4th.
        SimpleHttpResponse httpResponsePending = SimpleHttpResponse.create(400, responsePending.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON);
        SimpleHttpResponse httpResponse = SimpleHttpResponse.create(200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON);
        when(this.mockClient.getToken(anyString(), anyString()))
            .thenReturn(httpResponsePending, httpResponsePending, httpResponsePending, httpResponse);

        // Start polling
        this.console.onPostSubscriptionRequest();

        // Wait for the token with a timeout
        Token token = this.console.waitForToken();

        // Verify the token was obtained
        assertTrue(this.console.isTokenTaskCompleted());
        assertNotNull(token);
        assertEquals("AYjcyMzY3ZDhiNmJkNTY", token.getAccessToken());
    }
}
