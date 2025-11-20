package com.wazuh.contentmanager.test.rest;

import com.wazuh.contentmanager.ContentManagerPlugin;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Before;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.ParseException;

import java.io.IOException;

public class RestPostUpdateActionIT extends OpenSearchRestTestCase {
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Create the subscription with correct data before each test
        ensureSubscriptionExists();
    }

    // TODO: When the real external-service handling is implemented, adapt this test accordingly.
    /**
     * External Service Unavailable (503) integration test.
     * Sends a request with a test-only header that simulates the external service being down
     * and expects a 503 Service Unavailable response.
     */
    public void testExternalServiceUnavailable() throws Exception {
        Request request = new Request("POST", ContentManagerPlugin.UPDATE_URI);

        // Test-only headers to trigger simulated external service error and zero-duration update.
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.addHeader("X-Wazuh-Test-Simulate-External-Service-Error", "true");
        options.addHeader("X-Wazuh-Test-Simulated-Duration", "0");
        options.addHeader("X-Wazuh-Test-Rate-Limit", "100");
        request.setOptions(options.build());

        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            int statusCode = e.getResponse().getStatusLine().getStatusCode();

            String body;
            try {
                body = EntityUtils.toString(e.getResponse().getEntity());
            } catch (ParseException | IOException ex) {
                body = "Could not read body: " + ex.getMessage();
            }

            logger.info("Received status for 503 test: " + statusCode);

            assertEquals("Expected 503 Service Unavailable but got: " + statusCode + ". Body: " + body,
                503, statusCode);
        }
    }

    // TODO: When the real update mechanism is implemented, adapt this test as needed.
    /**
     * Concurrency integration test.
     * 1. Sends a slow request (simulated 3s) using the header "X-Wazuh-Test-Simulated-Duration".
     * 2. Immediately sends a second request.
     * 3. Expects a 409 Conflict on the second request.
     */
    public void testConcurrentUpdatesConflict() throws Exception {
        // --- REQUEST 1
        Request requestSlow = new Request("POST", ContentManagerPlugin.UPDATE_URI);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.addHeader("X-Wazuh-Test-Simulated-Duration", "3000");
        options.addHeader("X-Wazuh-Test-Rate-Limit", "100");
        requestSlow.setOptions(options.build());

        // Use a separate thread so the slow request doesn't block the test
        Thread thread = new Thread(() -> {
            try {
                client().performRequest(requestSlow);
            } catch (Exception e) {
                logger.error("Error performing slow request in concurrency test: " + e.getMessage(), e);
            }
        });
        thread.start();

        // --- PETITION 2
        Request requestFast = new Request("POST", ContentManagerPlugin.UPDATE_URI);
        RequestOptions.Builder optionsFast = RequestOptions.DEFAULT.toBuilder();
        optionsFast.addHeader("X-Wazuh-Test-Rate-Limit", "100");
        requestFast.setOptions(optionsFast.build());

        try {
            client().performRequest(requestFast);
        } catch (ResponseException e) {
            int statusCode = e.getResponse().getStatusLine().getStatusCode();

            String body;
            try {
                body = EntityUtils.toString(e.getResponse().getEntity());
            } catch (ParseException | IOException ex) {
                body = "Could not read body: " + ex.getMessage();
            }

            logger.info("Received status for second request: " + statusCode);

            assertEquals("Expected 409 Conflict but got: " + statusCode + ". Body: " + body,
                409, statusCode);

            // Wait for the slow thread to finish before ending the test
            Thread.sleep(3000);
        }
    }

    // --- Helpers ---

    private void ensureSubscriptionExists() throws IOException {
        Request request = new Request("POST", ContentManagerPlugin.SUBSCRIPTION_URI);

        request.setJsonEntity(
            "{\n" +
                "  \"device_code\": \"test-device-code\",\n" +
                "  \"client_id\": \"test-client-id\",\n" +
                "  \"expires_in\": 3600,\n" +
                "  \"interval\": 5\n" +
                "}"
        );

        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            int status = e.getResponse().getStatusLine().getStatusCode();
            logger.warn("Warning creating subscription in setup: Code " + status + " - " + e.getMessage());
        }
    }
}
