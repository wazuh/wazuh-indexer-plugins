/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 */
package com.wazuh.contentmanager.cti.console.client;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Client for handling telemetry-related requests to the Wazuh CTI API.
 * This class extends the base ApiClient to reuse the asynchronous HTTP infrastructure.
 */
public class TelemetryClient extends ApiClient {
    private static final Logger log = LogManager.getLogger(TelemetryClient.class);
    
    /** Target endpoint for the telemetry heartbeat. */
    private static final String PING_URI = "https://cti.wazuh.com/api/v1/ping";

    /**
     * Performs an asynchronous GET request to the CTI ping endpoint.
     * This follows a "fire-and-forget" pattern to avoid blocking system processes.
     *
     * @param uuid    The unique identifier for the OpenSearch cluster.
     * @param version The current version of the Wazuh Indexer.
     */
    public void sendPing(String uuid, String version) {
        try {
            // Build the URL with query parameters for identification
            String fullUri = String.format("%s?uuid=%s&version=%s", PING_URI, uuid, version);
            
            SimpleHttpRequest request = SimpleRequestBuilder.get(fullUri)
                    .addHeader("Content-Type", ContentType.APPLICATION_JSON.toString())
                    .build();

            log.debug("Sending telemetry ping to: {}", fullUri);

            // Execute the request using the inherited asynchronous client from ApiClient.
            // A null callback is used as the response body is not required for this heartbeat.
            this.client.execute(request, null); 
            
        } catch (Exception e) {
            log.error("Failed to send telemetry ping due to an unexpected error: {}", e.getMessage());
        }
    }
}
