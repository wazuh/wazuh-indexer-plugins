/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console.client;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Client for handling telemetry-related requests to the Wazuh CTI API. This class extends the base
 * ApiClient to reuse the asynchronous HTTP infrastructure.
 */
public class TelemetryClient extends ApiClient {
    private static final Logger log = LogManager.getLogger(TelemetryClient.class);

    /** Target endpoint for the telemetry heartbeat. */
    private static final String PING_URI = "https://api.pre.cloud.wazuh.com/api/v1/ping";

    /**
     * Performs an asynchronous GET request to the CTI ping endpoint. This follows a "fire-and-forget"
     * pattern to avoid blocking system processes.
     *
     * @param uuid The unique identifier for the OpenSearch cluster.
     * @param version The current version of the Wazuh Indexer.
     */
    public void ping(String uuid, String version) {
        if (uuid == null || version == null || uuid.isBlank() || version.isBlank()) {
            log.error("UUID or version is null or blank. Aborting telemetry ping.");
            return;
        }

        try {
            SimpleHttpRequest request =
                    SimpleRequestBuilder.get(PING_URI)
                            .addHeader("wazuh-uid", uuid)
                            .addHeader("wazuh-tag", "v" + version)
                            .addHeader("user-agent", "Wazuh Indexer " + version)
                            .addHeader("Accept", "application/json")
                            .build();

            log.debug("Sending telemetry ping to: {}", PING_URI);

            // Execute the request using the inherited asynchronous client from ApiClient.
            // A null callback is used as the response body is not required for this heartbeat.
            this.client.execute(
                    request,
                    new FutureCallback<>() {
                        @Override
                        public void completed(SimpleHttpResponse response) {
                            if (response.getCode() >= 200 && response.getCode() < 300) {
                                log.info("Telemetry Ping sent successfully to CTI (Code: {})", response.getCode());
                            } else {
                                log.warn("Telemetry Ping failed. CTI responded with code: {}", response.getCode());
                                if (response.getCode() == 401) {
                                    log.error("CTI Rejected (401). Body content: {}", response.getBodyText());
                                }
                            }
                        }

                        @Override
                        public void failed(Exception ex) {
                            log.error("Telemetry Ping failed due to network error: {}", ex.getMessage());
                        }

                        @Override
                        public void cancelled() {
                            log.warn("Telemetry Ping request was cancelled.");
                        }
                    });

        } catch (Exception e) {
            log.error("Failed to send telemetry ping due to an unexpected error: {}", e.getMessage());
        }
    }
}
