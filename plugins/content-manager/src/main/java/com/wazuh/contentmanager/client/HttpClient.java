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

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.*;

import com.wazuh.contentmanager.util.http.HttpResponseCallback;
import reactor.util.annotation.NonNull;

public class HttpClient {

    private static final Logger log = LogManager.getLogger(HttpClient.class);

    private static final int TIMEOUT = 10;
    private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;
    private static CloseableHttpAsyncClient httpClient;
    private static final Object LOCK = new Object();

    protected final URI apiUri;

    protected HttpClient(@NonNull URI apiUri) {
        this.apiUri = apiUri;
        startHttpAsyncClient();
    }

    /** Initializes and starts the HTTP async client */
    private static void startHttpAsyncClient() {
        synchronized (LOCK) {
            if (httpClient == null) {
                try {
                    SSLContext sslContext =
                            SSLContextBuilder.create()
                                    .loadTrustMaterial(null, (chains, authType) -> true)
                                    .build();

                    httpClient =
                            HttpAsyncClients.custom()
                                    .setConnectionManager(
                                            PoolingAsyncClientConnectionManagerBuilder.create()
                                                    .setTlsStrategy(
                                                            ClientTlsStrategyBuilder.create().setSslContext(sslContext).build())
                                                    .build())
                                    .build();
                    httpClient.start();
                } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
                    log.error("Error initializing HTTP client: {}", e.getMessage());
                    throw new RuntimeException("Failed to initialize HttpClient", e);
                }
            }
        }
    }

    /** Stops the HTTP async client */
    public static void stopHttpAsyncClient() {
        synchronized (LOCK) {
            if (httpClient != null) {
                log.info("Shutting down HTTP client.");
                httpClient.close(CloseMode.GRACEFUL);
                httpClient = null;
            }
        }
    }

    /**
     * Sends an HTTP request with the specified method.
     *
     * @param method HTTP method (GET, POST, etc.)
     * @param requestBody Data to send (optional)
     * @param queryParameters Query parameters (optional)
     * @param headers Headers (optional)
     * @return SimpleHttpResponse response
     */
    protected SimpleHttpResponse sendRequest(
            @NonNull String method,
            String endpoint,
            String requestBody,
            Map<String, String> queryParameters,
            Header... headers) {
        URI _apiUri;
        if (httpClient == null) {
            startHttpAsyncClient();
        }
        if (endpoint != null) {
            _apiUri = URI.create(this.apiUri.toString() + endpoint);
        } else {
            _apiUri = this.apiUri;
        }

        try {
            HttpHost httpHost = HttpHost.create(_apiUri);
            log.info("Sending {} request to [{}]", method, _apiUri);

            SimpleRequestBuilder builder = SimpleRequestBuilder.create(method);
            if (requestBody != null) {
                builder.setBody(requestBody, ContentType.APPLICATION_JSON);
            }
            if (queryParameters != null) {
                queryParameters.forEach(builder::addParameter);
            }
            if (headers != null) {
                builder.setHeaders(headers);
            }

            SimpleHttpRequest request = builder.setHttpHost(httpHost).setPath(_apiUri.getPath()).build();

            return httpClient
                    .execute(
                            SimpleRequestProducer.create(request),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    request, "Failed to execute outgoing " + method + " request"))
                    .get(TIMEOUT, TIME_UNIT);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("HTTP {} request failed: {}", method, e.getMessage());
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Unexpected error in HTTP {} request: {}", method, e.getMessage());
        }
        return null;
    }
}
