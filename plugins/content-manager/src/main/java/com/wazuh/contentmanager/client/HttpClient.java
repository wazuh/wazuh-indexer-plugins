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
import org.apache.hc.core5.http.Method;
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

/**
 * HttpClient is a base class to handle HTTP requests to external APIs. It supports secure
 * communication using SSL/TLS and manages an async HTTP client.
 */
public class HttpClient {

    private static final Logger log = LogManager.getLogger(HttpClient.class);

    private static final int TIMEOUT = 10;
    private static final Object LOCK = new Object();
    protected static CloseableHttpAsyncClient httpClient;

    protected final URI apiUri;

    /** Exception class for handling HTTP client errors. */
    public static class HttpClientException extends Exception {
        public HttpClientException(String message, Throwable cause) {
            super(message, cause);
        }

        public HttpClientException(String message) {
            super(message);
        }
    }

    /**
     * Constructs an HttpClient instance with the specified API URI.
     *
     * @param apiUri The base URI for API requests.
     */
    protected HttpClient(@NonNull URI apiUri) throws HttpClientException {
        this.apiUri = apiUri;
        startHttpAsyncClient();
    }

    /**
     * Initializes and starts the HTTP asynchronous client if not already started. Ensures thread-safe
     * initialization.
     *
     * @throws HttpClientException If an error occurs during client initialization.
     */
    private static void startHttpAsyncClient() throws HttpClientException {
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
                    throw new HttpClientException("Failed to initialize HttpClient", e);
                }
            }
        }
    }

    /**
     * Sends an HTTP request with the specified parameters.
     *
     * @param method The HTTP method (e.g., GET, POST, PUT, DELETE).
     * @param endpoint The endpoint to append to the base API URI.
     * @param requestBody The request body (optional, applicable for POST/PUT).
     * @param queryParameters The query parameters (optional).
     * @param headers The headers to include in the request (optional).
     * @return A SimpleHttpResponse containing the response details.
     * @throws HttpClientException If an error occurs during the request.
     */
    protected SimpleHttpResponse sendRequest(
            @NonNull Method method,
            String endpoint,
            String requestBody,
            Map<String, String> queryParameters,
            Header... headers)
            throws HttpClientException {
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
            log.debug("Sending {} request to [{}]", method, _apiUri);

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
            log.debug("Request sent: [{}]", request);
            return httpClient
                    .execute(
                            SimpleRequestProducer.create(request),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    request, "Failed to execute outgoing " + method + " request"))
                    .get(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            Thread.currentThread().interrupt();
            throw new HttpClientException("HTTP request failed: " + e.getMessage());
        } catch (Exception e) {
            throw new HttpClientException("Unexpected error: " + e.getMessage());
        }
    }
}
