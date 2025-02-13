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
package com.wazuh.contentmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.util.Map;
import java.util.concurrent.*;

import reactor.util.annotation.NonNull;

public abstract class HttpClient {

    private static final Logger log = LogManager.getLogger(HttpClient.class);

    private static final int TIMEOUT = 10;
    private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;
    private static CloseableHttpAsyncClient httpClient;
    private static final Object LOCK = new Object();

    private static HttpClient instance;
    protected final URI apiUri;

    protected HttpClient(URI apiUri){
        this.apiUri = apiUri;
        startHttpAsyncClient();
    }

    public static HttpClient getInstance() {
        return instance;
    }

    /** Initializes and starts the HTTP async client */
    private static void startHttpAsyncClient() {
        synchronized (LOCK) {
            if (httpClient == null) {
                try {
                    SSLContext sslContext = SSLContextBuilder.create()
                            .loadTrustMaterial(null, (chains, authType) -> true)
                            .build();
                    httpClient = HttpAsyncClients.custom()
                            .setConnectionManager(
                                    PoolingAsyncClientConnectionManagerBuilder.create()
                                            .setTlsStrategy(ClientTlsStrategyBuilder.create().setSslContext(sslContext).build())
                                            .build()
                            ).build();
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

    protected CompletableFuture<SimpleHttpResponse> sendRequestAsync (
            @NonNull String method,
            String requestBody,
            String endpoint,
            Map<String, String> queryParameters,
            Header... headers) {
        URI _apiUri;
        if (httpClient == null) {
            startHttpAsyncClient();
        }
        if (endpoint != null) {
            _apiUri = this.apiUri.resolve(endpoint);
        } else {
            _apiUri = this.apiUri;
        }

        HttpHost httpHost = null;
        try {
            log.info("URI previous: {}", _apiUri);
            httpHost = HttpHost.create(_apiUri.toString());
            log.info("Sending {} request to [{}]", method, _apiUri);
        } catch (URISyntaxException e) {
            log.error("Problems in the creation of HttpHost {}", e.getMessage());
        }
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
        SimpleHttpRequest request = builder.setHttpHost(httpHost).setPath(this.apiUri.getPath()).build();
        CompletableFuture<SimpleHttpResponse> futureResponse = new CompletableFuture<>();
        httpClient.execute(
                SimpleRequestProducer.create(request),
                SimpleResponseConsumer.create(),
                new FutureCallback<>() {
                    public void completed(SimpleHttpResponse result) { futureResponse.complete(result); }
                    public void failed(Exception ex) { futureResponse.completeExceptionally(ex); }
                    public void cancelled() { futureResponse.cancel(true); }
                });
        return futureResponse;
    }

    public CompletableFuture<SimpleHttpResponse> privilegedRequestAsync(
            String method,  String endpoint, String body, Map<String, String> queryParameters, Header headers){
        return AccessController.doPrivileged(
                (PrivilegedAction<CompletableFuture<SimpleHttpResponse>>)
                        () -> { return this.sendRequestAsync(method, endpoint, body, queryParameters, headers);
                        });
    }
}
