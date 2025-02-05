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
package com.wazuh.contentmanager.util.http;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.Nullable;

import javax.net.ssl.SSLContext;

import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import reactor.util.annotation.NonNull;

public class HttpClient {

    private static final Logger log = LogManager.getLogger(HttpClient.class);

    /** Http requests default timeout * */
    public static final int TIMEOUT = 10;

    static HttpClient INSTANCE;

    private CloseableHttpAsyncClient httpClient;

    private HttpClient() {
        startHttpAsyncClient();
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link HttpClient#INSTANCE}
     */
    public static HttpClient getInstance() {
        if (HttpClient.INSTANCE == null) {
            INSTANCE = new HttpClient();
        }
        return HttpClient.INSTANCE;
    }

    /** Starts http async client. */
    private void startHttpAsyncClient() {
        if (this.httpClient == null) {
            try {
                // From the official example on
                // https://opensearch.org/docs/latest/clients/java/#initializing-the-client-with-ssl-and-tls-enabled-using-apache-httpclient-5-transport

                // Create a custom TrustManager that trusts self-signed certificates
                final SSLContext sslContext =
                        SSLContextBuilder.create()
                                .loadTrustMaterial(null, (chains, authType) -> true)
                                .build();

                final TlsStrategy tlsStrategy =
                        ClientTlsStrategyBuilder.create().setSslContext(sslContext).build();

                final PoolingAsyncClientConnectionManager connectionManager =
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(tlsStrategy)
                                .build();

                final IOReactorConfig ioReactorConfig =
                        IOReactorConfig.custom().setSoTimeout(TIMEOUT, TimeUnit.SECONDS).build();

                httpClient =
                        HttpAsyncClients.custom()
                                .setIOReactorConfig(ioReactorConfig)
                                .setConnectionManager(connectionManager)
                                .build();
                httpClient.start();
            } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
                log.error("Error starting async Http client {}", e.getMessage());
            }
        }
    }

    /** Stop http async client. */
    public void stopHttpAsyncClient() {
        if (this.httpClient != null) {
            log.info("Shutting down.");
            httpClient.close(CloseMode.GRACEFUL);
            httpClient = null;
        }
    }

    /**
     * Sends a GET request.
     *
     * @param uri Well-formed URI
     * @param requestBody data to send
     * @param headers auth value (Basic "user:password", "Bearer token")
     * @return SimpleHttpResponse response
     */
    public SimpleHttpResponse get(
            @NonNull URI uri,
            @Nullable String requestBody,
            @Nullable Map<String, String> queryParameters,
            @Nullable Header... headers) {
        try {
            final HttpHost httpHost = HttpHost.create(uri);

            log.info("Sending requestBody to [{}]", uri);
            log.debug("Headers {}", (Object) headers);

            final SimpleRequestBuilder builder = SimpleRequestBuilder.get();
            if (requestBody != null) {
                builder.setBody(requestBody, ContentType.APPLICATION_JSON);
            }
            if (queryParameters != null) {
                queryParameters.forEach(builder::addParameter);
            }
            if (headers != null) {
                builder.setHeaders(headers);
            }

            final SimpleHttpRequest httpGetRequest =
                    builder.setHttpHost(httpHost).setPath(uri.getPath()).build();

            return this.httpClient
                    .execute(
                            SimpleRequestProducer.create(httpGetRequest),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    httpGetRequest, "Failed to execute outgoing GET request"))
                    .get(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Exception found while performing Http GET request interrupted {}",
                    e.getMessage());
        } catch (Exception e) {
            log.error("Grabbing generic exception {}", e.getMessage());
        }
        return null;
    }
}
