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
package com.wazuh.contentmanager.http;

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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.rest.HttpResponseCallback;
import reactor.util.annotation.NonNull;

public class GetClient {

    private static final Logger log = LogManager.getLogger(GetClient.class);

    /** Http requests default timeout * */
    public static final int TIMEOUT = 10;

    static GetClient INSTANCE;

    private CloseableHttpAsyncClient httpClient;

    private GetClient() {
        startHttpAsyncClient();
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link GetClient#INSTANCE}
     */
    public static GetClient getInstance() {
        if (GetClient.INSTANCE == null) {
            INSTANCE = new GetClient();
        }
        return GetClient.INSTANCE;
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
     * @param receiverURI Well-formed URI
     * @param payload data to send
     * @param headers auth value (Basic "user:password", "Bearer token")
     * @return SimpleHttpResponse response
     */
    public SimpleHttpResponse get(
            @NonNull URI receiverURI, @Nullable String payload, @Nullable Header... headers) {
        try {
            final HttpHost httpHost = HttpHost.create(receiverURI);

            log.info("Sending payload to [{}]", receiverURI);
            log.debug("Headers {}", (Object) headers);

            final SimpleRequestBuilder builder = SimpleRequestBuilder.get();
            if (payload != null) {
                builder.setBody(payload, ContentType.APPLICATION_JSON);
            }
            if (headers != null) {
                builder.setHeaders(headers);
            }

            final SimpleHttpRequest httpGetRequest =
                    builder.setHttpHost(httpHost).setPath(receiverURI.getPath()).build();

            return this.httpClient
                    .execute(
                            SimpleRequestProducer.create(httpGetRequest),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    httpGetRequest, "Failed to execute outgoing GET request"))
                    .get(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            log.error("Operation interrupted {}", e.getMessage());
        } catch (ExecutionException e) {
            log.error("Execution failed {}", e.getMessage());
        } catch (TimeoutException e) {
            log.error("Operation timed out {}", e.getMessage());
        }
        return null;
    }
}
