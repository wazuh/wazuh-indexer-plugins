/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.Randomness;

import java.net.URI;
import java.util.concurrent.Future;

/** HTTP Rest client. Currently used to perform POST requests against the Wazuh Server. */
public class HttpRestClient {

    private static final Logger log = LogManager.getLogger(HttpRestClient.class);
    private static HttpRestClient instance;
    private CloseableHttpAsyncClient httpClient;

    /** Private default constructor */
    private HttpRestClient() {
        startHttpAsyncClient();
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link HttpRestClient#instance}
     */
    public static HttpRestClient getInstance() {
        if (HttpRestClient.instance == null) {
            instance = new HttpRestClient();
        }
        return HttpRestClient.instance;
    }

    /** Starts http async client. */
    private void startHttpAsyncClient() {
        if (this.httpClient == null) {
            try {
                PoolingAsyncClientConnectionManager cm =
                        PoolingAsyncClientConnectionManagerBuilder.create().build();

                IOReactorConfig ioReactorConfig =
                        IOReactorConfig.custom().setSoTimeout(Timeout.ofSeconds(5)).build();

                httpClient =
                        HttpAsyncClients.custom()
                                .setIOReactorConfig(ioReactorConfig)
                                .setConnectionManager(cm)
                                .build();

                httpClient.start();
            } catch (Exception e) {
                // handle exception
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
     * Sends a POST request.
     *
     * @param uri Well-formed URI
     * @param payload data to send
     * @return HTTP response
     */
    public SimpleHttpResponse post(URI uri, String payload) {
        Long id = Randomness.get().nextLong();

        try {
            // Create request
            HttpHost httpHost = HttpHost.create(uri.getHost());

            SimpleHttpRequest httpPostRequest =
                    SimpleRequestBuilder.post()
                            .setHttpHost(httpHost)
                            .setPath(uri.getPath())
                            .setBody(payload, ContentType.APPLICATION_JSON)
                            .build();

            // log request
            Future<SimpleHttpResponse> future =
                    this.httpClient.execute(
                            SimpleRequestProducer.create(httpPostRequest),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    httpPostRequest, "Failed to send data for ID: " + id));

            return future.get();
        } catch (Exception e) {
            log.error("Failed to send data for ID: {}", id);
        }
        return null;
    }
}
