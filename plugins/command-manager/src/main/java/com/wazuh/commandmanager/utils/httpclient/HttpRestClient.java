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
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import reactor.util.annotation.NonNull;
import reactor.util.annotation.Nullable;

/** HTTP Rest client. Currently used to perform POST requests against the Wazuh Server. */
public class HttpRestClient {

    public static final long TIMEOUT = 4;
    public static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;
    public static final int MAX_RETRIES = 3;

    private static final Logger log = LogManager.getLogger(HttpRestClient.class);
    static HttpRestClient instance;
    private CloseableHttpAsyncClient httpClient;

    /** Private default constructor */
    HttpRestClient() {
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
                // Trust standard CA and those trusted by our custom strategy
                final SSLContext sslContext =
                        SSLContexts.custom()
                                // Custom TrustStrategy implementations are intended for
                                // verification
                                // of certificates whose CA is not trusted by the system, and where
                                // specifying
                                // a custom truststore containing the certificate chain is not an
                                // option.
                                .loadTrustMaterial(
                                        (chain, authType) -> {
                                            // Please note that validation of the server certificate
                                            // without validation
                                            // of the entire certificate chain in this example is
                                            // preferred to completely
                                            // disabling trust verification, however this still
                                            // potentially allows
                                            // for man-in-the-middle attacks.
                                            final X509Certificate cert = chain[0];
                                            return "CN=httpbin.org"
                                                    .equalsIgnoreCase(
                                                            cert.getSubjectDN().getName());
                                        })
                                .build();

                final TlsStrategy tlsStrategy =
                        ClientTlsStrategyBuilder.create().setSslContext(sslContext).build();

                PoolingAsyncClientConnectionManager cm =
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(tlsStrategy)
                                .build();

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
     * @param receiverURI Well-formed URI
     * @param payload data to send
     * @param payloadId payload ID
     * @param headers auth value (Basic "user:password", "Bearer token")
     * @return SimpleHttpResponse response
     */
    public SimpleHttpResponse post(
            @NonNull URI receiverURI,
            @Nullable String payload,
            @Nullable String payloadId,
            @Nullable Header... headers) {
        try {
            HttpHost httpHost = HttpHost.create(receiverURI);

            log.info("Sending payload with id [{}] to [{}]", payloadId, receiverURI);

            SimpleRequestBuilder builder = SimpleRequestBuilder.post();
            if (payload != null) {
                builder.setBody(payload, ContentType.APPLICATION_JSON);
            }
            if (headers != null) {
                builder.setHeaders(headers);
            }

            SimpleHttpRequest httpPostRequest =
                    builder.setHttpHost(httpHost).setPath(receiverURI.getPath()).build();

            Future<SimpleHttpResponse> future =
                    this.httpClient.execute(
                            SimpleRequestProducer.create(httpPostRequest),
                            SimpleResponseConsumer.create(),
                            new HttpResponseCallback(
                                    httpPostRequest,
                                    "Failed to execute outgoing POST request with payload id ["
                                            + payloadId
                                            + "]"));

            return future.get(TIMEOUT, TIME_UNIT);
        } catch (InterruptedException e) {
            log.error("Operation interrupted {}", e.getMessage());
        } catch (ExecutionException e) {
            log.error("Execution failed {}", e.getMessage());
        } catch (TimeoutException e) {
            log.error("Operation timed out {}", e.getMessage());
        } catch (Exception e) {
            log.error("Error sending payload with id [{}] due to {}", payloadId, e.toString());
        }

        return null;
    }
}
