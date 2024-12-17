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
package com.wazuh.commandmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import java.net.URI;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.commandmanager.settings.PluginSettings;
import reactor.util.annotation.NonNull;
import reactor.util.annotation.Nullable;

import static com.wazuh.commandmanager.utils.httpclient.AuthHttpRestClient.SECURITY_USER_AUTHENTICATE;

/** HTTP Rest client. Currently used to perform POST requests against the Wazuh Server. */
public class HttpRestClient {

    private static final Logger log = LogManager.getLogger(HttpRestClient.class);

    /** Seconds on which the request times outs. */
    public static final int TIMEOUT = 5;

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
                // From the official example on
                // https://opensearch.org/docs/latest/clients/java/#initializing-the-client-with-ssl-and-tls-enabled-using-apache-httpclient-5-transport
                // TODO extract hardcoded values to settings.
                //                System.setProperty("javax.net.ssl.trustStore",
                // "/usr/share/wazuh-indexer/jdk/lib/security/cacerts");
                //                System.setProperty("javax.net.ssl.trustStorePassword", "");

                //                CredentialsProvider basicCredentials =
                // CredentialsProviderBuilder.create()
                //                        .add(
                //                                HttpHost.create(loginUri),
                //                                PluginSettings.getInstance().getAuthUsername(),
                //
                // PluginSettings.getInstance().getAuthPassword().toCharArray()
                //                        ).build();

                // Basic auth
                final String mApiURI = PluginSettings.getInstance().getUri();
                final URI loginUri =
                        new URIBuilder(mApiURI).appendPath(SECURITY_USER_AUTHENTICATE).build();
                final HttpHost host = HttpHost.create(loginUri);
                final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                        new AuthScope(host),
                        new UsernamePasswordCredentials(
                                PluginSettings.getInstance().getAuthUsername(),
                                PluginSettings.getInstance().getAuthPassword().toCharArray()));

                // Create a custom TrustManager that trusts self-signed certificates
                final SSLContext sslContext =
                        SSLContextBuilder.create()
                                .loadTrustMaterial(null, (chains, authType) -> true)
                                .build();

                @SuppressWarnings("deprecation")
                final TlsStrategy tlsStrategy =
                        ClientTlsStrategyBuilder.create()
                                .setSslContext(sslContext)
                                .setTlsDetailsFactory(
                                        new Factory<SSLEngine, TlsDetails>() {
                                            @Override
                                            public TlsDetails create(SSLEngine sslEngine) {
                                                return new TlsDetails(
                                                        sslEngine.getSession(),
                                                        sslEngine.getApplicationProtocol());
                                            }
                                        })
                                .build();

                final PoolingAsyncClientConnectionManager connectionManager =
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(tlsStrategy)
                                .build();

                IOReactorConfig ioReactorConfig =
                        IOReactorConfig.custom().setSoTimeout(TIMEOUT, TimeUnit.SECONDS).build();

                httpClient =
                        HttpAsyncClients.custom()
                                .setDefaultCredentialsProvider(credentialsProvider)
                                .setIOReactorConfig(ioReactorConfig)
                                .setConnectionManager(connectionManager)
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
            log.debug("Headers {}", (Object) headers);

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

            return future.get(TIMEOUT, TimeUnit.SECONDS);
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
