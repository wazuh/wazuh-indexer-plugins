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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.utils.DateUtils;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.utils.HttpResponseCallback;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Client for interacting with the Wazuh CTI Catalog API.
 *
 * <p>This client manages an asynchronous HTTP client to perform requests against the catalog
 * service, specifically handling consumer context retrieval.
 */
public class ApiClient implements AutoCloseable {

    private static final Logger log = LogManager.getLogger(ApiClient.class);

    private final String baseUri;
    private final ResourceUrlResolver urlResolver;
    private CloseableHttpAsyncClient client;

    /**
     * Constructs an ApiClient instance with a URL resolver and initializes the underlying HTTP
     * client.
     *
     * @param urlResolver the resolver used to transform resource URLs before making HTTP requests.
     */
    public ApiClient(ResourceUrlResolver urlResolver) {
        this.baseUri = PluginSettings.getInstance().getCtiBaseUrl();
        this.urlResolver = urlResolver;
        this.buildClient();
    }

    /** Constructs an ApiClient instance with an regular URL resolver. */
    public ApiClient() {
        this(new RegularUrlResolver());
    }

    /**
     * Builds and starts the asynchronous HTTP client.
     *
     * @throws RuntimeException if the SSL context cannot be initialized.
     */
    private void buildClient() {
        IOReactorConfig ioReactorConfig =
                IOReactorConfig.custom()
                        .setSoTimeout(Timeout.ofSeconds(PluginSettings.getInstance().getClientTimeout()))
                        .build();

        SSLContext sslContext;
        try {
            sslContext =
                    SSLContextBuilder.create().loadTrustMaterial(null, (chains, authType) -> true).build();
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new RuntimeException("Failed to initialize HttpClient", e);
        }

        List<Header> defaultHeaders =
                List.of(
                        new BasicHeader(HttpHeaders.USER_AGENT, PluginSettings.getInstance().getUserAgent()));

        this.client =
                HttpAsyncClients.custom()
                        .setIOReactorConfig(ioReactorConfig)
                        .setDefaultHeaders(defaultHeaders)
                        // Keep the default transient-I/O retry, but never let the async client retry on
                        // a response status code: a 429 must surface to executeWithRetry() so the
                        // Retry-After backoff runs on the calling thread
                        .setRetryStrategy(new StatusCodeAwareRetryStrategy())
                        .setConnectionManager(
                                PoolingAsyncClientConnectionManagerBuilder.create()
                                        .setTlsStrategy(
                                                ClientTlsStrategyBuilder.create().setSslContext(sslContext).build())
                                        .build())
                        .build();

        this.client.start();
    }

    /** Closes the underlying HTTP asynchronous client gracefully. */
    @Override
    public void close() {
        this.client.close(CloseMode.GRACEFUL);
    }

    /**
     * Normalizes a consumer URI.
     *
     * <p>Blank values are returned as empty strings. Non-blank values must be absolute HTTP(S) URLs
     * and have trailing slashes stripped.
     *
     * @throws IllegalArgumentException if a non-blank value is not an absolute HTTP(S) URL.
     */
    private String buildConsumerURI(String consumerUri) {
        if (consumerUri == null || consumerUri.isBlank()) {
            return "";
        }
        String uri = consumerUri.trim();
        if (!uri.startsWith("https://")) {
            throw new IllegalArgumentException("Consumer URI must start with https://");
        }

        URI parsedUri;
        try {
            parsedUri = URI.create(uri);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Consumer URI is not a valid absolute URL: " + uri, e);
        }
        if (parsedUri.getHost() == null || parsedUri.getHost().isBlank()) {
            throw new IllegalArgumentException("Consumer URI must include a valid host: " + uri);
        }
        String baseUri = PluginSettings.getInstance().getCtiBaseUrl();
        URI parsedBaseUri;
        try {
            parsedBaseUri = URI.create(baseUri);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("CTI base URL is not a valid absolute URL: " + baseUri, e);
        }
        if (parsedBaseUri.getHost() == null
                || !parsedUri.getHost().equalsIgnoreCase(parsedBaseUri.getHost())) {
            throw new IllegalArgumentException(
                    "Consumer URI host ["
                            + parsedUri.getHost()
                            + "] does not match the CTI base host ["
                            + parsedBaseUri.getHost()
                            + "]");
        }

        while (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri;
    }

    /**
     * Retrieves consumer details from the CTI Catalog.
     *
     * @param consumerUri The full URL of the consumer.
     * @return A {@link SimpleHttpResponse} containing the API response.
     * @throws ExecutionException If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the wait timed out.
     */
    public SimpleHttpResponse getConsumer(String consumerUri)
            throws ExecutionException, InterruptedException, TimeoutException {
        String uri = this.urlResolver.resolve(this.buildConsumerURI(consumerUri));
        SimpleHttpRequest request = SimpleRequestBuilder.get(uri).build();
        return this.executeWithRetry(request);
    }

    /**
     * Retrieves the changes for a specific consumer within a given context.
     *
     * @param consumerUri The full URL of the consumer.
     * @param fromOffset The starting offset (exclusive).
     * @param toOffset The ending offset (inclusive).
     * @return A {@link SimpleHttpResponse} containing the API response.
     * @throws ExecutionException If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the wait timed out.
     */
    public SimpleHttpResponse getChanges(String consumerUri, long fromOffset, long toOffset)
            throws ExecutionException, InterruptedException, TimeoutException {
        String uri =
                this.urlResolver.resolve(
                        this.buildConsumerURI(consumerUri)
                                + "/changes?from_offset="
                                + fromOffset
                                + "&to_offset="
                                + toOffset);

        SimpleHttpRequest request = SimpleRequestBuilder.get(uri).build();
        return this.executeWithRetry(request);
    }

    /**
     * Constructs the full URI for the releases updates endpoint.
     *
     * @param tag The release tag (e.g., "v5.0.0").
     * @return A string representing the full absolute URL for the releases updates endpoint.
     */
    private String buildReleasesUpdatesURI(String tag) {
        return this.baseUri + "/releases/" + tag + "/updates";
    }

    /**
     * Retrieves available release updates for a given version tag from the CTI API.
     *
     * @param tag The release tag to query updates for (e.g., "v5.0.0").
     * @return A {@link SimpleHttpResponse} containing the API response with available updates.
     * @throws ExecutionException If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the wait timed out.
     */
    public SimpleHttpResponse getReleaseUpdates(String tag)
            throws ExecutionException, InterruptedException, TimeoutException {
        String uri = this.urlResolver.resolve(this.buildReleasesUpdatesURI(tag));
        SimpleHttpRequest request = SimpleRequestBuilder.get(uri).build();
        return this.executeWithRetry(request);
    }

    /**
     * Executes an HTTP request, retrying on HTTP 429 (Too Many Requests) responses.
     *
     * <p>Each attempt blocks up to {@link PluginSettings#getClientTimeout()} seconds on a single
     * round-trip. When the API responds with 429 and retries remain, the wait is derived from the
     * {@code Retry-After} header (or an exponential-backoff fallback) via {@link
     * #computeRetryDelaySeconds}, slept off on the calling thread, and the request is re-issued.
     * Retries are bounded by {@link PluginSettings#getClientMaxRetries()}; once exhausted the last
     * 429 response is returned to the caller, which handles the non-200 status as before.
     *
     * @param request the request to execute.
     * @return the {@link SimpleHttpResponse} of the first non-429 attempt, or the last 429 response
     *     if all retries are exhausted.
     * @throws ExecutionException If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If a single attempt exceeded the client timeout.
     */
    SimpleHttpResponse executeWithRetry(SimpleHttpRequest request)
            throws ExecutionException, InterruptedException, TimeoutException {
        PluginSettings settings = PluginSettings.getInstance();
        int maxRetries = settings.getClientMaxRetries();
        long clientTimeout = settings.getClientTimeout();

        SimpleHttpResponse response = null;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            response = this.executeOnce(request, clientTimeout);

            if (response.getCode() != HttpStatus.SC_TOO_MANY_REQUESTS || attempt == maxRetries) {
                return response;
            }

            long delaySeconds = this.computeRetryDelaySeconds(response, attempt);
            log.warn(
                    Constants.W_LOG_CTI_RATE_LIMITED,
                    request.getRequestUri(),
                    delaySeconds,
                    attempt + 1,
                    maxRetries);
            Thread.sleep(TimeUnit.SECONDS.toMillis(delaySeconds));
        }
        return response;
    }

    /**
     * Executes a single HTTP round-trip, blocking up to {@code clientTimeout} seconds on the
     * response.
     *
     * @param request the request to execute.
     * @param clientTimeout the per-attempt deadline in seconds.
     * @return the {@link SimpleHttpResponse}.
     * @throws ExecutionException If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the wait timed out.
     */
    SimpleHttpResponse executeOnce(SimpleHttpRequest request, long clientTimeout)
            throws ExecutionException, InterruptedException, TimeoutException {
        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));

        return future.get(clientTimeout, TimeUnit.SECONDS);
    }

    /**
     * Computes how long to wait before the next 429 retry, in seconds.
     *
     * <p>The wait is the greater of the exponential backoff floor ({@code base * 2^attempt}) and the
     * server's {@code Retry-After} header (parsed as delta-seconds or an RFC-1123 HTTP-date). The
     * backoff floor is always enforced, so a missing, zero, or too-small {@code Retry-After} cannot
     * collapse the wait to near-zero and burn every retry in milliseconds; a {@code Retry-After} that
     * asks for longer than the floor is honored. The total number of retries is bounded by {@code
     * max_retries}.
     *
     * @param response the 429 response.
     * @param attempt the zero-based retry attempt index (drives the backoff floor).
     * @return the wait in seconds, never negative.
     */
    long computeRetryDelaySeconds(SimpleHttpResponse response, int attempt) {
        PluginSettings settings = PluginSettings.getInstance();

        long backoff = (long) settings.getClientRetryBackoffBaseSeconds() * (1L << attempt);

        long retryAfter = -1;
        Header header = response.getFirstHeader(HttpHeaders.RETRY_AFTER);
        if (header != null && header.getValue() != null) {
            String value = header.getValue().trim();
            try {
                retryAfter = Long.parseLong(value);
            } catch (NumberFormatException e) {
                Instant when = DateUtils.parseStandardDate(value);
                if (when != null) {
                    retryAfter = when.getEpochSecond() - Instant.now().getEpochSecond();
                }
            }
        }

        return Math.max(backoff, Math.max(0, retryAfter));
    }
}
