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

import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;

import java.io.IOException;

/**
 * Retry strategy that preserves the library's default retry behavior for transient I/O errors but
 * never retries on a response status code. Status-code retries (notably HTTP 429) are handled
 * explicitly by {@link ApiClient#executeWithRetry} so the backoff wait happens on the calling
 * worker thread rather than inside the async client, where it would otherwise outlast the {@code
 * future.get(...)} deadline and abort the request.
 */
public class StatusCodeAwareRetryStrategy implements HttpRequestRetryStrategy {

    private final HttpRequestRetryStrategy delegate;

    /**
     * Constructs a strategy delegating I/O-error decisions to a {@link
     * DefaultHttpRequestRetryStrategy}.
     */
    public StatusCodeAwareRetryStrategy() {
        this(new DefaultHttpRequestRetryStrategy());
    }

    /**
     * Constructs a strategy delegating I/O-error decisions to the provided strategy.
     *
     * @param delegate the strategy to delegate transient-I/O retry decisions to.
     */
    public StatusCodeAwareRetryStrategy(HttpRequestRetryStrategy delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean retryRequest(
            HttpRequest request, IOException exception, int execCount, HttpContext context) {
        // Preserve default behavior for transient I/O errors (connection resets, timeouts, ...).
        return this.delegate.retryRequest(request, exception, execCount, context);
    }

    @Override
    public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
        // Never retry based on the response status inside the async client; 429 is surfaced to the
        // caller and retried by ApiClient#executeWithRetry.
        return false;
    }

    @Override
    public TimeValue getRetryInterval(HttpResponse response, int execCount, HttpContext context) {
        return this.delegate.getRetryInterval(response, execCount, context);
    }
}
