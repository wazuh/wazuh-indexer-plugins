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
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.http.protocol.BasicHttpContext;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link StatusCodeAwareRetryStrategy}. */
public class StatusCodeAwareRetryStrategyTests extends OpenSearchTestCase {

    /** A status-code response (e.g. 429) is never retried by the async client itself. */
    public void testStatusCodeRetryAlwaysFalse() {
        StatusCodeAwareRetryStrategy strategy = new StatusCodeAwareRetryStrategy();
        HttpContext ctx = new BasicHttpContext();

        HttpResponse tooMany = new BasicHttpResponse(HttpStatus.SC_TOO_MANY_REQUESTS);
        HttpResponse serviceUnavailable = new BasicHttpResponse(HttpStatus.SC_SERVICE_UNAVAILABLE);
        HttpResponse ok = new BasicHttpResponse(HttpStatus.SC_OK);

        assertFalse(strategy.retryRequest(tooMany, 1, ctx));
        assertFalse(strategy.retryRequest(serviceUnavailable, 1, ctx));
        assertFalse(strategy.retryRequest(ok, 1, ctx));
    }

    /** Transient I/O-error retry decisions are delegated to the wrapped default strategy. */
    public void testIoErrorRetryDelegates() {
        HttpRequestRetryStrategy delegate = mock(HttpRequestRetryStrategy.class);
        HttpContext ctx = new BasicHttpContext();
        HttpRequest request = new BasicHttpRequest("GET", "/changes");
        IOException ioe = new IOException("connection reset");

        when(delegate.retryRequest(any(HttpRequest.class), any(IOException.class), anyInt(), any()))
                .thenReturn(true);

        StatusCodeAwareRetryStrategy strategy = new StatusCodeAwareRetryStrategy(delegate);

        assertTrue(strategy.retryRequest(request, ioe, 1, ctx));
        verify(delegate).retryRequest(request, ioe, 1, ctx);
    }

    /** The retry interval is delegated to the wrapped default strategy. */
    public void testRetryIntervalDelegates() {
        HttpRequestRetryStrategy delegate = mock(HttpRequestRetryStrategy.class);
        HttpContext ctx = new BasicHttpContext();
        HttpResponse response = new BasicHttpResponse(HttpStatus.SC_TOO_MANY_REQUESTS);
        TimeValue expected = TimeValue.ofSeconds(7);

        when(delegate.getRetryInterval(any(HttpResponse.class), anyInt(), any())).thenReturn(expected);

        StatusCodeAwareRetryStrategy strategy = new StatusCodeAwareRetryStrategy(delegate);

        assertEquals(expected, strategy.getRetryInterval(response, 1, ctx));
        verify(delegate).getRetryInterval(response, 1, ctx);
    }
}
