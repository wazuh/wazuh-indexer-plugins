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

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.utils.DateUtils;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.NoHttpResponseException;
import org.opensearch.common.network.NetworkAddress;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for the 429 and transport-error retry loop and Retry-After parsing in {@link
 * ApiClient}.
 */
public class ApiClientRetryTests extends OpenSearchTestCase {

    private static final String URI =
            "https://api.pre.cloud.wazuh.com/changes?from_offset=0&to_offset=1";

    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(Settings.EMPTY);
    }

    @Override
    public void tearDown() throws Exception {
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /**
     * An {@link ApiClient} whose real methods run (so {@code executeWithRetry} / {@code
     * computeRetryDelaySeconds} are exercised) but whose constructor never runs — the mock is
     * instantiated without starting a real I/O reactor.
     */
    private static ApiClient realMethodClient() {
        return mock(ApiClient.class, CALLS_REAL_METHODS);
    }

    /**
     * A {@link #realMethodClient()} with {@code executeOnce} stubbed to return the scripted
     * responses, or throw the scripted exceptions, in order (repeating the last one once exhausted),
     * standing in for the network. The retry delays are stubbed to {@code 0} so these control-flow
     * tests do not sleep; delay computation is covered by the dedicated {@code
     * computeRetryDelaySeconds} tests.
     */
    private static ApiClient scriptedClient(Object... outcomes) throws Exception {
        ApiClient client = realMethodClient();
        List<Object> scripted = List.of(outcomes);
        int[] calls = {0};
        doAnswer(
                        invocation -> {
                            Object outcome = scripted.get(Math.min(calls[0], scripted.size() - 1));
                            calls[0]++;
                            if (outcome instanceof Exception e) {
                                throw e;
                            }
                            return outcome;
                        })
                .when(client)
                .executeOnce(any(SimpleHttpRequest.class), anyLong());
        doReturn(0L).when(client).computeRetryDelaySeconds(any(SimpleHttpResponse.class), anyInt());
        doReturn(0L).when(client).computeBackoffSeconds(anyInt());
        return client;
    }

    /** The exception {@code executeOnce} throws when the server closes the connection. */
    private static ExecutionException connectionClosed() {
        return new ExecutionException(new ConnectionClosedException("Connection closed by peer"));
    }

    private static SimpleHttpResponse response(int code, String retryAfter) {
        SimpleHttpResponse response = SimpleHttpResponse.create(code);
        if (retryAfter != null) {
            response.addHeader(HttpHeaders.RETRY_AFTER, retryAfter);
        }
        return response;
    }

    private static SimpleHttpRequest request() {
        return SimpleRequestBuilder.get(URI).build();
    }

    /** A 429 (Retry-After: 0) followed by a 200 retries exactly once and returns the 200. */
    public void testRetriesOn429ThenSucceeds() throws Exception {
        ApiClient client =
                scriptedClient(
                        response(HttpStatus.SC_TOO_MANY_REQUESTS, "0"), response(HttpStatus.SC_OK, null));

        SimpleHttpResponse result = client.executeWithRetry(request());

        assertEquals(HttpStatus.SC_OK, result.getCode());
        verify(client, times(2)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /** A non-429 response is returned immediately without any retry. */
    public void testNoRetryOnSuccess() throws Exception {
        ApiClient client = scriptedClient(response(HttpStatus.SC_OK, null));

        SimpleHttpResponse result = client.executeWithRetry(request());

        assertEquals(HttpStatus.SC_OK, result.getCode());
        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * A persistent 429 exhausts max_retries and returns the last 429; total attempts = retries + 1.
     */
    public void testPersistent429ExhaustsRetries() throws Exception {
        ApiClient client = scriptedClient(response(HttpStatus.SC_TOO_MANY_REQUESTS, "0"));

        SimpleHttpResponse result = client.executeWithRetry(request());

        assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, result.getCode());
        verify(client, times(PluginSettings.getInstance().getClientMaxRetries() + 1))
                .executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * With a zero retry budget (the interactive version-check path) a 429 is returned after a single
     * attempt, even with a large Retry-After, and no backoff is ever computed or slept.
     */
    public void testZeroRetriesReturns429WithoutWaiting() throws Exception {
        ApiClient client = scriptedClient(response(HttpStatus.SC_TOO_MANY_REQUESTS, "3600"));

        SimpleHttpResponse result = client.executeWithRetry(request(), 0);

        assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, result.getCode());
        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
        verify(client, never()).computeRetryDelaySeconds(any(SimpleHttpResponse.class), anyInt());
    }

    /**
     * A closed connection, a missing response and a connection reset are each retried, and the 200
     * that follows them is returned.
     */
    public void testRetriesTransportErrorsThenSucceeds() throws Exception {
        ApiClient client =
                scriptedClient(
                        connectionClosed(),
                        new ExecutionException(new NoHttpResponseException("No response")),
                        new ExecutionException(new SocketException("Connection reset")),
                        response(HttpStatus.SC_OK, null));

        SimpleHttpResponse result = client.executeWithRetry(request());

        assertEquals(HttpStatus.SC_OK, result.getCode());
        verify(client, times(4)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * An attempt that exceeds the client timeout is retried, and the 200 that follows is returned.
     */
    public void testRetriesTimeoutThenSucceeds() throws Exception {
        ApiClient client =
                scriptedClient(new TimeoutException("Timeout deadline"), response(HttpStatus.SC_OK, null));

        SimpleHttpResponse result = client.executeWithRetry(request());

        assertEquals(HttpStatus.SC_OK, result.getCode());
        verify(client, times(2)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * A persistent transport error exhausts max_retries and the last exception is rethrown unchanged;
     * total attempts = retries + 1.
     */
    public void testPersistentTransportErrorExhaustsRetries() throws Exception {
        ExecutionException failure = connectionClosed();
        ApiClient client = scriptedClient(failure);

        ExecutionException thrown =
                expectThrows(ExecutionException.class, () -> client.executeWithRetry(request()));

        assertSame(failure, thrown);
        verify(client, times(PluginSettings.getInstance().getClientMaxRetries() + 1))
                .executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * 429 responses and transport errors draw from the same max_retries budget: with the default 3
     * retries, the fourth failure is surfaced even though neither kind failed more than twice.
     */
    public void testRateLimitsAndTransportErrorsShareRetries() throws Exception {
        ApiClient client =
                scriptedClient(
                        response(HttpStatus.SC_TOO_MANY_REQUESTS, "0"),
                        connectionClosed(),
                        response(HttpStatus.SC_TOO_MANY_REQUESTS, "0"),
                        connectionClosed(),
                        response(HttpStatus.SC_OK, null));

        expectThrows(ExecutionException.class, () -> client.executeWithRetry(request()));

        verify(client, times(4)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /**
     * A failure that does not clear on its own, such as a refused connection, is rethrown at once.
     * {@link ConnectException} is a {@link SocketException} too, so this also checks that only a
     * reset is retried.
     */
    public void testNonTransientErrorIsNotRetried() throws Exception {
        ApiClient client =
                scriptedClient(new ExecutionException(new ConnectException("Connection refused")));

        expectThrows(ExecutionException.class, () -> client.executeWithRetry(request()));

        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /** Only idempotent GET requests are re-issued after a transport error. */
    public void testNonGetRequestIsNotRetried() throws Exception {
        ApiClient client = scriptedClient(connectionClosed());

        expectThrows(
                ExecutionException.class,
                () -> client.executeWithRetry(SimpleRequestBuilder.post(URI).build()));

        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /** An interrupted attempt is rethrown at once, without a retry. */
    public void testInterruptIsNotRetried() throws Exception {
        ApiClient client = scriptedClient(new InterruptedException());

        expectThrows(InterruptedException.class, () -> client.executeWithRetry(request()));

        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
    }

    /** With a zero retry budget a transport error is rethrown after a single attempt. */
    public void testZeroRetriesRethrowsTransportError() throws Exception {
        ApiClient client = scriptedClient(connectionClosed());

        expectThrows(ExecutionException.class, () -> client.executeWithRetry(request(), 0));

        verify(client, times(1)).executeOnce(any(SimpleHttpRequest.class), anyLong());
        verify(client, never()).computeBackoffSeconds(anyInt());
    }

    /**
     * Against a real server that closes the first connection without answering, the request is sent
     * again on a new connection and gets the 200 the server answers there.
     */
    public void testRetriesConnectionClosedByServer() throws Exception {
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(
                Settings.builder()
                        .put(PluginSettings.CLIENT_RETRY_BACKOFF_BASE_SECONDS.getKey(), 1)
                        .build());
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                ApiClient client = new ApiClient()) {
            Thread responder =
                    new Thread(
                            () -> {
                                try {
                                    try (Socket first = server.accept()) {
                                        readRequest(first);
                                    }
                                    try (Socket second = server.accept()) {
                                        readRequest(second);
                                        second
                                                .getOutputStream()
                                                .write(
                                                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                                                .getBytes(StandardCharsets.US_ASCII));
                                    }
                                } catch (IOException e) {
                                    throw new UncheckedIOException(e);
                                }
                            });
            responder.start();

            SimpleHttpResponse result =
                    client.executeWithRetry(
                            SimpleRequestBuilder.get(
                                            "http://"
                                                    + NetworkAddress.format(
                                                            new InetSocketAddress(
                                                                    server.getInetAddress(), server.getLocalPort())))
                                    .build());
            responder.join();

            assertEquals(HttpStatus.SC_OK, result.getCode());
        }
    }

    /**
     * Reads a request head up to its blank line. Closing a socket with unread bytes resets the
     * connection instead of closing it, and the async client retries a reset on its own.
     */
    private static void readRequest(Socket socket) throws IOException {
        BufferedReader reader =
                new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        String line;
        do {
            line = reader.readLine();
        } while (line != null && !line.isEmpty());
    }

    /**
     * A positive Retry-After is honored verbatim, even when it is smaller than the exponential
     * backoff would be at this attempt — the server's explicit short wait must not be inflated.
     */
    public void testPositiveRetryAfterHonoredVerbatim() {
        ApiClient client = realMethodClient();

        // attempt 3 → backoff would be base * 2^3 (e.g. 240s); a 20s Retry-After must still win.
        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, "20"), 3);

        assertEquals(20L, delay);
    }

    /**
     * Regression for the observed 60s/0s/0s collapse: a {@code Retry-After: 0} must NOT be honored
     * verbatim — it is treated as unusable and the exponential backoff (base * 2^attempt) applies.
     */
    public void testZeroRetryAfterFallsBackToBackoff() {
        ApiClient client = realMethodClient();
        int base = PluginSettings.getInstance().getClientRetryBackoffBaseSeconds();

        long delay = client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, "0"), 1);

        assertEquals((long) base * 2, delay); // 2^1 = 2
    }

    /** A negative Retry-After is treated as unusable and falls back to exponential backoff. */
    public void testNegativeRetryAfterFallsBackToBackoff() {
        ApiClient client = realMethodClient();
        int base = PluginSettings.getInstance().getClientRetryBackoffBaseSeconds();

        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, "-5"), 0);

        assertEquals((long) base, delay); // 2^0 = 1
    }

    /** A positive HTTP-date Retry-After is converted to a delta and honored. */
    public void testRetryAfterHttpDate() {
        ApiClient client = realMethodClient();
        String httpDate = DateUtils.formatStandardDate(Instant.now().plusSeconds(180));

        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, httpDate), 0);

        // ~180s, with a small tolerance for clock movement between formatting and evaluation.
        assertTrue("delay was " + delay, delay >= 175 && delay <= 181);
    }

    /** A missing Retry-After header falls back to exponential backoff: base * 2^attempt. */
    public void testMissingHeaderFallsBackToBackoff() {
        ApiClient client = realMethodClient();
        int base = PluginSettings.getInstance().getClientRetryBackoffBaseSeconds();

        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, null), 2);

        assertEquals((long) base * 4, delay); // 2^2 = 4
    }

    /** An unparseable Retry-After header falls back to exponential backoff. */
    public void testGarbageHeaderFallsBackToBackoff() {
        ApiClient client = realMethodClient();
        int base = PluginSettings.getInstance().getClientRetryBackoffBaseSeconds();

        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, "not-a-date"), 1);

        assertEquals((long) base * 2, delay); // 2^1 = 2
    }
}
