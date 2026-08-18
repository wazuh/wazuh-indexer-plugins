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
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for the 429 retry loop and Retry-After parsing in {@link ApiClient}. */
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
     * A {@link #realMethodClient()} with {@code executeOnce} stubbed to return the scripted responses
     * in order (repeating the last one once exhausted), standing in for the network.
     */
    private static ApiClient scriptedClient(SimpleHttpResponse... responses) throws Exception {
        ApiClient client = realMethodClient();
        List<SimpleHttpResponse> scripted = new ArrayList<>(List.of(responses));
        int[] calls = {0};
        doAnswer(
                        invocation -> {
                            SimpleHttpResponse response = scripted.get(Math.min(calls[0], scripted.size() - 1));
                            calls[0]++;
                            return response;
                        })
                .when(client)
                .executeOnce(any(SimpleHttpRequest.class), anyLong());
        return client;
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

    /** A numeric Retry-After header is honored verbatim. */
    public void testRetryAfterNumericSeconds() {
        ApiClient client = realMethodClient();

        long delay = client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, "5"), 0);

        assertEquals(5L, delay);
    }

    /** An HTTP-date Retry-After header is converted to a delta in seconds. */
    public void testRetryAfterHttpDate() {
        ApiClient client = realMethodClient();
        String httpDate = DateUtils.formatStandardDate(Instant.now().plusSeconds(30));

        long delay =
                client.computeRetryDelaySeconds(response(HttpStatus.SC_TOO_MANY_REQUESTS, httpDate), 0);

        // Allow a small tolerance for clock movement between formatting and evaluation.
        assertTrue("delay was " + delay, delay >= 25 && delay <= 31);
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
