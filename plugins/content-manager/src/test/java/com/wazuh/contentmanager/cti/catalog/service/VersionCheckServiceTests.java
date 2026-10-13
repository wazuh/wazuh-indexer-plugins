/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.io.CloseMode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VersionCheckService}: thread hand-off, coalescing, rate limit, failure
 * release, thread context and close.
 */
public class VersionCheckServiceTests extends OpenSearchTestCase {

    private static final VersionCheckResponse OK =
            new VersionCheckResponse("{}", RestStatus.OK, Map.of());
    private static final VersionCheckResponse ERROR =
            new VersionCheckResponse("unreachable", RestStatus.INTERNAL_SERVER_ERROR);

    private ThreadPool threadPool;
    private ThreadContext threadContext;
    private ExecutorService executor;
    private List<Runnable> submitted;
    private long now;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.now = 1_000L;
        this.submitted = new ArrayList<>();
        this.executor = mock(ExecutorService.class);
        // Hold submitted tasks so each test decides when the "CTI call" completes.
        doAnswer(
                        invocation -> {
                            this.submitted.add(invocation.getArgument(0));
                            return null;
                        })
                .when(this.executor)
                .execute(any(Runnable.class));
        this.threadPool = mock(ThreadPool.class);
        when(this.threadPool.executor(PluginSettings.VERSION_CHECK_THREAD_POOL))
                .thenReturn(this.executor);
        when(this.threadPool.relativeTimeInMillis()).thenAnswer(invocation -> this.now);
        this.threadContext = new ThreadContext(Settings.EMPTY);
        when(this.threadPool.getThreadContext()).thenReturn(this.threadContext);
    }

    /** A service whose CTI call is stubbed to return {@code response}. */
    private VersionCheckService service(VersionCheckResponse response) {
        VersionCheckService service =
                spy(
                        new VersionCheckService(
                                mock(Environment.class),
                                mock(ClusterService.class),
                                this.threadPool,
                                () -> mock(ApiClient.class)));
        doReturn(response).when(service).fetch();
        return service;
    }

    /** Runs every held task, as the version-check pool would. */
    private void runSubmitted() {
        List<Runnable> tasks = new ArrayList<>(this.submitted);
        this.submitted.clear();
        tasks.forEach(Runnable::run);
    }

    @SuppressWarnings("unchecked")
    private static ActionListener<VersionCheckResponse> listener() {
        return mock(ActionListener.class);
    }

    /** The CTI call is handed to the version-check pool; nothing runs on the calling thread. */
    public void testCheckDoesNotRunOnCallingThread() {
        VersionCheckService service = this.service(OK);
        ActionListener<VersionCheckResponse> listener = listener();

        service.check(listener);

        assertEquals(1, this.submitted.size());
        verify(service, never()).fetch();
        verify(listener, never()).onResponse(any());

        this.runSubmitted();

        verify(service, times(1)).fetch();
        verify(listener).onResponse(OK);
    }

    /** Checks that arrive while one is in flight wait for it instead of issuing their own. */
    public void testConcurrentChecksShareOneCall() {
        VersionCheckService service = this.service(OK);
        ActionListener<VersionCheckResponse> first = listener();
        ActionListener<VersionCheckResponse> second = listener();
        ActionListener<VersionCheckResponse> third = listener();

        service.check(first);
        service.check(second);
        service.check(third);
        assertEquals(1, this.submitted.size());

        this.runSubmitted();

        verify(service, times(1)).fetch();
        verify(first).onResponse(OK);
        verify(second).onResponse(OK);
        verify(third).onResponse(OK);
    }

    /** Starts and completes one check, as a user clicking "check updates" once. */
    private void checkAndRun(VersionCheckService service) {
        service.check(listener());
        this.runSubmitted();
    }

    /**
     * A full bucket allows a burst of calls; the next check is answered 429 with the time until the
     * next token, and once that token is earned a new call is made. Nothing is served from cache.
     */
    public void testBurstThenRateLimited() {
        VersionCheckService service = this.service(OK);
        for (int i = 0; i < VersionCheckService.BUCKET_CAPACITY; i++) {
            this.checkAndRun(service);
        }
        verify(service, times((int) VersionCheckService.BUCKET_CAPACITY)).fetch();

        ActionListener<VersionCheckResponse> limited = listener();
        service.check(limited);
        verify(limited)
                .onResponse(
                        argThat(
                                response ->
                                        response.getStatus() == RestStatus.TOO_MANY_REQUESTS
                                                && response.getRetryAfterSeconds() == 12
                                                && response.getMessage().contains("retry in 12 seconds")));
        assertTrue(this.submitted.isEmpty());

        this.now += VersionCheckService.TOKEN_REFILL_MILLIS - 1;
        ActionListener<VersionCheckResponse> stillLimited = listener();
        service.check(stillLimited);
        verify(stillLimited).onResponse(argThat(response -> response.getRetryAfterSeconds() == 1));

        this.now += 1;
        ActionListener<VersionCheckResponse> allowed = listener();
        service.check(allowed);
        this.runSubmitted();
        verify(allowed).onResponse(OK);
        verify(service, times((int) VersionCheckService.BUCKET_CAPACITY + 1)).fetch();
    }

    /** A failed CTI call spends a token like a successful one. */
    public void testFailedCallSpendsToken() {
        VersionCheckService service = this.service(ERROR);
        for (int i = 0; i < VersionCheckService.BUCKET_CAPACITY; i++) {
            this.checkAndRun(service);
        }

        ActionListener<VersionCheckResponse> limited = listener();
        service.check(limited);
        verify(limited)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.TOO_MANY_REQUESTS));
        assertTrue(this.submitted.isEmpty());
    }

    /** Checks that join an in-flight call spend no token. */
    public void testJoiningInFlightCallSpendsNoToken() {
        VersionCheckService service = this.service(OK);
        service.check(listener());
        for (int i = 0; i < 20; i++) {
            service.check(listener());
        }
        this.runSubmitted();
        verify(service, times(1)).fetch();

        // The 20 joiners spent nothing: the rest of the burst is still available.
        for (int i = 1; i < VersionCheckService.BUCKET_CAPACITY; i++) {
            this.checkAndRun(service);
        }
        verify(service, times((int) VersionCheckService.BUCKET_CAPACITY)).fetch();
    }

    /** An idle period refills the bucket only up to its capacity. */
    public void testRefillIsCappedAtCapacity() {
        VersionCheckService service = this.service(OK);
        this.checkAndRun(service);

        this.now += 100 * VersionCheckService.TOKEN_REFILL_MILLIS;
        for (int i = 0; i < VersionCheckService.BUCKET_CAPACITY; i++) {
            this.checkAndRun(service);
        }
        ActionListener<VersionCheckResponse> limited = listener();
        service.check(limited);
        verify(limited)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.TOO_MANY_REQUESTS));
    }

    /** A pool rejection answers 429 and gives its token back: the next check tries again. */
    public void testRejectionAnswers429AndGivesTokenBack() {
        VersionCheckService service = this.service(OK);
        doAnswer(
                        invocation -> {
                            throw new OpenSearchRejectedExecutionException("rejected");
                        })
                .when(this.executor)
                .execute(any(Runnable.class));
        ActionListener<VersionCheckResponse> listener = listener();

        service.check(listener);

        verify(listener)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.TOO_MANY_REQUESTS));
        verify(service, never()).fetch();

        // More rejected checks than the bucket holds: each one still reaches the pool, so none of
        // them spent a token.
        for (int i = 0; i < VersionCheckService.BUCKET_CAPACITY; i++) {
            service.check(listener());
        }
        verify(this.executor, times((int) VersionCheckService.BUCKET_CAPACITY + 1))
                .execute(any(Runnable.class));
    }

    /**
     * An {@link Error} escaping the fetch still answers every waiter (500) and clears the in-flight
     * marker, so the next check issues a new call instead of queuing forever.
     */
    public void testErrorInFetchReleasesWaiters() {
        VersionCheckService service = this.service(OK);
        doThrow(new AssertionError("boom")).when(service).fetch();
        ActionListener<VersionCheckResponse> first = listener();
        ActionListener<VersionCheckResponse> second = listener();

        service.check(first);
        service.check(second);
        expectThrows(AssertionError.class, this::runSubmitted);

        verify(first)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.INTERNAL_SERVER_ERROR));
        verify(second)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.INTERNAL_SERVER_ERROR));

        service.check(listener());
        assertEquals(1, this.submitted.size());
    }

    /**
     * Each coalesced caller is answered in its own thread context, not in the context of the caller
     * whose check issued the call.
     */
    public void testCoalescedCallersKeepTheirThreadContext() {
        VersionCheckService service = this.service(OK);
        AtomicReference<String> seenByFirst = new AtomicReference<>();
        AtomicReference<String> seenBySecond = new AtomicReference<>();

        try (ThreadContext.StoredContext ignored = this.threadContext.stashContext()) {
            this.threadContext.putHeader("caller", "first");
            service.check(
                    ActionListener.wrap(
                            r -> seenByFirst.set(this.threadContext.getHeader("caller")), e -> {}));
        }
        try (ThreadContext.StoredContext ignored = this.threadContext.stashContext()) {
            this.threadContext.putHeader("caller", "second");
            service.check(
                    ActionListener.wrap(
                            r -> seenBySecond.set(this.threadContext.getHeader("caller")), e -> {}));
        }

        // The pool runs the call in the first caller's context.
        try (ThreadContext.StoredContext ignored = this.threadContext.stashContext()) {
            this.threadContext.putHeader("caller", "first");
            this.runSubmitted();
        }

        assertEquals("first", seenByFirst.get());
        assertEquals("second", seenBySecond.get());
    }

    /** One CTI client serves every fetch and is closed with the service. */
    @SuppressForbidden(reason = "Setting system property required to resolve the version in tests")
    public void testClientIsSharedAndClosed() throws Exception {
        System.setProperty("INDEXER_TEST_ENV", "true");
        try {
            AtomicInteger created = new AtomicInteger();
            ApiClient client = mock(ApiClient.class);
            SimpleHttpResponse ctiResponse = SimpleHttpResponse.create(HttpStatus.SC_OK);
            ctiResponse.setBody("{\"data\":{}}", ContentType.APPLICATION_JSON);
            when(client.getReleaseUpdates(anyString())).thenReturn(ctiResponse);
            VersionCheckService service =
                    new VersionCheckService(
                            mock(Environment.class),
                            mock(ClusterService.class, RETURNS_DEEP_STUBS),
                            this.threadPool,
                            () -> {
                                created.incrementAndGet();
                                return client;
                            });

            assertEquals(RestStatus.OK, service.fetch().getStatus());
            assertEquals(RestStatus.OK, service.fetch().getStatus());
            assertEquals(1, created.get());
            verify(client, times(2)).getReleaseUpdates(anyString());

            service.close();
            verify(client).close(CloseMode.IMMEDIATE);

            // No client is started after close: the fetch fails instead.
            assertEquals(RestStatus.INTERNAL_SERVER_ERROR, service.fetch().getStatus());
            assertEquals(1, created.get());
        } finally {
            System.clearProperty("INDEXER_TEST_ENV");
        }
    }
}
