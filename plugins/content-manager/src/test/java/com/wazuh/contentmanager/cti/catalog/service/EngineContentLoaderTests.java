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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.gateway.GatewayService;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EngineContentLoader}. The reload is fully asynchronous, so the tests stub
 * the {@link SpaceService} reads to respond synchronously and back the generic pool with a
 * same-thread executor: {@link EngineContentLoader#reloadIfChanged()} then completes before it
 * returns, and the assertions need no waiting.
 *
 * <p>The loader tracks the shared spaces {@code standard}, {@code test} and {@code custom}. By
 * default {@link #setUp()} stubs every space to have no policy (so it is skipped), and each test
 * opts specific spaces in via {@link #stubPolicy}.
 */
public class EngineContentLoaderTests extends OpenSearchTestCase {

    private static final String STANDARD = "standard";
    private static final String TEST = "test";
    private static final String CUSTOM = "custom";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EngineService engine;
    private SpaceService spaceService;
    private ThreadPool threadPool;
    private EngineContentLoader loader;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engine = mock(EngineService.class);
        this.spaceService = mock(SpaceService.class);
        this.threadPool = mock(ThreadPool.class);
        // Run the (normally forked) blocking Engine call on the calling thread so each
        // reloadIfChanged() finishes synchronously; schedule() is left returning null, which the
        // loader treats as "watchdog could not be armed".
        when(this.threadPool.generic()).thenReturn(OpenSearchExecutors.newDirectExecutorService());
        this.loader = new EngineContentLoader(this.engine, this.spaceService, this.threadPool);

        // Default: every space has no policy (skipped). Individual tests override per space so an
        // untouched tracked space is a fast no-op.
        doAnswer(
                        inv -> {
                            ActionListener<Map<String, Object>> l = inv.getArgument(1);
                            l.onResponse(null);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(anyString(), any());
        // Default payload for any space (only reached when a space's hash actually changed).
        doAnswer(
                        inv -> {
                            ActionListener<JsonNode> l = inv.getArgument(1);
                            l.onResponse(MAPPER.createObjectNode());
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(anyString(), any());
    }

    /** Builds a policy source map carrying the aggregate space hash at {@code space.hash.sha256}. */
    private static Map<String, Object> policyWithHash(String spaceName, String sha256) {
        Map<String, Object> hash = new HashMap<>();
        hash.put(Constants.KEY_SHA256, sha256);
        Map<String, Object> space = new HashMap<>();
        space.put(Constants.KEY_NAME, spaceName);
        space.put(Constants.KEY_HASH, hash);
        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_SPACE, space);
        return policy;
    }

    /**
     * Stubs {@link SpaceService#getPolicy} for one space to synchronously return the given source.
     */
    private void stubPolicy(String spaceName, Map<String, Object> policy) {
        doAnswer(
                        inv -> {
                            ActionListener<Map<String, Object>> l = inv.getArgument(1);
                            l.onResponse(policy);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(eq(spaceName), any());
    }

    @SuppressWarnings("unchecked")
    private void okPromote() {
        doAnswer(
                        inv -> {
                            ActionListener<RestResponse> l = inv.getArgument(1);
                            l.onResponse(new RestResponse("ok", RestStatus.OK.getStatus()));
                            return null;
                        })
                .when(this.engine)
                .promoteAsync(any(), any());
    }

    /** A changed (first-seen) hash triggers a promote and the hash is recorded. */
    public void testChangedHashPromotes() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.okPromote();

        this.loader.reloadIfChanged();

        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /** A second reload with the same hash after a successful load is a no-op. */
    public void testUnchangedHashSkips() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.okPromote();

        this.loader.reloadIfChanged();
        this.loader.reloadIfChanged();

        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /** A different hash after a successful load triggers another promote. */
    public void testNewHashReloads() {
        this.okPromote();

        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.loader.reloadIfChanged();

        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-2"));
        this.loader.reloadIfChanged();

        verify(this.engine, times(2)).promoteAsync(any(), any());
    }

    /** A non-OK Engine response does not record the hash, so the next reload retries. */
    @SuppressWarnings("unchecked")
    public void testNonOkResponseIsRetried() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        doAnswer(
                        inv -> {
                            ActionListener<RestResponse> l = inv.getArgument(1);
                            l.onResponse(new RestResponse("busy", RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                            return null;
                        })
                .when(this.engine)
                .promoteAsync(any(), any());

        this.loader.reloadIfChanged();
        this.loader.reloadIfChanged();

        verify(this.engine, times(2)).promoteAsync(any(), any());
    }

    /** No policy yet: nothing is loaded. */
    public void testNullPolicySkips() {
        this.stubPolicy(STANDARD, null);

        this.loader.reloadIfChanged();

        verify(this.engine, never()).promoteAsync(any(), any());
    }

    /** A policy without an aggregate hash is skipped. */
    public void testMissingHashSkips() {
        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_SPACE, new HashMap<>()); // space present but no hash
        this.stubPolicy(STANDARD, policy);

        this.loader.reloadIfChanged();

        verify(this.engine, never()).promoteAsync(any(), any());
    }

    /** All three tracked spaces (standard, test, custom) with changed hashes each load once. */
    public void testAllTrackedSpacesLoad() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.stubPolicy(CUSTOM, policyWithHash(CUSTOM, "cust-1"));
        this.okPromote();

        this.loader.reloadIfChanged();

        verify(this.engine, times(3)).promoteAsync(any(), any());
    }

    /** Only the space whose hash changed reloads; the unchanged ones are skipped. */
    public void testOnlyChangedSpaceReloads() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.stubPolicy(CUSTOM, policyWithHash(CUSTOM, "cust-1"));
        this.okPromote();

        this.loader.reloadIfChanged(); // loads all three (3 promotes)

        this.stubPolicy(TEST, policyWithHash(TEST, "test-2")); // only TEST changes
        this.loader.reloadIfChanged(); // one more promote (TEST)

        verify(this.engine, times(4)).promoteAsync(any(), any());
    }

    /** A promoted TEST space alone loads even when standard/custom are unchanged/absent. */
    public void testTestSpaceLoadsIndependently() {
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.okPromote();

        this.loader.reloadIfChanged();

        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /**
     * Nothing to load means no pool thread is borrowed at all: the hash reads run on the caller's
     * callbacks and the engine call is delegated to {@code promoteAsync}.
     */
    public void testNoThreadIsBorrowedWhenNothingChanged() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.okPromote();

        this.loader.reloadIfChanged(); // loads STANDARD via promoteAsync (no generic dispatch)
        verify(this.threadPool, never()).generic();

        this.loader.reloadIfChanged(); // everything up to date now
        verify(this.threadPool, never()).generic();
    }

    /** A read failure is logged per space and still lets the remaining spaces load. */
    public void testFailedSpaceDoesNotBlockOthers() {
        doAnswer(
                        inv -> {
                            ActionListener<Map<String, Object>> l = inv.getArgument(1);
                            l.onFailure(new IllegalStateException("index read failed"));
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(eq(STANDARD), any());
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.stubPolicy(CUSTOM, policyWithHash(CUSTOM, "cust-1"));
        this.okPromote();

        this.loader.reloadIfChanged();

        verify(this.engine, times(2)).promoteAsync(any(), any());
    }

    /** The single-flight guard is released once the async chain finishes, so later triggers run. */
    public void testGuardIsReleasedAfterFailure() {
        doAnswer(
                        inv -> {
                            ActionListener<JsonNode> l = inv.getArgument(1);
                            l.onFailure(new IllegalStateException("payload build failed"));
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(eq(STANDARD), any());
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.okPromote();

        this.loader.reloadIfChanged(); // fails before promoting
        verify(this.engine, never()).promoteAsync(any(), any());

        // Guard released: a later trigger retries and this time the payload builds.
        doAnswer(
                        inv -> {
                            ActionListener<JsonNode> l = inv.getArgument(1);
                            l.onResponse(MAPPER.createObjectNode());
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(eq(STANDARD), any());

        this.loader.reloadIfChanged();

        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /** The listener overload is notified when the run finishes, after the spaces were loaded. */
    public void testListenerIsNotifiedOnCompletion() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.okPromote();

        AtomicReference<Boolean> completed = new AtomicReference<>();
        this.loader.reloadIfChanged(
                ActionListener.wrap(v -> completed.set(true), e -> completed.set(false)));

        assertEquals(Boolean.TRUE, completed.get());
        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /**
     * A trigger arriving while a reload is in flight does not start a second run; its listener is
     * notified when the run it was folded into finishes.
     */
    public void testFoldedTriggerIsNotifiedWithTheRunItJoined() {
        // Hold the STANDARD policy read open so the run stays in flight across both triggers.
        AtomicReference<ActionListener<Map<String, Object>>> pendingRead = new AtomicReference<>();
        doAnswer(
                        inv -> {
                            pendingRead.set(inv.getArgument(1));
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(eq(STANDARD), any());
        this.okPromote();

        AtomicReference<Boolean> first = new AtomicReference<>();
        AtomicReference<Boolean> second = new AtomicReference<>();
        this.loader.reloadIfChanged(ActionListener.wrap(v -> first.set(true), e -> first.set(false)));
        this.loader.reloadIfChanged(ActionListener.wrap(v -> second.set(true), e -> second.set(false)));

        // Still in flight: neither listener has been notified, and only one run was started.
        assertNull(first.get());
        assertNull(second.get());
        verify(this.spaceService, times(1)).getPolicy(eq(STANDARD), any());

        pendingRead.get().onResponse(policyWithHash(STANDARD, "std-1"));

        assertEquals(Boolean.TRUE, first.get());
        assertEquals(Boolean.TRUE, second.get());
        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /**
     * A missing policies index ends the run after the first space: every space reads the same index,
     * so the remaining ones are not attempted (and the caller is not told this is a failure).
     */
    public void testMissingPoliciesIndexEndsTheRunQuietly() {
        this.stubPolicyFailure(new IndexNotFoundException(Constants.INDEX_POLICIES));
        this.assertRunDeferredThenRecovers();
    }

    /**
     * Same for a cluster block: before the cluster state is recovered every read is rejected with
     * {@code state not recovered / initialized}, which is a startup condition, not a load failure.
     */
    public void testClusterBlockEndsTheRunQuietly() {
        this.stubPolicyFailure(
                new ClusterBlockException(Set.of(GatewayService.STATE_NOT_RECOVERED_BLOCK)));
        this.assertRunDeferredThenRecovers();
    }

    /**
     * Stubs every space's policy read to fail with {@code cause}, wrapped as {@code getPolicy} does.
     */
    private void stubPolicyFailure(Exception cause) {
        doAnswer(
                        inv -> {
                            ActionListener<Map<String, Object>> l = inv.getArgument(1);
                            l.onFailure(
                                    new IOException("Failed to retrieve policy: " + cause.getMessage(), cause));
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(anyString(), any());
    }

    /**
     * Asserts the run stopped after the first space without reporting a failure, and that a later
     * trigger loads normally once the reads succeed.
     */
    private void assertRunDeferredThenRecovers() {
        AtomicReference<Boolean> completed = new AtomicReference<>();
        this.loader.reloadIfChanged(
                ActionListener.wrap(v -> completed.set(true), e -> completed.set(false)));

        assertEquals(Boolean.TRUE, completed.get());
        verify(this.spaceService, times(1)).getPolicy(anyString(), any());
        verify(this.engine, never()).promoteAsync(any(), any());

        // Once the reads succeed the next trigger loads normally.
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.stubPolicy(TEST, null);
        this.stubPolicy(CUSTOM, null);
        this.okPromote();

        this.loader.reloadIfChanged();

        verify(this.engine, times(1)).promoteAsync(any(), any());
    }

    /** An unavailable Engine is reported to the listener and does not wedge the guard. */
    public void testListenerFailsWhenEngineUnavailable() {
        EngineContentLoader nullEngineLoader =
                new EngineContentLoader(null, this.spaceService, this.threadPool);

        AtomicReference<Exception> failure = new AtomicReference<>();
        nullEngineLoader.reloadIfChanged(ActionListener.wrap(v -> {}, failure::set));

        assertNotNull(failure.get());
        // Guard released: a second call reaches the same check rather than being folded in.
        AtomicReference<Exception> secondFailure = new AtomicReference<>();
        nullEngineLoader.reloadIfChanged(ActionListener.wrap(v -> {}, secondFailure::set));
        assertNotNull(secondFailure.get());
    }
}
