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

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;

import java.util.HashMap;
import java.util.Map;

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
 * Unit tests for {@link EngineContentLoader}. The tests drive {@link
 * EngineContentLoader#doReload()} directly to bypass the thread-pool hop, and stub the async {@link
 * SpaceService} reads to respond synchronously.
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
    private EngineContentLoader loader;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engine = mock(EngineService.class);
        this.spaceService = mock(SpaceService.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        this.loader = new EngineContentLoader(this.engine, this.spaceService, threadPool);

        // Default: every space has no policy (skipped). Individual tests override per space so an
        // untouched tracked space is a fast no-op rather than an unstubbed 60s await.
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

    private void okPromote() {
        when(this.engine.promote(any())).thenReturn(new RestResponse("ok", RestStatus.OK.getStatus()));
    }

    /** A changed (first-seen) hash triggers a promote and the hash is recorded. */
    public void testChangedHashPromotes() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.okPromote();

        this.loader.doReload();

        verify(this.engine, times(1)).promote(any());
    }

    /** A second reload with the same hash after a successful load is a no-op. */
    public void testUnchangedHashSkips() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.okPromote();

        this.loader.doReload();
        this.loader.doReload();

        verify(this.engine, times(1)).promote(any());
    }

    /** A different hash after a successful load triggers another promote. */
    public void testNewHashReloads() {
        this.okPromote();

        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        this.loader.doReload();

        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-2"));
        this.loader.doReload();

        verify(this.engine, times(2)).promote(any());
    }

    /** A non-OK Engine response does not record the hash, so the next reload retries. */
    public void testNonOkResponseIsRetried() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "hash-1"));
        when(this.engine.promote(any()))
                .thenReturn(new RestResponse("busy", RestStatus.INTERNAL_SERVER_ERROR.getStatus()));

        this.loader.doReload();
        this.loader.doReload();

        verify(this.engine, times(2)).promote(any());
    }

    /** No policy yet: nothing is loaded. */
    public void testNullPolicySkips() {
        this.stubPolicy(STANDARD, null);

        this.loader.doReload();

        verify(this.engine, never()).promote(any());
    }

    /** A policy without an aggregate hash is skipped. */
    public void testMissingHashSkips() {
        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_SPACE, new HashMap<>()); // space present but no hash
        this.stubPolicy(STANDARD, policy);

        this.loader.doReload();

        verify(this.engine, never()).promote(any());
    }

    /** All three tracked spaces (standard, test, custom) with changed hashes each load once. */
    public void testAllTrackedSpacesLoad() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.stubPolicy(CUSTOM, policyWithHash(CUSTOM, "cust-1"));
        this.okPromote();

        this.loader.doReload();

        verify(this.engine, times(3)).promote(any());
    }

    /** Only the space whose hash changed reloads; the unchanged ones are skipped. */
    public void testOnlyChangedSpaceReloads() {
        this.stubPolicy(STANDARD, policyWithHash(STANDARD, "std-1"));
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.stubPolicy(CUSTOM, policyWithHash(CUSTOM, "cust-1"));
        this.okPromote();

        this.loader.doReload(); // loads all three (3 promotes)

        this.stubPolicy(TEST, policyWithHash(TEST, "test-2")); // only TEST changes
        this.loader.doReload(); // one more promote (TEST)

        verify(this.engine, times(4)).promote(any());
    }

    /** A promoted TEST space alone loads even when standard/custom are unchanged/absent. */
    public void testTestSpaceLoadsIndependently() {
        this.stubPolicy(TEST, policyWithHash(TEST, "test-1"));
        this.okPromote();

        this.loader.doReload();

        verify(this.engine, times(1)).promote(any());
    }
}
