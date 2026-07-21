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
 */
public class EngineContentLoaderTests extends OpenSearchTestCase {

    private static final String STANDARD = "standard";
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
    }

    /** Builds a policy source map carrying the aggregate space hash at {@code space.hash.sha256}. */
    private static Map<String, Object> policyWithHash(String sha256) {
        Map<String, Object> hash = new HashMap<>();
        hash.put(Constants.KEY_SHA256, sha256);
        Map<String, Object> space = new HashMap<>();
        space.put(Constants.KEY_NAME, STANDARD);
        space.put(Constants.KEY_HASH, hash);
        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_SPACE, space);
        return policy;
    }

    /** Stubs {@link SpaceService#getPolicy} to synchronously return the given policy source. */
    private void stubPolicy(Map<String, Object> policy) {
        doAnswer(
                        inv -> {
                            ActionListener<Map<String, Object>> l = inv.getArgument(1);
                            l.onResponse(policy);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(eq(STANDARD), any());
    }

    /** Stubs {@link SpaceService#buildEnginePayload} to synchronously return an empty payload. */
    private void stubPayload() {
        JsonNode payload = MAPPER.createObjectNode();
        doAnswer(
                        inv -> {
                            ActionListener<JsonNode> l = inv.getArgument(1);
                            l.onResponse(payload);
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(eq(STANDARD), any());
    }

    /** A changed (first-seen) hash triggers a promote and the hash is recorded. */
    public void testChangedHashPromotes() {
        this.stubPolicy(policyWithHash("hash-1"));
        this.stubPayload();
        when(this.engine.promote(any())).thenReturn(new RestResponse("ok", RestStatus.OK.getStatus()));

        this.loader.doReload();

        verify(this.engine, times(1)).promote(any());
    }

    /** A second reload with the same hash after a successful load is a no-op. */
    public void testUnchangedHashSkips() {
        this.stubPolicy(policyWithHash("hash-1"));
        this.stubPayload();
        when(this.engine.promote(any())).thenReturn(new RestResponse("ok", RestStatus.OK.getStatus()));

        this.loader.doReload();
        this.loader.doReload();

        verify(this.engine, times(1)).promote(any());
    }

    /** A different hash after a successful load triggers another promote. */
    public void testNewHashReloads() {
        this.stubPayload();
        when(this.engine.promote(any())).thenReturn(new RestResponse("ok", RestStatus.OK.getStatus()));

        this.stubPolicy(policyWithHash("hash-1"));
        this.loader.doReload();

        this.stubPolicy(policyWithHash("hash-2"));
        this.loader.doReload();

        verify(this.engine, times(2)).promote(any());
    }

    /** A non-OK Engine response does not record the hash, so the next reload retries. */
    public void testNonOkResponseIsRetried() {
        this.stubPolicy(policyWithHash("hash-1"));
        this.stubPayload();
        when(this.engine.promote(any()))
                .thenReturn(new RestResponse("busy", RestStatus.INTERNAL_SERVER_ERROR.getStatus()));

        this.loader.doReload();
        this.loader.doReload();

        verify(this.engine, times(2)).promote(any());
    }

    /** No STANDARD policy yet: nothing is loaded. */
    public void testNullPolicySkips() {
        this.stubPolicy(null);

        this.loader.doReload();

        verify(this.engine, never()).promote(any());
    }

    /** A policy without an aggregate hash is skipped. */
    public void testMissingHashSkips() {
        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_SPACE, new HashMap<>()); // space present but no hash
        this.stubPolicy(policy);

        this.loader.doReload();

        verify(this.engine, never()).promote(any());
    }
}
