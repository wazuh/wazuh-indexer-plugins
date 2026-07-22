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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Loads the shared, cluster-persisted content spaces into the <em>local</em> node's Engine, keyed
 * off each space's cluster-wide aggregate content hash.
 *
 * <p>Engine communication is inherently node-local (a Unix domain socket), so every node must load
 * the content into its own Engine. The content itself lives in the cluster-wide {@code
 * wazuh-threatintel-*} indices; only the Engine load is a node-local side effect. This loader is
 * the per-node piece that performs that side effect.
 *
 * <p>It tracks the {@link #TRACKED_SPACES shared singleton spaces} — {@code STANDARD} (changed by
 * catalog sync) and {@code TEST}/{@code CUSTOM} (changed only by the promote flow). Per-user {@code
 * DRAFT} content is not an Engine space and is not tracked.
 *
 * <p>{@link #reloadIfChanged()} is driven from a cluster-state listener registered on every node
 * (so it reaches all nodes, not just the elected cluster manager) and from the post-sync and
 * post-promote broadcasts as a prompt nudge. For each tracked space it compares the aggregate
 * {@code space.hash.sha256} stored in {@link Constants#INDEX_POLICIES} against the hash last loaded
 * into this node's Engine and reloads only that space when they differ. Because the cluster-state
 * listener fires on every cluster-state update, a load that failed because the Engine was not yet
 * ready is retried on a subsequent event without any dedicated timer or poll; once loaded, every
 * later call is a cheap in-memory comparison.
 */
public class EngineContentLoader {

    private static final Logger log = LogManager.getLogger(EngineContentLoader.class);

    /** Blocking-call timeout for the async index reads, in seconds. */
    private static final long AWAIT_TIMEOUT_SECONDS = 60;

    /**
     * The shared, cluster-persisted spaces whose Engine representation must be consistent across the
     * cluster. Each node loads all of them into its own Engine.
     */
    private static final List<String> TRACKED_SPACES =
            List.of(Space.STANDARD.toString(), Space.TEST.toString(), Space.CUSTOM.toString());

    private final EngineService engine;
    private final SpaceService spaceService;
    private final ThreadPool threadPool;

    /**
     * Per-space hash of the content currently loaded into this node's Engine (space name → hash).
     * In-memory only: a node restart (fresh Engine) starts empty and reloads every space. A space's
     * entry is advanced only after a successful (200 OK) load, so a failed load is retried on the
     * next trigger.
     */
    private final Map<String, String> loadedHashes = new ConcurrentHashMap<>();

    /** Collapses concurrent triggers so at most one reload is scheduled/running at a time. */
    private final AtomicBoolean inFlight = new AtomicBoolean(false);

    /**
     * Constructs a new EngineContentLoader.
     *
     * @param engine the node-local Engine service.
     * @param spaceService the space service used to read the content hash and build the payload.
     * @param threadPool the thread pool used to offload the blocking reload off the caller thread.
     */
    public EngineContentLoader(
            EngineService engine, SpaceService spaceService, ThreadPool threadPool) {
        this.engine = engine;
        this.spaceService = spaceService;
        this.threadPool = threadPool;
    }

    /**
     * Reloads each tracked space into the local Engine if its cluster-wide content hash differs from
     * the last successfully loaded hash. Non-blocking and safe to call from a cluster-applier thread:
     * the actual work is offloaded to the generic thread pool and single-flighted, so a burst of
     * cluster-state events collapses into a single reload.
     */
    public void reloadIfChanged() {
        if (!this.inFlight.compareAndSet(false, true)) {
            // A reload is already scheduled or running; this trigger is folded into it.
            return;
        }
        try {
            this.threadPool
                    .generic()
                    .execute(
                            () -> {
                                try {
                                    this.doReload();
                                } finally {
                                    this.inFlight.set(false);
                                }
                            });
        } catch (Exception e) {
            // Could not schedule (e.g. pool shutting down); release the guard so a later trigger can
            // retry.
            this.inFlight.set(false);
            log.error(Constants.E_LOG_ENGINE_RELOAD_SCHEDULE_FAILED, e.getMessage());
        }
    }

    /**
     * Performs the actual reload on the calling thread (the generic pool thread, where blocking is
     * permitted). Package-private so tests can drive it directly without the thread-pool hop. Reloads
     * each {@link #TRACKED_SPACES tracked space} independently; a failure loading one space is logged
     * and does not prevent the others from loading.
     */
    void doReload() {
        if (this.engine == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        for (String space : TRACKED_SPACES) {
            try {
                this.reloadSpace(space);
            } catch (Exception e) {
                log.error(Constants.E_LOG_ENGINE_SPACE_LOAD_FAILED, space, e.getMessage());
            }
        }
    }

    /**
     * Reloads a single space into the local Engine. Package-private for tests.
     *
     * <p>Reads the space's aggregate hash from {@link Constants#INDEX_POLICIES}; if there is no
     * policy yet, no usable hash, or the hash matches what is already loaded for this space, it does
     * nothing. Otherwise it builds the space's engine payload and promotes it, recording the new hash
     * only on a 200 OK so a non-OK response is retried on the next trigger.
     *
     * @param space the space name (e.g. {@code standard}, {@code test}, {@code custom}).
     * @throws Exception if an index read or the Engine call fails.
     */
    void reloadSpace(String space) throws Exception {
        Map<String, Object> policy = this.awaitResult(l -> this.spaceService.getPolicy(space, l));
        if (policy == null) {
            log.debug(Constants.D_LOG_ENGINE_SPACE_NO_POLICY, space);
            return;
        }

        String desiredHash = extractSpaceHash(policy);
        if (desiredHash == null || desiredHash.isBlank()) {
            log.debug(Constants.D_LOG_ENGINE_SPACE_NO_HASH, space);
            return;
        }
        if (desiredHash.equals(this.loadedHashes.get(space))) {
            log.debug(Constants.D_LOG_ENGINE_SPACE_UNCHANGED, space);
            return;
        }

        JsonNode payload = this.awaitResult(l -> this.spaceService.buildEnginePayload(space, l));
        RestResponse response = this.engine.promote(payload);
        if (response.getStatus() == RestStatus.OK.getStatus()) {
            this.loadedHashes.put(space, desiredHash);
            log.info(Constants.I_LOG_ENGINE_SPACE_LOADED, space);
        } else {
            log.warn(
                    Constants.W_LOG_ENGINE_SPACE_LOAD_STATUS,
                    space,
                    response.getStatus(),
                    response.getMessage());
        }
    }

    /**
     * Extracts the aggregate space hash ({@code space.hash.sha256}) from a policy document source.
     * This is the hash maintained by {@link SpaceService#calculateAndUpdate}, which changes whenever
     * any resource in the space changes — distinct from the policy document's own top-level hash.
     *
     * @param policy the policy document source map.
     * @return the aggregate space hash, or {@code null} if the space sub-object is absent.
     */
    @SuppressWarnings("unchecked")
    private static String extractSpaceHash(Map<String, Object> policy) {
        Object space = policy.get(Constants.KEY_SPACE);
        if (!(space instanceof Map)) {
            return null;
        }
        return Resource.extractHash((Map<String, Object>) space);
    }

    /**
     * Bridges an asynchronous {@link ActionListener}-based operation into a blocking call. Only
     * invoked from the generic pool thread, where blocking is permitted.
     *
     * @param <T> the result type.
     * @param op consumer that starts the async operation with the supplied listener.
     * @return the operation result.
     * @throws Exception if the operation fails or times out.
     */
    private <T> T awaitResult(Consumer<ActionListener<T>> op) throws Exception {
        CompletableFuture<T> future = new CompletableFuture<>();
        op.accept(ActionListener.wrap(future::complete, future::completeExceptionally));
        try {
            return future.get(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            throw (cause instanceof Exception ex) ? ex : e;
        } catch (TimeoutException e) {
            throw new Exception(e);
        }
    }
}
