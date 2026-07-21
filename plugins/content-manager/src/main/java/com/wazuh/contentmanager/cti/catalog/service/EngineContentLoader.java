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

import java.util.Map;
import java.util.concurrent.CompletableFuture;
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
 * Loads the STANDARD space content into the <em>local</em> node's Engine, keyed off the
 * cluster-wide aggregate content hash.
 *
 * <p>Engine communication is inherently node-local (a Unix domain socket), so every node must load
 * the content into its own Engine. The content itself lives in the cluster-wide {@code
 * wazuh-threatintel-*} indices; only the Engine load is a node-local side effect. This loader is
 * the per-node piece that performs that side effect.
 *
 * <p>{@link #reloadIfChanged()} is driven from a cluster-state listener registered on every node
 * (so it reaches all nodes, not just the elected cluster manager) and from the post-sync path on
 * the manager as a prompt nudge. It compares the aggregate {@code space.hash.sha256} stored in
 * {@link Constants#INDEX_POLICIES} against the hash last loaded into this node's Engine and reloads
 * only when they differ. Because the cluster-state listener fires on every cluster-state update, a
 * load that failed because the Engine was not yet ready is retried on a subsequent event without
 * any dedicated timer or poll; once loaded, every later call is a cheap in-memory comparison.
 */
public class EngineContentLoader {

    private static final Logger log = LogManager.getLogger(EngineContentLoader.class);

    /** Blocking-call timeout for the async index reads, in seconds. */
    private static final long AWAIT_TIMEOUT_SECONDS = 60;

    private final EngineService engine;
    private final SpaceService spaceService;
    private final ThreadPool threadPool;

    /**
     * Hash of the content currently loaded into this node's Engine. In-memory only: a node restart
     * (fresh Engine) starts from {@code null} and reloads. Advanced only after a successful (200 OK)
     * load, so a failed load is retried on the next trigger.
     */
    private volatile String loadedHash;

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
     * Reloads the STANDARD space into the local Engine if the cluster-wide content hash differs from
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
            log.error(Constants.E_LOG_ENGINE_STANDARD_LOAD_FAILED, e.getMessage());
        }
    }

    /**
     * Performs the actual reload on the calling thread (the generic pool thread, where blocking is
     * permitted). Package-private so tests can drive it directly without the thread-pool hop.
     *
     * <p>Reads the aggregate STANDARD hash from {@link Constants#INDEX_POLICIES}; if there is no
     * STANDARD policy yet, no usable hash, or the hash matches what is already loaded, it does
     * nothing. Otherwise it builds the STANDARD engine payload and promotes it, recording the new
     * hash only on a 200 OK so a non-OK response is retried on the next trigger.
     */
    void doReload() {
        if (this.engine == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        try {
            Map<String, Object> policy =
                    this.awaitResult(l -> this.spaceService.getPolicy(Space.STANDARD.toString(), l));
            if (policy == null) {
                log.debug(Constants.D_LOG_ENGINE_STANDARD_NO_POLICY);
                return;
            }

            String desiredHash = extractSpaceHash(policy);
            if (desiredHash == null || desiredHash.isBlank()) {
                log.debug(Constants.D_LOG_ENGINE_STANDARD_NO_HASH);
                return;
            }
            if (desiredHash.equals(this.loadedHash)) {
                log.debug(Constants.D_LOG_ENGINE_STANDARD_UNCHANGED);
                return;
            }

            JsonNode payload =
                    this.awaitResult(l -> this.spaceService.buildEnginePayload(Space.STANDARD.toString(), l));
            RestResponse response = this.engine.promote(payload);
            if (response.getStatus() == RestStatus.OK.getStatus()) {
                this.loadedHash = desiredHash;
                log.info(Constants.I_LOG_ENGINE_STANDARD_LOADED);
            } else {
                log.warn(
                        Constants.W_LOG_ENGINE_STANDARD_LOAD_STATUS,
                        response.getStatus(),
                        response.getMessage());
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_ENGINE_STANDARD_LOAD_FAILED, e.getMessage());
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
