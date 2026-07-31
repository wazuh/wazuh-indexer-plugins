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
import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
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
 *
 * <p>The reload is fully asynchronous: the index reads are chained through {@link ActionListener}
 * callbacks instead of being awaited on a pool thread, and the tracked spaces are walked one at a
 * time so at most one Engine load is in progress. Only the blocking Engine call itself is
 * dispatched to the generic pool, which keeps this frequently-triggered path from holding generic
 * threads — a scarce, cluster-wide shared resource — while it waits on the content indices.
 */
public class EngineContentLoader {

    private static final Logger log = LogManager.getLogger(EngineContentLoader.class);

    /**
     * Upper bound on how long a single reload run may stay in flight. It only guards against a lost
     * callback wedging the single-flight guard forever: when it fires, the run is completed
     * exceptionally so a later trigger can start a fresh one.
     */
    private static final TimeValue RELOAD_TIMEOUT = TimeValue.timeValueMinutes(10);

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

    /** Guards {@link #current} and each run's waiter list and completion flag. */
    private final Object mutex = new Object();

    /**
     * The reload currently in flight, or {@code null} when idle. Acts as the single-flight guard: a
     * trigger arriving while a run is in flight is folded into it instead of starting another.
     */
    private Run current;

    /** One reload run: the listeners waiting on it, its watchdog and its completion flag. */
    private static final class Run {
        private final List<ActionListener<Void>> waiters = new ArrayList<>();

        /** Assigned before the chain starts, read by whichever thread completes the run. */
        private volatile Scheduler.ScheduledCancellable watchdog;

        private boolean finished;
    }

    /**
     * Constructs a new EngineContentLoader.
     *
     * @param engine the node-local Engine service.
     * @param spaceService the space service used to read the content hash and build the payload.
     * @param threadPool the thread pool used to offload the blocking Engine call off the caller
     *     thread and to arm the in-flight watchdog.
     */
    public EngineContentLoader(
            EngineService engine, SpaceService spaceService, ThreadPool threadPool) {
        this.engine = engine;
        this.spaceService = spaceService;
        this.threadPool = threadPool;
    }

    /**
     * Records a hash as already loaded for the given space, so that a subsequent {@link
     * #reloadIfChanged} skips it when the index hash matches. Use this when an external path (e.g.
     * {@link com.wazuh.contentmanager.transport.TransportActionHelper#reloadStandardSpaceIntoEngine})
     * has already promoted the space's content into the Engine.
     *
     * @param space the space name (e.g. {@code standard}).
     * @param hash the hash that was successfully loaded.
     */
    public void updateLoadedHash(String space, String hash) {
        this.loadedHashes.put(space, hash);
    }

    /**
     * Reloads each tracked space into the local Engine if its cluster-wide content hash differs from
     * the last successfully loaded hash, ignoring the outcome. Every outcome — a per-space failure,
     * an unavailable Engine, a timed-out run — is already logged, so the fire-and-forget triggers
     * (the cluster-state listener, the post-sync and post-promote broadcasts) need no listener.
     *
     * @see #reloadIfChanged(ActionListener)
     */
    public void reloadIfChanged() {
        this.reloadIfChanged(ActionListener.wrap(v -> {}, e -> {}));
    }

    /**
     * Reloads each tracked space into the local Engine if its cluster-wide content hash differs from
     * the last successfully loaded hash, notifying {@code listener} when the reload finishes.
     * Non-blocking and safe to call from a cluster-applier thread: the work is driven entirely by
     * {@link ActionListener} callbacks and single-flighted, so a burst of triggers collapses into a
     * single reload.
     *
     * <p>No thread is parked waiting for the index reads — each step continues on the thread that
     * completes the previous one. The generic pool is borrowed only for the blocking Engine socket
     * call, and only for a space whose hash actually changed; the steady-state case (nothing changed)
     * costs no pool thread at all.
     *
     * <p>Because triggers are collapsed, a call made while a reload is already running is notified
     * when <em>that</em> run finishes, not by a run of its own. Such a run may have read the content
     * hashes before this caller's change landed, so completion means "the in-flight reload finished",
     * not "every change visible at call time is loaded". The cluster-state listener keeps converging
     * the node either way.
     *
     * @param listener notified once: {@code onResponse} when the run completed (individual space
     *     failures are logged, not surfaced), {@code onFailure} if the Engine is unavailable or the
     *     run did not complete within {@link #RELOAD_TIMEOUT}.
     */
    public void reloadIfChanged(ActionListener<Void> listener) {
        Run run;
        synchronized (this.mutex) {
            if (this.current != null) {
                // A reload is already running; this trigger is folded into it and so is its listener.
                this.current.waiters.add(listener);
                return;
            }
            run = new Run();
            run.waiters.add(listener);
            this.current = run;
        }
        if (this.engine == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            this.complete(run, new IllegalStateException(Constants.E_LOG_ENGINE_IS_NULL));
            return;
        }
        run.watchdog = this.armWatchdog(run);
        try {
            this.reloadFrom(0, () -> this.complete(run, null));
        } catch (Exception e) {
            log.error(Constants.E_LOG_ENGINE_RELOAD_SCHEDULE_FAILED, e.getMessage());
            this.complete(run, e);
        }
    }

    /**
     * Ends a reload run: cancels its watchdog, clears the single-flight guard and notifies everyone
     * that joined the run. Idempotent — the first caller wins, so the watchdog and the normal
     * completion path cannot both notify, and a chain that completes after its watchdog already fired
     * does not disturb the run that replaced it.
     *
     * @param run the run to complete.
     * @param failure {@code null} when the run completed, otherwise the failure to report.
     * @return {@code true} if this call ended the run, {@code false} if it had already ended.
     */
    private boolean complete(Run run, Exception failure) {
        List<ActionListener<Void>> waiters;
        synchronized (this.mutex) {
            if (run.finished) {
                return false;
            }
            run.finished = true;
            if (this.current == run) {
                this.current = null;
            }
            waiters = List.copyOf(run.waiters);
            run.waiters.clear();
        }
        if (run.watchdog != null) {
            run.watchdog.cancel();
        }
        for (ActionListener<Void> waiter : waiters) {
            if (failure == null) {
                waiter.onResponse(null);
            } else {
                waiter.onFailure(failure);
            }
        }
        return true;
    }

    /**
     * Reloads the {@link #TRACKED_SPACES tracked spaces} one at a time, each step chained off the
     * previous space's completion. A failure loading one space is logged and does not prevent the
     * others from loading. Package-private so tests can drive the chain directly.
     *
     * <p>A node that cannot read the content yet is the one exception: every space reads its hash
     * from the same {@link Constants#INDEX_POLICIES} index, so a missing index or a cluster block
     * (usually {@code state not recovered / initialized}) is a precondition of the whole run rather
     * than a per-space failure. Both are normal while a node starts up and both clear on their own,
     * so the run ends after a single debug line instead of logging the same error once per tracked
     * space on every cluster-state update. The next cluster-state event retries.
     *
     * @param index index into {@link #TRACKED_SPACES} of the space to reload next.
     * @param onComplete invoked once, after the last space finishes (successfully or not).
     */
    void reloadFrom(int index, Runnable onComplete) {
        if (index >= TRACKED_SPACES.size()) {
            onComplete.run();
            return;
        }
        String space = TRACKED_SPACES.get(index);
        ActionListener<Void> next =
                ActionListener.wrap(
                        v -> this.reloadFrom(index + 1, onComplete),
                        e -> {
                            if (ExceptionsHelper.unwrap(e, IndexNotFoundException.class) != null) {
                                log.debug(
                                        Constants.D_LOG_ENGINE_POLICIES_INDEX_NOT_READY, Constants.INDEX_POLICIES);
                                onComplete.run();
                                return;
                            }
                            if (ExceptionsHelper.unwrap(e, ClusterBlockException.class) != null) {
                                log.debug(Constants.D_LOG_ENGINE_CLUSTER_NOT_READY, e.getMessage());
                                onComplete.run();
                                return;
                            }
                            log.error(Constants.E_LOG_ENGINE_SPACE_LOAD_FAILED, space, e.getMessage());
                            this.reloadFrom(index + 1, onComplete);
                        });
        try {
            this.reloadSpace(space, next);
        } catch (Exception e) {
            next.onFailure(e);
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
     * @param listener notified when this space is done: {@code onResponse} whether it was skipped or
     *     loaded, {@code onFailure} if an index read or the Engine call failed.
     */
    void reloadSpace(String space, ActionListener<Void> listener) {
        this.spaceService.getPolicy(
                space,
                ActionListener.wrap(
                        policy -> {
                            if (policy == null) {
                                log.debug(Constants.D_LOG_ENGINE_SPACE_NO_POLICY, space);
                                listener.onResponse(null);
                                return;
                            }

                            String desiredHash = extractSpaceHash(policy);
                            if (desiredHash == null || desiredHash.isBlank()) {
                                log.debug(Constants.D_LOG_ENGINE_SPACE_NO_HASH, space);
                                listener.onResponse(null);
                                return;
                            }
                            if (desiredHash.equals(this.loadedHashes.get(space))) {
                                log.debug(Constants.D_LOG_ENGINE_SPACE_UNCHANGED, space);
                                listener.onResponse(null);
                                return;
                            }

                            this.spaceService.buildEnginePayload(
                                    space,
                                    ActionListener.wrap(
                                            payload -> this.promote(space, desiredHash, payload, listener),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Promotes a space's payload into the local Engine on a generic pool thread. This is the only
     * blocking step of a reload (a Unix-domain-socket round trip), so it is the only one that
     * occupies a pool thread — and only for a space whose content actually changed.
     *
     * @param space the space name.
     * @param desiredHash the hash to record once the Engine accepts the payload.
     * @param payload the space's engine payload.
     * @param listener notified when the Engine call completes.
     */
    private void promote(
            String space, String desiredHash, JsonNode payload, ActionListener<Void> listener) {
        this.engine.promoteAsync(
                payload,
                ActionListener.wrap(
                        response -> {
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
                            listener.onResponse(null);
                        },
                        listener::onFailure));
    }

    /**
     * Arms the in-flight watchdog for a reload run. It exists only so a callback that never fires
     * cannot wedge the single-flight guard for the lifetime of the node: when it fires, the run is
     * completed exceptionally, its waiters are released and the next trigger starts a fresh run.
     *
     * @param run the run to time out.
     * @return the scheduled task so {@link #complete} can cancel it, or {@code null} if it could not
     *     be scheduled (e.g. the pool is shutting down).
     */
    private Scheduler.ScheduledCancellable armWatchdog(Run run) {
        try {
            return this.threadPool.schedule(
                    () -> {
                        if (this.complete(
                                run,
                                new OpenSearchTimeoutException(
                                        Constants.W_LOG_ENGINE_RELOAD_TIMED_OUT, RELOAD_TIMEOUT))) {
                            log.warn(Constants.W_LOG_ENGINE_RELOAD_TIMED_OUT, RELOAD_TIMEOUT);
                        }
                    },
                    RELOAD_TIMEOUT,
                    ThreadPool.Names.GENERIC);
        } catch (Exception e) {
            log.debug(Constants.E_LOG_ENGINE_RELOAD_SCHEDULE_FAILED, e.getMessage());
            return null;
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
}
