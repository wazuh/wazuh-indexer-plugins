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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.threadpool.ThreadPool;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex.EngineLoadUpdate;
import com.wazuh.contentmanager.cti.catalog.model.EngineLoadFailure;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.NodeShutdown;
import com.wazuh.contentmanager.utils.TransientFailures;

/**
 * Records the result of loading the CTI ruleset content, the {@code standard} space, into this
 * node's Engine in the ruleset consumer document of {@code .wazuh-cti-consumers}. Without it, the
 * document reads as in sync while the Engine refuses the content or cannot be reached, and every
 * client that reads it says the ruleset is up to date.
 *
 * <p>Each node records its own result under its node id: a failure while its loads fail, nothing
 * once one succeeds. While any node has a failure recorded, the document lists {@code engine_load}
 * in {@code pending_sync_phases} and shows the most recent failure in {@code engine_load_error}
 * (see {@code LocalConsumer#toXContent}). The failures of nodes that left the cluster are dropped:
 * by every write, and by the elected cluster manager when a node leaves or when it is elected.
 *
 * <p>The document is written only when the recorded state changes: a node starts failing, fails in
 * a different way, or loads the content again. Retries that fail the same way leave it alone. The
 * document is read for every result, so the record converges even after a restart, a rejoin, or a
 * write it missed; next to the load the result comes from, the read costs nothing.
 *
 * <p>Results are recorded one at a time, off the caller's thread: a single task on the generic pool
 * records the latest result, so bursts collapse and a failure can never be written after the
 * success that followed it. A record that cannot be written is retried with a growing delay until
 * it is. The task stashes the thread context, because a load started by the reload broadcast runs
 * in the context of the user whose change triggered it.
 */
public class EngineLoadReporter {

    private static final Logger log = LogManager.getLogger(EngineLoadReporter.class);

    /** Longest Engine message recorded; longer ones are cut. */
    static final int MESSAGE_MAX_LENGTH = 1024;

    /** Delay before the first retry of a record that could not be written. */
    static final TimeValue RETRY_INITIAL_DELAY = TimeValue.timeValueSeconds(5);

    /** Upper bound of the retry delay, which doubles with each consecutive failed attempt. */
    static final TimeValue RETRY_MAX_DELAY = TimeValue.timeValueMinutes(5);

    /** ISO-8601 with milliseconds always present, as the other dates of the consumer document. */
    private static final DateTimeFormatter TIMESTAMP =
            new DateTimeFormatterBuilder().appendInstant(3).toFormatter(Locale.ROOT);

    /**
     * The result of one load: loaded, or failed with a reason and a message.
     *
     * @param reason {@code null} when the load succeeded.
     * @param message The Engine's message, when the load failed.
     */
    record Outcome(String reason, String message) {
        static final Outcome LOADED = new Outcome(null, null);

        boolean loaded() {
            return this.reason == null;
        }
    }

    private final ConsumersIndex consumersIndex;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    /** Guards the fields below. */
    private final Object mutex = new Object();

    /** The latest result not yet recorded, or {@code null}. */
    private Outcome pending;

    /** Whether the failures of departed nodes are to be dropped. */
    private boolean prunePending;

    /** Whether the task is running or waiting for a retry; at most one at a time. */
    private boolean draining;

    /** Consecutive attempts that failed to write, for the retry delay. */
    private int failedAttempts;

    /** Whether the current streak of failed attempts was already logged as a warning. */
    private boolean warned;

    /**
     * Constructs a reporter.
     *
     * @param consumersIndex the index holding the ruleset consumer document.
     * @param clusterService gives the local node and the nodes in the cluster.
     * @param threadPool runs the recording task and its retries.
     */
    public EngineLoadReporter(
            ConsumersIndex consumersIndex, ClusterService clusterService, ThreadPool threadPool) {
        this.consumersIndex = consumersIndex;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    /**
     * Reports that this node's Engine accepted a space.
     *
     * @param space the space name.
     */
    public void loaded(String space) {
        if (EngineLoadReporter.isRecorded(space)) {
            this.submit(Outcome.LOADED, false);
        }
    }

    /**
     * Reports that loading a space into this node's Engine failed.
     *
     * @param space the space name.
     * @param reason {@link EngineLoadFailure#REASON_REFUSED} or {@link
     *     EngineLoadFailure#REASON_UNREACHABLE}.
     * @param message the Engine's message; cut to {@link #MESSAGE_MAX_LENGTH} characters.
     */
    public void failed(String space, String reason, String message) {
        if (EngineLoadReporter.isRecorded(space)) {
            this.submit(new Outcome(reason, EngineLoadReporter.trim(message)), false);
        }
    }

    /**
     * Drops the failures of departed nodes when this node is the elected cluster manager and a node
     * left, or it was just elected. A node that never comes back would otherwise keep {@code
     * engine_load} listed forever. Called from the cluster applier thread: it only queues the work.
     *
     * @param event the cluster state change.
     */
    public void onClusterChanged(ClusterChangedEvent event) {
        if (!event.localNodeClusterManager()) {
            return;
        }
        if (event.nodesRemoved() || !event.previousState().nodes().isLocalNodeElectedClusterManager()) {
            this.submit(null, true);
        }
    }

    /**
     * Returns whether the results of a space are recorded. Only the {@code standard} space holds the
     * CTI ruleset; {@code test} and {@code custom} hold the user's own content.
     *
     * @param space the space name.
     * @return {@code true} for the {@code standard} space.
     */
    private static boolean isRecorded(String space) {
        return Space.STANDARD.toString().equals(space);
    }

    /**
     * Cuts an Engine message to {@link #MESSAGE_MAX_LENGTH} characters.
     *
     * @param message the message, or {@code null}.
     * @return the message, cut, or an empty string.
     */
    static String trim(String message) {
        if (message == null) {
            return "";
        }
        return message.length() > MESSAGE_MAX_LENGTH
                ? message.substring(0, MESSAGE_MAX_LENGTH)
                : message;
    }

    /**
     * Queues a result, or a prune, and starts the task unless it is already running.
     *
     * @param outcome the result, or {@code null} to only drop the failures of departed nodes.
     * @param prune whether to drop the failures of departed nodes.
     */
    private void submit(Outcome outcome, boolean prune) {
        synchronized (this.mutex) {
            if (outcome != null) {
                this.pending = outcome;
            }
            this.prunePending |= prune;
            if (this.draining) {
                return;
            }
            this.draining = true;
        }
        try {
            this.threadPool.generic().execute(this::drain);
        } catch (Exception e) {
            // The node is shutting down: the next start loads every space and records the results.
            synchronized (this.mutex) {
                this.draining = false;
            }
            log.debug(Constants.D_LOG_ENGINE_LOAD_RESULT_NODE_STOPPING, e.getMessage());
        }
    }

    /**
     * Records the queued results until none is left. When a record cannot be written, it is queued
     * again, unless a newer result arrived meanwhile, and the task retries after a delay.
     */
    void drain() {
        while (true) {
            Outcome outcome;
            boolean prune;
            synchronized (this.mutex) {
                outcome = this.pending;
                prune = this.prunePending;
                this.pending = null;
                this.prunePending = false;
                if (outcome == null && !prune) {
                    this.draining = false;
                    return;
                }
            }
            try (ThreadContext.StoredContext ignored =
                    this.threadPool.getThreadContext().stashContext()) {
                this.record(outcome);
                synchronized (this.mutex) {
                    this.failedAttempts = 0;
                    this.warned = false;
                }
            } catch (Exception e) {
                synchronized (this.mutex) {
                    if (this.pending == null) {
                        this.pending = outcome;
                    }
                    this.prunePending |= prune;
                }
                this.retryLater(e);
                return;
            }
        }
    }

    /**
     * Applies one result to the ruleset consumer document.
     *
     * @param outcome the result, or {@code null} to only drop the failures of departed nodes.
     * @throws Exception if the document cannot be read or written.
     */
    private void record(Outcome outcome) throws Exception {
        DiscoveryNode localNode = this.clusterService.localNode();
        DiscoveryNodes nodes = this.clusterService.state().nodes();
        String now = TIMESTAMP.format(Instant.ofEpochMilli(this.threadPool.absoluteTimeInMillis()));
        EngineLoadUpdate result =
                this.consumersIndex.updateEngineLoadFailures(
                        Constants.CONSUMER_TYPE_RULESET,
                        stored -> EngineLoadReporter.apply(stored, outcome, localNode, nodes, now));
        Object described =
                outcome == null ? "departed nodes dropped" : EngineLoadReporter.describe(outcome);
        switch (result) {
            case ABSENT ->
                    log.debug(
                            Constants.D_LOG_ENGINE_LOAD_RESULT_DOC_ABSENT,
                            Constants.CONSUMER_TYPE_RULESET,
                            localNode.getName());
            case UNCHANGED ->
                    log.debug(
                            Constants.D_LOG_ENGINE_LOAD_RESULT_UNCHANGED,
                            localNode.getName(),
                            Constants.CONSUMER_TYPE_RULESET,
                            described);
            case WRITTEN ->
                    log.debug(
                            Constants.D_LOG_ENGINE_LOAD_RESULT_RECORDED,
                            localNode.getName(),
                            Constants.CONSUMER_TYPE_RULESET,
                            described);
        }
    }

    /**
     * Computes the failures to record from the stored ones. Pure, so a conflicting write can run it
     * again on the newer document.
     *
     * <p>Failures of nodes that are not in the cluster are dropped, but only while a cluster manager
     * is elected: a node cut off from the cluster sees no other nodes.
     *
     * @param stored the stored failures by node id.
     * @param outcome this node's result, or {@code null} to only drop the departed nodes.
     * @param localNode this node.
     * @param nodes the nodes in the cluster.
     * @param now the time to record as {@code failed_at} when this node starts failing this way.
     * @return the failures to record.
     */
    static Map<String, EngineLoadFailure> apply(
            Map<String, EngineLoadFailure> stored,
            Outcome outcome,
            DiscoveryNode localNode,
            DiscoveryNodes nodes,
            String now) {
        Map<String, EngineLoadFailure> updated = new TreeMap<>(stored);
        if (nodes.getClusterManagerNodeId() != null) {
            updated.keySet().removeIf(nodeId -> !nodes.nodeExists(nodeId));
        }
        if (outcome == null) {
            return updated;
        }
        if (outcome.loaded()) {
            updated.remove(localNode.getId());
            return updated;
        }
        EngineLoadFailure failure =
                new EngineLoadFailure(now, outcome.reason(), outcome.message(), localNode.getName());
        if (!failure.isSameFailureAs(updated.get(localNode.getId()))) {
            updated.put(localNode.getId(), failure);
        }
        return updated;
    }

    /**
     * Describes a result for the logs.
     *
     * @param outcome the result.
     * @return {@code loaded}, or the reason and message of the failure.
     */
    private static String describe(Outcome outcome) {
        return outcome.loaded() ? "loaded" : outcome.reason() + " (" + outcome.message() + ")";
    }

    /**
     * Schedules the task again after a record could not be written. The delay doubles with each
     * consecutive failed attempt, up to {@link #RETRY_MAX_DELAY}. The first failure of a streak is
     * logged as a warning, unless the index is only starting up or the node is stopping; a stopping
     * node gives up, since the next start loads every space and records the results again.
     *
     * @param e why the record could not be written.
     */
    private void retryLater(Exception e) {
        if (NodeShutdown.isShutdownFailure(e)) {
            synchronized (this.mutex) {
                this.draining = false;
            }
            log.debug(Constants.D_LOG_ENGINE_LOAD_RESULT_NODE_STOPPING, e.getMessage());
            return;
        }
        int attempts;
        Level level;
        synchronized (this.mutex) {
            attempts = this.failedAttempts++;
            level = this.warned ? Level.DEBUG : TransientFailures.levelFor(e, Level.WARN);
            this.warned |= level == Level.WARN;
        }
        TimeValue delay =
                TimeValue.timeValueMillis(
                        Math.min(
                                RETRY_INITIAL_DELAY.millis() << Math.min(attempts, 16), RETRY_MAX_DELAY.millis()));
        log.log(
                level,
                Constants.W_LOG_ENGINE_LOAD_RESULT_FAILED,
                Constants.CONSUMER_TYPE_RULESET,
                delay,
                e.getMessage());
        try {
            this.threadPool.schedule(this::drain, delay, ThreadPool.Names.GENERIC);
        } catch (Exception scheduleFailure) {
            synchronized (this.mutex) {
                this.draining = false;
            }
        }
    }
}
