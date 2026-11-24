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

import org.opensearch.Version;
import org.opensearch.action.NoShardAvailableActionException;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodeRole;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.node.NodeClosedException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex.EngineLoadUpdate;
import com.wazuh.contentmanager.cti.catalog.model.EngineLoadFailure;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link EngineLoadReporter}: what each node records in the ruleset consumer document
 * after an Engine call, and when it writes.
 */
public class EngineLoadReporterTests extends OpenSearchTestCase {

    private static final String STANDARD = "standard";
    private static final String REFUSED_MESSAGE =
            "Failed to build operation 'tmp_json.event.action: $_tmp.method': Field 'tmp_json.event.action'"
                    + " is not defined in WCS schema";

    private DiscoveryNode node1;
    private DiscoveryNode node2;
    private FakeConsumersIndex consumersIndex;
    private AtomicLong clock;
    private List<Scheduled> scheduled;
    private ThreadContext threadContext;

    /** A task handed to {@link ThreadPool#schedule}, run by the test when it chooses. */
    private record Scheduled(Runnable task, TimeValue delay) {}

    /**
     * In-memory stand-in for {@link ConsumersIndex#updateEngineLoadFailures}: applies the change to
     * the stored failures and counts the writes, the way the real index only writes a changed map.
     */
    private static final class FakeConsumersIndex extends ConsumersIndex {
        private Map<String, EngineLoadFailure> stored = new TreeMap<>();
        private boolean exists = true;
        private int writes;
        private int failuresToThrow;
        private Exception failure;
        private UnaryOperator<Map<String, EngineLoadFailure>> lastChange;
        private Runnable onUpdate = () -> {};

        FakeConsumersIndex(Client client) {
            super(client);
        }

        @Override
        public EngineLoadUpdate updateEngineLoadFailures(
                String type, UnaryOperator<Map<String, EngineLoadFailure>> change)
                throws ExecutionException {
            Assert.assertEquals(Constants.CONSUMER_TYPE_RULESET, type);
            this.onUpdate.run();
            this.lastChange = change;
            if (this.failuresToThrow > 0) {
                this.failuresToThrow--;
                throw new ExecutionException(this.failure);
            }
            if (!this.exists) {
                return EngineLoadUpdate.ABSENT;
            }
            Map<String, EngineLoadFailure> updated =
                    change.apply(Collections.unmodifiableMap(this.stored));
            if (updated.equals(this.stored)) {
                return EngineLoadUpdate.UNCHANGED;
            }
            this.stored = new TreeMap<>(updated);
            this.writes++;
            return EngineLoadUpdate.WRITTEN;
        }
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
        this.node1 =
                new DiscoveryNode(
                        "node-1",
                        "id-1",
                        OpenSearchTestCase.buildNewFakeTransportAddress(),
                        Collections.emptyMap(),
                        DiscoveryNodeRole.BUILT_IN_ROLES,
                        Version.CURRENT);
        this.node2 =
                new DiscoveryNode(
                        "node-2",
                        "id-2",
                        OpenSearchTestCase.buildNewFakeTransportAddress(),
                        Collections.emptyMap(),
                        DiscoveryNodeRole.BUILT_IN_ROLES,
                        Version.CURRENT);
        this.consumersIndex = new FakeConsumersIndex(mock(Client.class));
        this.clock = new AtomicLong(1_763_880_432_000L);
        this.scheduled = new ArrayList<>();
        this.threadContext = new ThreadContext(Settings.EMPTY);
    }

    /**
     * Builds a reporter running on {@code localNode}, with its records written on the calling thread
     * and its retries collected in {@link #scheduled}.
     */
    private EngineLoadReporter reporter(DiscoveryNode localNode, DiscoveryNodes nodes) {
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.localNode()).thenReturn(localNode);
        when(clusterService.state())
                .thenReturn(ClusterState.builder(new ClusterName("test")).nodes(nodes).build());
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.generic()).thenReturn(OpenSearchExecutors.newDirectExecutorService());
        when(threadPool.getThreadContext()).thenReturn(this.threadContext);
        when(threadPool.absoluteTimeInMillis()).thenAnswer(invocation -> this.clock.get());
        when(threadPool.schedule(
                        any(Runnable.class), any(TimeValue.class), eq(ThreadPool.Names.GENERIC)))
                .thenAnswer(
                        invocation -> {
                            this.scheduled.add(
                                    new Scheduled(invocation.getArgument(0), invocation.getArgument(1)));
                            return null;
                        });
        return new EngineLoadReporter(this.consumersIndex, clusterService, threadPool);
    }

    /** Both nodes in the cluster, node 1 the elected cluster manager. */
    private DiscoveryNodes bothNodes(DiscoveryNode localNode) {
        return DiscoveryNodes.builder()
                .add(this.node1)
                .add(this.node2)
                .localNodeId(localNode.getId())
                .clusterManagerNodeId(this.node1.getId())
                .build();
    }

    private EngineLoadReporter reporter1() {
        return this.reporter(this.node1, this.bothNodes(this.node1));
    }

    private EngineLoadReporter reporter2() {
        return this.reporter(this.node2, this.bothNodes(this.node2));
    }

    /** A refused payload records the node's failure, with the Engine's message and the time. */
    public void testRefusedLoadRecordsTheFailure() {
        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(1, this.consumersIndex.writes);
        Assert.assertEquals(
                Map.of(
                        "id-1",
                        new EngineLoadFailure(
                                "2025-11-23T06:47:12.000Z",
                                EngineLoadFailure.REASON_REFUSED,
                                REFUSED_MESSAGE,
                                "node-1")),
                this.consumersIndex.stored);
    }

    /** An unreachable Engine is recorded as such; a long message is cut. */
    public void testUnreachableEngineIsRecordedWithACutMessage() {
        String longMessage = "x".repeat(EngineLoadReporter.MESSAGE_MAX_LENGTH + 500);

        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_UNREACHABLE, longMessage);

        EngineLoadFailure failure = this.consumersIndex.stored.get("id-1");
        Assert.assertEquals(EngineLoadFailure.REASON_UNREACHABLE, failure.getReason());
        Assert.assertEquals(EngineLoadReporter.MESSAGE_MAX_LENGTH, failure.getMessage().length());
    }

    /** A retry that fails the same way writes nothing and keeps the time the failure started. */
    public void testSameFailureAgainWritesNothing() {
        EngineLoadReporter reporter = this.reporter1();
        reporter.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);
        this.clock.addAndGet(60_000);

        reporter.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(1, this.consumersIndex.writes);
        Assert.assertEquals(
                "2025-11-23T06:47:12.000Z", this.consumersIndex.stored.get("id-1").getFailedAt());
    }

    /** A failure of another kind is a change of state: it is written with a new time. */
    public void testDifferentFailureIsWritten() {
        EngineLoadReporter reporter = this.reporter1();
        reporter.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);
        this.clock.addAndGet(60_000);

        reporter.failed(
                STANDARD, EngineLoadFailure.REASON_UNREACHABLE, "Timed out communicating with the Engine.");

        Assert.assertEquals(2, this.consumersIndex.writes);
        EngineLoadFailure failure = this.consumersIndex.stored.get("id-1");
        Assert.assertEquals(EngineLoadFailure.REASON_UNREACHABLE, failure.getReason());
        Assert.assertEquals("2025-11-23T06:48:12.000Z", failure.getFailedAt());
    }

    /** A successful load after a failure removes the node's failure. */
    public void testSuccessAfterFailureClearsIt() {
        EngineLoadReporter reporter = this.reporter1();
        reporter.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        reporter.loaded(STANDARD);

        Assert.assertEquals(2, this.consumersIndex.writes);
        Assert.assertTrue(this.consumersIndex.stored.isEmpty());
    }

    /** A successful load with nothing recorded writes nothing. */
    public void testSuccessWithNothingRecordedWritesNothing() {
        this.reporter1().loaded(STANDARD);

        Assert.assertEquals(0, this.consumersIndex.writes);
    }

    /**
     * After a restart the reporter knows nothing of what it recorded before; it compares with the
     * document. The same failure writes nothing, and a success clears the failure recorded before the
     * restart.
     */
    public void testRestartWhilePending() {
        EngineLoadFailure beforeRestart =
                new EngineLoadFailure(
                        "2025-11-22T10:00:00.000Z",
                        EngineLoadFailure.REASON_REFUSED,
                        REFUSED_MESSAGE,
                        "node-1");
        this.consumersIndex.stored.put("id-1", beforeRestart);

        EngineLoadReporter restarted = this.reporter1();
        restarted.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(0, this.consumersIndex.writes);
        Assert.assertEquals(beforeRestart, this.consumersIndex.stored.get("id-1"));

        restarted.loaded(STANDARD);

        Assert.assertTrue(this.consumersIndex.stored.isEmpty());
    }

    /**
     * Any failing node keeps the load pending: when one of two failing nodes recovers, the other's
     * failure stays, and the load is no longer pending only once both loaded the content.
     */
    public void testOneNodeStillFailingKeepsThePendingLoad() {
        EngineLoadReporter reporter1 = this.reporter1();
        EngineLoadReporter reporter2 = this.reporter2();
        reporter1.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);
        this.clock.addAndGet(1_000);
        reporter2.failed(
                STANDARD, EngineLoadFailure.REASON_UNREACHABLE, "Failed to communicate with the Engine.");

        Assert.assertEquals(Set.of("id-1", "id-2"), this.consumersIndex.stored.keySet());

        reporter2.loaded(STANDARD);

        Assert.assertEquals(Set.of("id-1"), this.consumersIndex.stored.keySet());
        Assert.assertEquals("node-1", this.consumersIndex.stored.get("id-1").getNode());

        reporter1.loaded(STANDARD);

        Assert.assertTrue(this.consumersIndex.stored.isEmpty());
    }

    /** A node that loads the content does not clear another node's failure. */
    public void testLoadingNodeLeavesTheFailingNodeAlone() {
        this.reporter2()
                .failed(
                        STANDARD,
                        EngineLoadFailure.REASON_UNREACHABLE,
                        "Failed to communicate with the Engine.");

        this.reporter1().loaded(STANDARD);

        Assert.assertEquals(Set.of("id-2"), this.consumersIndex.stored.keySet());
    }

    /** Only the standard space holds the CTI ruleset: the user's spaces are not recorded. */
    public void testOtherSpacesAreNotRecorded() {
        EngineLoadReporter reporter = this.reporter1();

        reporter.failed("test", EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);
        reporter.failed("custom", EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertNull(this.consumersIndex.lastChange);
        Assert.assertEquals(0, this.consumersIndex.writes);
    }

    /**
     * The elected cluster manager drops the failure of a node that left the cluster, which would
     * otherwise keep the load pending forever.
     */
    public void testClusterManagerDropsTheFailureOfADepartedNode() {
        this.consumersIndex.stored.put(
                "id-2",
                new EngineLoadFailure(
                        "2025-11-22T10:00:00.000Z", EngineLoadFailure.REASON_UNREACHABLE, "down", "node-2"));
        DiscoveryNodes withoutNode2 =
                DiscoveryNodes.builder()
                        .add(this.node1)
                        .localNodeId(this.node1.getId())
                        .clusterManagerNodeId(this.node1.getId())
                        .build();
        EngineLoadReporter reporter = this.reporter(this.node1, withoutNode2);

        reporter.onClusterChanged(this.event(withoutNode2, this.bothNodes(this.node1)));

        Assert.assertTrue(this.consumersIndex.stored.isEmpty());
    }

    /** A node that is not the elected cluster manager leaves departed nodes to it. */
    public void testOtherNodesDoNotPruneOnClusterChanges() {
        DiscoveryNodes seenByNode2 =
                DiscoveryNodes.builder()
                        .add(this.node1)
                        .add(this.node2)
                        .localNodeId(this.node2.getId())
                        .clusterManagerNodeId(this.node1.getId())
                        .build();
        EngineLoadReporter reporter = this.reporter(this.node2, seenByNode2);

        reporter.onClusterChanged(this.event(seenByNode2, seenByNode2));

        Assert.assertNull(this.consumersIndex.lastChange);
    }

    /**
     * Without an elected cluster manager a node sees no other nodes, so it drops nobody's failure
     * while recording its own.
     */
    public void testNoPruneWithoutAClusterManager() {
        this.consumersIndex.stored.put(
                "id-2",
                new EngineLoadFailure(
                        "2025-11-22T10:00:00.000Z", EngineLoadFailure.REASON_UNREACHABLE, "down", "node-2"));
        DiscoveryNodes cutOff =
                DiscoveryNodes.builder().add(this.node1).localNodeId(this.node1.getId()).build();

        this.reporter(this.node1, cutOff)
                .failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(Set.of("id-1", "id-2"), this.consumersIndex.stored.keySet());
    }

    /** With no consumer document yet there is nothing to record into, and nothing fails. */
    public void testAbsentDocumentRecordsNothing() {
        this.consumersIndex.exists = false;

        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(0, this.consumersIndex.writes);
        Assert.assertTrue(this.scheduled.isEmpty());
    }

    /**
     * A record that cannot be written is retried after a delay that doubles with each failed attempt,
     * and is written once the index accepts it.
     */
    public void testFailedWriteIsRetriedWithBackoff() {
        this.consumersIndex.failuresToThrow = 2;
        this.consumersIndex.failure =
                new NoShardAvailableActionException(new ShardId("idx", "uuid", 0));
        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(1, this.scheduled.size());
        Assert.assertEquals(EngineLoadReporter.RETRY_INITIAL_DELAY, this.scheduled.get(0).delay());
        this.scheduled.get(0).task().run();
        Assert.assertEquals(2, this.scheduled.size());
        Assert.assertEquals(TimeValue.timeValueSeconds(10), this.scheduled.get(1).delay());
        this.scheduled.get(1).task().run();

        Assert.assertEquals(2, this.scheduled.size());
        Assert.assertEquals(1, this.consumersIndex.writes);
        Assert.assertTrue(this.consumersIndex.stored.containsKey("id-1"));
    }

    /**
     * While a retry is pending, a newer result replaces the one that could not be written: a success
     * that follows a failure is never overwritten by it.
     */
    public void testNewerResultReplacesTheOneWaitingForARetry() {
        this.consumersIndex.failuresToThrow = 1;
        this.consumersIndex.failure = new IllegalStateException("index not ready");
        EngineLoadReporter reporter = this.reporter1();
        reporter.failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);
        Assert.assertEquals(1, this.scheduled.size());

        // The task waits for its retry, so this result is only queued.
        reporter.loaded(STANDARD);
        Assert.assertEquals(0, this.consumersIndex.writes);
        this.scheduled.get(0).task().run();

        Assert.assertTrue(this.consumersIndex.stored.isEmpty());
        Assert.assertEquals(0, this.consumersIndex.writes);
    }

    /** A stopping node gives up instead of retrying: the next start records the results again. */
    public void testStoppingNodeDoesNotRetry() {
        this.consumersIndex.failuresToThrow = 1;
        this.consumersIndex.failure = new NodeClosedException(this.node1);

        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertTrue(this.scheduled.isEmpty());
    }

    /**
     * The record is written with the thread context stashed: a load started by the reload broadcast
     * runs in the context of the user whose change triggered it, who may not be allowed to write the
     * consumers index.
     */
    public void testThreadContextIsStashed() {
        List<String> seenUsers = new ArrayList<>();
        this.consumersIndex.onUpdate = () -> seenUsers.add(this.threadContext.getHeader("user"));
        this.threadContext.putHeader("user", "analyst");

        this.reporter1().failed(STANDARD, EngineLoadFailure.REASON_REFUSED, REFUSED_MESSAGE);

        Assert.assertEquals(Collections.singletonList(null), seenUsers);
        Assert.assertEquals("analyst", this.threadContext.getHeader("user"));
    }

    private ClusterChangedEvent event(DiscoveryNodes current, DiscoveryNodes previous) {
        return new ClusterChangedEvent(
                "test",
                ClusterState.builder(new ClusterName("test")).nodes(current).build(),
                ClusterState.builder(new ClusterName("test")).nodes(previous).build());
    }
}
