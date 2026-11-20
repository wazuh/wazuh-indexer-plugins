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
package com.wazuh.contentmanager.utils;

import org.apache.logging.log4j.Level;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.NoShardAvailableActionException;
import org.opensearch.action.UnavailableShardsException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.gateway.GatewayService;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.node.NodeClosedException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.ConnectTransportException;
import org.opensearch.transport.NodeDisconnectedException;
import org.opensearch.transport.NodeNotConnectedException;
import org.opensearch.transport.RemoteTransportException;
import org.opensearch.transport.SendRequestTransportException;
import org.junit.After;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;

import static com.wazuh.contentmanager.utils.TransientFailures.isTransientReadFailure;

/** Unit tests for {@link TransientFailures}. */
public class TransientFailuresTests extends OpenSearchTestCase {

    private static final ShardId SHARD_ID = new ShardId(Constants.INDEX_POLICIES, "_na_", 0);

    /**
     * Builds the "all shards failed" a search reports when every shard failed with the given causes,
     * one per shard, the way the search builds it: the shard failures plus the first one's root
     * cause.
     *
     * @param causes the shard-level causes.
     * @return the search failure.
     */
    public static SearchPhaseExecutionException allShardsFailed(Exception... causes) {
        return new SearchPhaseExecutionException(
                "query",
                "all shards failed",
                ExceptionsHelper.unwrapCause(causes[0]),
                Arrays.stream(causes).map(ShardSearchFailure::new).toArray(ShardSearchFailure[]::new));
    }

    /** The shutdown flag is JVM-wide: leave a running node behind for the tests that follow. */
    @After
    public void resetNodeShutdown() {
        NodeShutdown.watch(NodeShutdownTests.idleComponent());
    }

    /**
     * Verifies the transient-failure classifier: only genuine shard-recovery conditions are treated
     * as transient. A generic {@link SearchPhaseExecutionException} caused by a bad query (status
     * 400) must NOT be swallowed, otherwise real search failures would silently disappear.
     */
    public void testStartupConditionsAreTransient() {
        // "all shards failed" with no shard-level cause attached — reported as 503 → transient.
        assertTrue(
                isTransientReadFailure(
                        new SearchPhaseExecutionException(
                                "query", "all shards failed", ShardSearchFailure.EMPTY_ARRAY)));

        // "all shards failed" whose shard cause is NoShardAvailable (shards recovering) → transient.
        assertTrue(
                isTransientReadFailure(
                        new SearchPhaseExecutionException(
                                "query",
                                "all shards failed",
                                new NoShardAvailableActionException(SHARD_ID),
                                ShardSearchFailure.EMPTY_ARRAY)));

        // A bare NoShardAvailable → transient.
        assertTrue(isTransientReadFailure(new NoShardAvailableActionException(SHARD_ID)));

        // Shards known but not yet active → transient.
        assertTrue(
                isTransientReadFailure(new UnavailableShardsException(SHARD_ID, "not enough replicas")));

        // The index has not been created yet → transient.
        assertTrue(isTransientReadFailure(new IndexNotFoundException(Constants.INDEX_POLICIES)));

        // Cluster state not recovered yet → transient.
        assertTrue(
                isTransientReadFailure(
                        new ClusterBlockException(Set.of(GatewayService.STATE_NOT_RECOVERED_BLOCK))));
    }

    /** A real query error or an unrelated failure must stay an error. */
    public void testRealFailuresAreNotTransient() {
        // A real query error (status 400) → NOT transient; must propagate as an error.
        assertFalse(
                isTransientReadFailure(
                        new SearchPhaseExecutionException(
                                "query",
                                "parse error",
                                new IllegalArgumentException("bad query"),
                                ShardSearchFailure.EMPTY_ARRAY)));

        // An unrelated failure → NOT transient.
        assertFalse(isTransientReadFailure(new RuntimeException("boom")));
    }

    /**
     * A transient failure keeps its classification through the wrapper an intermediate reader adds
     * ({@code SpaceService.getPolicy} rewraps every failure as an {@link IOException}). Without this,
     * a caller inspecting the wrapper would log the startup condition as an ERROR.
     */
    public void testClassificationSurvivesWrapping() {
        SearchPhaseExecutionException cause =
                new SearchPhaseExecutionException(
                        "query", "all shards failed", ShardSearchFailure.EMPTY_ARRAY);

        assertTrue(
                isTransientReadFailure(
                        new IOException("Failed to retrieve policy: " + cause.getMessage(), cause)));
    }

    /**
     * A peer node that holds the only active copy of a shard and is restarting or stopping. Until
     * this node removes the peer from its cluster state the search is still sent there, and it fails
     * with a connection error (wazuh-indexer#2118). Each cause below is one seen live on a 2-node
     * cluster while the peer restarted.
     */
    public void testDepartingPeerIsTransient() {
        assertTrue(
                isTransientReadFailure(
                        allShardsFailed(new NodeNotConnectedException(null, "Node not connected"))));
        assertTrue(
                isTransientReadFailure(
                        allShardsFailed(
                                new NodeDisconnectedException(null, "indices:data/read/search[phase/query]"))));
        assertTrue(
                isTransientReadFailure(
                        allShardsFailed(new ConnectTransportException(null, "connect_exception"))));

        // The cause as a remote hop reports it, and the failure as the reader rewraps it.
        SearchPhaseExecutionException remote =
                allShardsFailed(
                        new RemoteTransportException(
                                "[node-2]", new NodeNotConnectedException(null, "Node not connected")));
        assertTrue(
                isTransientReadFailure(
                        new IOException("Failed to fetch resources: " + remote.getMessage(), remote)));
    }

    /**
     * A departing peer does not hide a real failure: a query error on another shard, or an "all
     * shards failed" with no connection error at all, has the same 500 status and stays an error.
     */
    public void testRealFailureBesideADepartingPeerIsNotTransient() {
        assertFalse(
                isTransientReadFailure(
                        allShardsFailed(
                                new NodeNotConnectedException(null, "Node not connected"),
                                new IllegalArgumentException("bad query"))));
        assertFalse(isTransientReadFailure(allShardsFailed(new IllegalStateException("boom"))));
    }

    /**
     * A failed read is logged at debug when it clears on its own, a transient read failure or the
     * local node shutting down, and at the caller's level otherwise.
     */
    public void testLevelFor() {
        NodeShutdown.watch(NodeShutdownTests.idleComponent());

        assertEquals(
                Level.DEBUG,
                TransientFailures.levelFor(
                        allShardsFailed(new NodeNotConnectedException(null, "Node not connected")),
                        Level.ERROR));
        assertEquals(
                Level.DEBUG,
                TransientFailures.levelFor(
                        new SendRequestTransportException(
                                null, "indices:data/read/search", new NodeClosedException((DiscoveryNode) null)),
                        Level.ERROR));
        assertEquals(
                Level.ERROR, TransientFailures.levelFor(new RuntimeException("boom"), Level.ERROR));
    }
}
