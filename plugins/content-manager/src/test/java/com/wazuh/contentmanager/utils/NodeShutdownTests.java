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
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.node.NodeClosedException;
import org.opensearch.search.SearchContextMissingException;
import org.opensearch.search.internal.ShardSearchContextId;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.NodeNotConnectedException;
import org.opensearch.transport.SendRequestTransportException;
import org.junit.After;

import java.util.concurrent.ExecutionException;

/** Unit tests for {@link NodeShutdown}. */
public class NodeShutdownTests extends OpenSearchTestCase {

    /** A lifecycle component with no work of its own, standing in for the node's cluster service. */
    public static AbstractLifecycleComponent idleComponent() {
        return new AbstractLifecycleComponent() {
            @Override
            protected void doStart() {}

            @Override
            protected void doStop() {}

            @Override
            protected void doClose() {}
        };
    }

    /** The flag is JVM-wide: leave a running node behind for the tests that follow. */
    @After
    public void resetNodeShutdown() {
        NodeShutdown.watch(idleComponent());
    }

    /** A running node classifies nothing as shutdown noise but a closed-node failure. */
    public void testRunningNodeIsNotStopping() {
        AbstractLifecycleComponent component = idleComponent();
        NodeShutdown.watch(component);
        component.start();

        assertFalse(NodeShutdown.isShutdownFailure(new RuntimeException("query malformed")));
        assertEquals(
                Level.WARN, NodeShutdown.levelFor(new RuntimeException("query malformed"), Level.WARN));
    }

    /** Stopping the watched component marks the node as shutting down, for any failure. */
    public void testStopMarksTheNodeAsStopping() {
        AbstractLifecycleComponent component = idleComponent();
        NodeShutdown.watch(component);
        component.start();

        component.stop();

        assertTrue(NodeShutdown.isStopping());
        // The point-in-time search cut by the search service freeing its contexts.
        SearchPhaseExecutionException freedContext =
                new SearchPhaseExecutionException(
                        "query",
                        "all shards failed",
                        new ShardSearchFailure[] {
                            new ShardSearchFailure(
                                    new SearchContextMissingException(new ShardSearchContextId("session", 7L)))
                        });
        assertTrue(NodeShutdown.isShutdownFailure(freedContext));
        assertEquals(Level.DEBUG, NodeShutdown.levelFor(freedContext, Level.ERROR));
    }

    /** Watching a new component forgets the stop seen on the previous one. */
    public void testWatchResetsAStopSeenBefore() {
        AbstractLifecycleComponent first = idleComponent();
        NodeShutdown.watch(first);
        first.start();
        first.stop();

        NodeShutdown.watch(idleComponent());

        assertFalse(NodeShutdown.isShutdownFailure(new RuntimeException("query malformed")));
    }

    /**
     * A closed-node failure counts even when the stop was not seen, wrapped as the client wraps it.
     */
    public void testNodeClosedExceptionIsAShutdownFailure() {
        NodeShutdown.watch(idleComponent());
        Exception wrapped =
                new ExecutionException(
                        new SendRequestTransportException(
                                null, "indices:data/read/get[s]", new NodeClosedException((DiscoveryNode) null)));

        assertTrue(NodeShutdown.isShutdownFailure(wrapped));
    }

    /** A peer leaving the cluster is a real failure of the sync running on this node. */
    public void testPeerLeavingIsNotAShutdownFailure() {
        NodeShutdown.watch(idleComponent());

        assertFalse(
                NodeShutdown.isShutdownFailure(new NodeNotConnectedException(null, "Node not connected")));
    }
}
