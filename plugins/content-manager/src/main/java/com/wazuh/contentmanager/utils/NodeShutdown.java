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
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.lifecycle.LifecycleListener;
import org.opensearch.node.NodeClosedException;

/**
 * Tells failures caused by the local node shutting down apart from real ones.
 *
 * <p>A node that stops while a sync runs fails every operation still in flight, and those failures
 * are an expected outcome of the stop, not a fault: they are logged at debug. The work they cut is
 * either recorded as pending before it starts or picked up again by the next pass after the
 * restart.
 *
 * <p>The exception alone does not tell them apart. The node stops its services in order: the
 * cluster service first, then the search service, which frees every open search and point-in-time
 * context, and only then the transport service, whose requests fail with {@link
 * NodeClosedException}. A search that was paging through a point in time in between fails with "all
 * shards failed" over a missing search context, which is also how an expired point in time fails on
 * a healthy node. So the stop is detected by its start, through a listener on the cluster service,
 * and {@link NodeClosedException} is kept as a signal for a stop the listener did not see.
 */
public final class NodeShutdown {

    /** Set once the watched component starts stopping; never cleared for that component. */
    private static volatile boolean stopping;

    private NodeShutdown() {}

    /**
     * Starts watching the given component, normally the node's cluster service, and forgets a stop
     * seen on a component watched before (a node restarted in the same JVM by the test framework).
     *
     * @param component the component whose stop marks the node as shutting down.
     */
    public static void watch(LifecycleComponent component) {
        stopping = false;
        component.addLifecycleListener(
                new LifecycleListener() {
                    @Override
                    public void beforeStop() {
                        stopping = true;
                    }
                });
    }

    /**
     * Returns whether a failure is the local node shutting down rather than a real failure of the
     * operation: the node has started stopping, or the failure's cause chain holds a {@link
     * NodeClosedException}.
     *
     * <p>A peer node going away ({@code NodeNotConnectedException}, {@code
     * NodeDisconnectedException}) is not counted: this node keeps running, and the sync it was doing
     * failed.
     *
     * @param e the failure to classify.
     * @return {@code true} if the failure is caused by the local node shutting down.
     */
    public static boolean isShutdownFailure(Throwable e) {
        return stopping || ExceptionsHelper.unwrap(e, NodeClosedException.class) != null;
    }

    /**
     * Returns the level to log a failure at: debug when it is the local node shutting down, the given
     * level otherwise.
     *
     * @param e the failure to log.
     * @param level the level for a real failure.
     * @return the level to log the failure at.
     */
    public static Level levelFor(Throwable e, Level level) {
        return isShutdownFailure(e) ? Level.DEBUG : level;
    }
}
