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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.transport.ConnectTransportException;

/**
 * Classifies index-read failures that clear on their own: a node starting up, or a peer node that
 * holds the only active copy of a shard leaving the cluster.
 *
 * <p>Shared by every read path that hits these conditions so they agree on what counts as noise:
 * the reader that hits the condition first (e.g. {@code SpaceService.getPolicy}) and the caller
 * that decides what to do about it (e.g. {@code EngineContentLoader}) must not classify the same
 * failure differently, or one of them logs an ERROR for a condition the other already knows is
 * transient.
 */
public final class TransientFailures {

    private TransientFailures() {}

    /**
     * Classifies a read failure as an expected, self-healing condition rather than a real error.
     *
     * <p>During startup (especially on a multi-node cluster) the index shards may not be allocated
     * yet: the index is briefly absent ({@link IndexNotFoundException}), the cluster state is not
     * recovered ({@link ClusterBlockException}), or a search reaches the coordinating node before any
     * shard copy is active. The last case surfaces as a {@link SearchPhaseExecutionException} ("all
     * shards failed") whose shard-level cause is a {@link NoShardAvailableActionException} or {@link
     * UnavailableShardsException}.
     *
     * <p>A peer node that restarts or stops causes the same "all shards failed" while it holds the
     * only active copy of a shard. Until this node applies the cluster state that removes the peer,
     * the search is still sent there and fails with a {@link ConnectTransportException} ({@code
     * NodeNotConnectedException}, {@code NodeDisconnectedException}, or a refused connection). Once
     * the peer is removed, the shard is unassigned and the search fails with a 503, as on startup.
     *
     * <p>Only these specific cases are transient. A generic {@link SearchPhaseExecutionException} — a
     * malformed query, an aggregation error — is a real failure and must not be swallowed, since that
     * class covers <em>all</em> search failures. Two kinds are accepted. One has status {@code 503
     * SERVICE_UNAVAILABLE}: that is "all shards failed" reported without a shard-level cause attached
     * (empty {@code shardFailures}), still an availability problem and not a query problem. The other
     * is one whose every shard failure is a shard copy on a node that could not be reached, so a
     * single query error among them keeps it a real failure.
     *
     * <p>The whole cause chain is inspected, so a failure already wrapped by an intermediate reader
     * (as {@code SpaceService.getPolicy} wraps it in an {@link java.io.IOException}) is still
     * classified on its original cause.
     *
     * @param e the failure to classify.
     * @return {@code true} if the failure is an expected condition that will self-heal once the
     *     cluster finishes recovering or the peer's shards are reassigned.
     */
    public static boolean isTransientReadFailure(Exception e) {
        if (ExceptionsHelper.unwrap(e, IndexNotFoundException.class) != null
                || ExceptionsHelper.unwrap(e, ClusterBlockException.class) != null
                || ExceptionsHelper.unwrap(e, NoShardAvailableActionException.class) != null
                || ExceptionsHelper.unwrap(e, UnavailableShardsException.class) != null) {
            return true;
        }
        SearchPhaseExecutionException searchFailure =
                (SearchPhaseExecutionException)
                        ExceptionsHelper.unwrap(e, SearchPhaseExecutionException.class);
        return searchFailure != null
                && (searchFailure.status() == RestStatus.SERVICE_UNAVAILABLE
                        || onlyUnreachableCopies(searchFailure.shardFailures()));
    }

    /**
     * Returns the level to log a failed content read at: debug when the failure clears on its own,
     * because the local node is shutting down ({@link NodeShutdown#isShutdownFailure}) or the read
     * failure is transient ({@link #isTransientReadFailure}), the given level otherwise.
     *
     * @param e the failure to log.
     * @param level the level for a real failure.
     * @return the level to log the failure at.
     */
    public static Level levelFor(Exception e, Level level) {
        return NodeShutdown.isShutdownFailure(e) || isTransientReadFailure(e) ? Level.DEBUG : level;
    }

    /**
     * Returns whether every shard failure of a search is a shard copy on a node this node could not
     * connect to. Copies that are merely not active never show up here: the search drops those
     * failures and reports the 503 checked above.
     *
     * @param failures the search's shard failures.
     * @return {@code true} if there is at least one failure and all of them are of that kind.
     */
    private static boolean onlyUnreachableCopies(ShardSearchFailure[] failures) {
        if (failures.length == 0) {
            return false;
        }
        for (ShardSearchFailure failure : failures) {
            if (!(ExceptionsHelper.unwrapCause(failure.getCause())
                    instanceof ConnectTransportException)) {
                return false;
            }
        }
        return true;
    }
}
