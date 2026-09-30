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

import org.opensearch.action.NoShardAvailableActionException;
import org.opensearch.action.UnavailableShardsException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.gateway.GatewayService;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.Set;

import static com.wazuh.contentmanager.utils.TransientFailures.isTransientReadFailure;

/** Unit tests for {@link TransientFailures}. */
public class TransientFailuresTests extends OpenSearchTestCase {

    private static final ShardId SHARD_ID = new ShardId(Constants.INDEX_POLICIES, "_na_", 0);

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
}
