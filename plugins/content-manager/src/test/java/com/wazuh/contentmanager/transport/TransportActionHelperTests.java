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
package com.wazuh.contentmanager.transport;

import org.apache.lucene.search.IndexSearcher;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NotSerializableExceptionWrapper;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.ReloadEngineContentAction;
import com.wazuh.contentmanager.action.ReloadEngineContentRequest;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Unit tests for {@link TransportActionHelper}. {@link
 * TransportActionHelper#reloadStandardSpaceIntoEngine} keeps the Engine's copy of the standard
 * policy in sync after a content mutation: without it the Engine serves the snapshot from its last
 * full load, so changes such as toggling an integration's {@code enabled} flag never reach the log
 * test endpoint.
 */
public class TransportActionHelperTests extends OpenSearchTestCase {

    private Client client;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
    }

    /**
     * A change to the standard space is loaded through the reload broadcast alone, which reaches this
     * node too. Promoting it here as well sent the Engine two overlapping loads of the same space,
     * and the Engine failed one of them (wazuh-indexer#2032).
     */
    public void testBroadcastsReloadWhenStandardSpaceChanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                Set.of(Space.STANDARD.toString()), this.client);

        verify(this.client)
                .execute(
                        eq(ReloadEngineContentAction.INSTANCE),
                        any(ReloadEngineContentRequest.class),
                        any(ActionListener.class));
        verifyNoMoreInteractions(this.client);
    }

    public void testSkipsReloadWhenStandardSpaceUnchanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                Set.of(Space.DRAFT.toString()), this.client);

        verifyNoInteractions(this.client);
    }

    public void testSkipsReloadWhenNoSpaceChanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(Set.of(), this.client);

        verifyNoInteractions(this.client);
    }

    public void testSkipsReloadWhenChangedSpacesIsNull() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(null, this.client);

        verifyNoInteractions(this.client);
    }

    /**
     * The mutation is already persisted by the time the reload runs, so a broadcast that fails is
     * logged, never rethrown.
     */
    @SuppressWarnings("unchecked")
    public void testToleratesBroadcastFailure() {
        doAnswer(
                        invocation -> {
                            ActionListener<Object> listener =
                                    (ActionListener<Object>) invocation.getArguments()[2];
                            listener.onFailure(new RuntimeException("node disconnected"));
                            return null;
                        })
                .when(this.client)
                .execute(
                        eq(ReloadEngineContentAction.INSTANCE),
                        any(ReloadEngineContentRequest.class),
                        any(ActionListener.class));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                Set.of(Space.STANDARD.toString()), this.client);
    }

    public void testClassifyExceptionReturnsSecurityExceptionStatus() {
        OpenSearchSecurityException securityException =
                new OpenSearchSecurityException("not authorized", RestStatus.FORBIDDEN);

        RestResponse classified = TransportActionHelper.classifyException(securityException);

        assertNotNull(classified);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), classified.getStatus());
    }

    /**
     * A cluster block's own {@code status()} often resolves below 500 (e.g. 403 for a write block),
     * but by convention it is a server fault, so it must be left unclassified rather than passed
     * through as a client error.
     */
    public void testClassifyExceptionLeavesClusterBlockUnclassified() {
        ClusterBlockException clusterBlockException =
                new ClusterBlockException(Map.of("my-index", Set.of(IndexMetadata.INDEX_WRITE_BLOCK)));
        assertEquals(RestStatus.FORBIDDEN, clusterBlockException.status());

        RestResponse classified = TransportActionHelper.classifyException(clusterBlockException);

        assertNull(classified);
    }

    /**
     * {@link IndexNotFoundException} carries a 404 status (below 500), but a missing internal plugin
     * index is a server fault, not a client not-found. It must be left unclassified so the caller
     * returns a generic 500 and does not leak the internal index name in the response body.
     */
    public void testClassifyExceptionLeavesIndexNotFoundUnclassified() {
        IndexNotFoundException indexNotFoundException =
                new IndexNotFoundException("wazuh-threatintel-policies");
        assertEquals(RestStatus.NOT_FOUND, indexNotFoundException.status());

        RestResponse classified = TransportActionHelper.classifyException(indexNotFoundException);

        assertNull(classified);
    }

    public void testClassifyExceptionReturnsOpenSearchExceptionStatusBelow500() {
        OpenSearchStatusException conflict =
                new OpenSearchStatusException(
                        "resource already exists in target space", RestStatus.CONFLICT);

        RestResponse classified = TransportActionHelper.classifyException(conflict);

        assertNotNull(classified);
        assertEquals(RestStatus.CONFLICT.getStatus(), classified.getStatus());
    }

    public void testClassifyExceptionLeavesServerFaultOpenSearchExceptionUnclassified() {
        OpenSearchStatusException serverFault =
                new OpenSearchStatusException("downstream unavailable", RestStatus.INTERNAL_SERVER_ERROR);

        RestResponse classified = TransportActionHelper.classifyException(serverFault);

        assertNull(classified);
    }

    public void testClassifyExceptionReturnsBadRequestForIllegalArgument() {
        RestResponse classified =
                TransportActionHelper.classifyException(new IllegalArgumentException("invalid input"));

        assertNotNull(classified);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), classified.getStatus());
    }

    /**
     * A search that fails on every shard names the shard's root cause, not the generic "all shards
     * failed" wrapper (wazuh-indexer#1945).
     */
    public void testRootCauseTypeNamesTheShardFailure() {
        SearchPhaseExecutionException allShardsFailed =
                new SearchPhaseExecutionException(
                        "query",
                        "all shards failed",
                        new ShardSearchFailure[] {new ShardSearchFailure(new IndexSearcher.TooManyClauses())});

        assertEquals("too_many_clauses", TransportActionHelper.rootCauseType(allShardsFailed));
    }

    /**
     * A shard failure from another node arrives wrapped for serialization; the wrapped exception's
     * type is the one reported.
     */
    public void testRootCauseTypeSeesThroughSerializationWrapper() {
        SearchPhaseExecutionException allShardsFailed =
                new SearchPhaseExecutionException(
                        "query",
                        "all shards failed",
                        new ShardSearchFailure[] {
                            new ShardSearchFailure(
                                    new NotSerializableExceptionWrapper(new IndexSearcher.TooManyClauses()))
                        });

        assertEquals("too_many_clauses", TransportActionHelper.rootCauseType(allShardsFailed));
    }

    /** A plain exception is named after its own class. */
    public void testRootCauseTypeOfPlainException() {
        assertEquals(
                "illegal_state_exception",
                TransportActionHelper.rootCauseType(new IllegalStateException("truncated")));
    }

    public void testClassifyExceptionReturnsNullForUnclassifiedException() {
        RestResponse classified =
                TransportActionHelper.classifyException(new RuntimeException("unexpected"));

        assertNull(classified);
    }
}
