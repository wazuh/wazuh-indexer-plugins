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
package com.wazuh.setup.index;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SetupStatusIndex}. Validates the setup status marker lifecycle: marker
 * invalidation at the beginning of initialization, completion signaling at the end, and resilience
 * to indexing failures.
 */
public class SetupStatusIndexTests extends OpenSearchTestCase {

    private SetupStatusIndex setupStatusIndex;
    private AutoCloseable mocks;

    @Mock private Client client;
    @Mock private ActionFuture<IndexResponse> indexFuture;
    @Mock private ClusterService clusterService;
    @Mock private ClusterState clusterState;
    @Mock private RoutingTable routingTable;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);

        this.setupStatusIndex =
                new SetupStatusIndex(SetupStatusIndex.INDEX_NAME, "templates/setup-status");
        this.setupStatusIndex.setClient(this.client);
        this.setupStatusIndex.setClusterService(this.clusterService);

        when(this.clusterService.state()).thenReturn(this.clusterState);
        when(this.clusterState.getRoutingTable()).thenReturn(this.routingTable);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** markComplete() persists the marker document with status=complete. */
    public void testMarkComplete_writesCompleteStatus() {
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.setupStatusIndex.markComplete();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals(SetupStatusIndex.SETUP_STATUS_ID, captured.id());
        assertTrue(
                "Payload must contain status=complete",
                captured
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_COMPLETE + "\""));
        assertTrue(
                "Payload must contain a timestamp",
                captured.source().utf8ToString().contains("\"timestamp\""));
    }

    /** markInitializing() with no marker index -> no stale marker to invalidate; no-op. */
    public void testMarkInitializing_indexMissing_isNoOp() {
        when(this.routingTable.hasIndex(SetupStatusIndex.INDEX_NAME)).thenReturn(false);

        this.setupStatusIndex.markInitializing();

        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** markInitializing() with an existing index -> overwrites the marker with status=initializing. */
    public void testMarkInitializing_indexExists_writesInitializingStatus() {
        when(this.routingTable.hasIndex(SetupStatusIndex.INDEX_NAME)).thenReturn(true);
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.setupStatusIndex.markInitializing();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals(SetupStatusIndex.SETUP_STATUS_ID, captured.id());
        assertTrue(
                "Payload must contain status=initializing",
                captured
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_INITIALIZING + "\""));
    }

    /** A failure while writing the marker is swallowed; node startup must not be affected. */
    public void testMarkComplete_exception_swallowed() {
        when(this.client.index(any(IndexRequest.class)))
                .thenThrow(new RuntimeException("Index unavailable"));

        this.setupStatusIndex.markComplete();
    }
}
