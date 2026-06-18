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
import org.opensearch.action.support.WriteRequest;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
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

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);

        this.setupStatusIndex =
                new SetupStatusIndex(SetupStatusIndex.INDEX_NAME, "templates/setup-status");
        this.setupStatusIndex.setClient(this.client);
        this.setupStatusIndex.setClusterService(this.clusterService);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** markReady() persists the marker document with status=ready. */
    public void testMarkReady_writesReadyStatus() {
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.setupStatusIndex.markReady();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals(SetupStatusIndex.SETUP_STATUS_ID, captured.id());
        assertTrue(
                "Payload must contain status=ready",
                captured
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_READY + "\""));
        assertTrue(
                "Payload must contain a timestamp",
                captured.source().utf8ToString().contains("\"timestamp\""));
        assertEquals(
                "The write must refresh the index immediately (periodic refresh is disabled)",
                WriteRequest.RefreshPolicy.IMMEDIATE,
                captured.getRefreshPolicy());
    }

    /** markRunning() always overwrites the marker with status=running. */
    public void testMarkRunning_writesRunningStatus() {
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.setupStatusIndex.markRunning();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals(SetupStatusIndex.SETUP_STATUS_ID, captured.id());
        assertTrue(
                "Payload must contain status=running",
                captured
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_RUNNING + "\""));
        assertEquals(
                "The write must refresh the index immediately (periodic refresh is disabled)",
                WriteRequest.RefreshPolicy.IMMEDIATE,
                captured.getRefreshPolicy());
    }

    /**
     * initialize() creates the template and index, then immediately marks the marker running —
     * verifying the fix for the race where a separate, earlier markRunning() call could silently
     * no-op if the cluster's routing table hadn't caught up yet after a restart.
     */
    public void testInitialize_createsIndexThenMarksRunning() {
        SetupStatusIndex spyIndex = spy(this.setupStatusIndex);
        doNothing().when(spyIndex).createTemplate(anyString());
        doNothing().when(spyIndex).createIndex(anyString());
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        spyIndex.initialize();

        verify(spyIndex).createTemplate("templates/setup-status");
        verify(spyIndex).createIndex(SetupStatusIndex.INDEX_NAME);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        assertTrue(
                "Payload must contain status=running",
                captor.getValue()
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_RUNNING + "\""));
    }

    /** A failure while writing the marker is swallowed; node startup must not be affected. */
    public void testMarkReady_exception_swallowed() {
        when(this.client.index(any(IndexRequest.class)))
                .thenThrow(new RuntimeException("Index unavailable"));

        this.setupStatusIndex.markReady();
    }

    /** markFailed() persists the marker document with status=failed. */
    public void testMarkFailed_writesFailedStatus() {
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.setupStatusIndex.markFailed();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals(SetupStatusIndex.SETUP_STATUS_ID, captured.id());
        assertTrue(
                "Payload must contain status=failed",
                captured
                        .source()
                        .utf8ToString()
                        .contains("\"status\":\"" + SetupStatusIndex.SETUP_STATUS_FAILED + "\""));
        assertEquals(
                "The write must refresh the index immediately (periodic refresh is disabled)",
                WriteRequest.RefreshPolicy.IMMEDIATE,
                captured.getRefreshPolicy());
    }

    /** A failure while writing the failed marker is swallowed too. */
    public void testMarkFailed_exception_swallowed() {
        when(this.client.index(any(IndexRequest.class)))
                .thenThrow(new RuntimeException("Index unavailable"));

        this.setupStatusIndex.markFailed();
    }
}
