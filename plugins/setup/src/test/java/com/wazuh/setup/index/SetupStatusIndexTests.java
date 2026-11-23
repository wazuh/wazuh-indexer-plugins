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

import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import java.util.Map;
import java.util.Optional;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.SchemaStatus;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
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
    @Mock private IndicesAdminClient indicesAdminClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);

        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(Settings.EMPTY).when(this.clusterService).getSettings();
        doReturn(this.indexFuture).when(this.indexFuture).actionGet(anyLong());

        this.setupStatusIndex =
                new SetupStatusIndex(SetupStatusIndex.INDEX_NAME, "templates/setup-status");
        this.setupStatusIndex.setClient(this.client);
        this.setupStatusIndex.setClusterService(this.clusterService);
    }

    /** Stubs the mapping update the index runs on itself at every initialization. */
    @SuppressWarnings("unchecked")
    private ActionFuture<AcknowledgedResponse> stubPutMapping() {
        ActionFuture<AcknowledgedResponse> future = mock(ActionFuture.class);
        doReturn(mock(AcknowledgedResponse.class)).when(future).actionGet(anyLong());
        doReturn(future).when(this.indicesAdminClient).putMapping(any(PutMappingRequest.class));
        return future;
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
     * initialize() creates the template and index, brings the index mapping up to the shipped one,
     * then immediately marks the marker running — verifying the fix for the race where a separate,
     * earlier markRunning() call could silently no-op if the cluster's routing table hadn't caught up
     * yet after a restart.
     */
    public void testInitialize_createsIndexThenMarksRunning() {
        SetupStatusIndex spyIndex = spy(this.setupStatusIndex);
        doNothing().when(spyIndex).createTemplate(anyString());
        doNothing().when(spyIndex).createIndex(anyString());
        this.stubPutMapping();
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        spyIndex.initialize();

        verify(spyIndex).createTemplate("templates/setup-status");
        verify(spyIndex).createIndex(SetupStatusIndex.INDEX_NAME);

        // The shipped mappings, record fields included, are pushed to the existing index.
        ArgumentCaptor<PutMappingRequest> mapping = ArgumentCaptor.forClass(PutMappingRequest.class);
        verify(this.indicesAdminClient).putMapping(mapping.capture());
        assertEquals(SetupStatusIndex.INDEX_NAME, mapping.getValue().indices()[0]);
        assertTrue(mapping.getValue().source().contains("\"" + IndexRecord.KEY_INSTALLED + "\""));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        assertTrue(
                "Payload must contain status=running",
                captor
                        .getValue()
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

    /** A failed mapping update is logged and initialization goes on to the marker. */
    public void testInitialize_mappingUpdateFailureDoesNotStopTheMarker() {
        SetupStatusIndex spyIndex = spy(this.setupStatusIndex);
        doNothing().when(spyIndex).createTemplate(anyString());
        doNothing().when(spyIndex).createIndex(anyString());
        when(this.indicesAdminClient.putMapping(any(PutMappingRequest.class)))
                .thenThrow(new RuntimeException("mapping update rejected"));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        spyIndex.initialize();

        verify(this.client).index(any(IndexRequest.class));
    }

    /** putIndexRecord() stores the record under the index name and refreshes at once. */
    public void testPutIndexRecord_writesTheRecord() {
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);
        IndexRecord record =
                IndexRecord.of("wazuh-states-sca", 50200, 50300, 50200, "mappings_updated");

        this.setupStatusIndex.putIndexRecord(record);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        IndexRequest captured = captor.getValue();
        assertEquals(SetupStatusIndex.INDEX_NAME, captured.index());
        assertEquals("wazuh-states-sca", captured.id());
        String payload = captured.source().utf8ToString();
        assertTrue(payload, payload.contains("\"status\":\"upgrade_in_place\""));
        assertTrue(payload, payload.contains("\"installed\":50200"));
        assertTrue(payload, payload.contains("\"step\":\"mappings_updated\""));
        assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, captured.getRefreshPolicy());
    }

    /** A failure while writing a record propagates: the records drive the upgrades. */
    public void testPutIndexRecord_failurePropagates() {
        when(this.client.index(any(IndexRequest.class)))
                .thenThrow(new RuntimeException("Index unavailable"));

        expectThrows(
                RuntimeException.class,
                () ->
                        this.setupStatusIndex.putIndexRecord(
                                IndexRecord.of("wazuh-states-sca", 50300, 50300, 50200, null)));
    }

    /** getIndexRecord() reads the record back, and is empty when there is none. */
    @SuppressWarnings("unchecked")
    public void testGetIndexRecord_readsTheRecord() {
        GetResponse response = mock(GetResponse.class);
        ActionFuture<GetResponse> future = mock(ActionFuture.class);
        doReturn(response).when(future).actionGet(anyLong());
        when(this.client.get(any(GetRequest.class))).thenReturn(future);
        when(response.isExists()).thenReturn(true);
        when(response.getSourceAsMap())
                .thenReturn(
                        Map.of(
                                IndexRecord.KEY_INDEX, "wazuh-states-sca",
                                IndexRecord.KEY_INSTALLED, 50200,
                                IndexRecord.KEY_SHIPPED, 50300,
                                IndexRecord.KEY_COMPAT, 50200,
                                IndexRecord.KEY_STATUS, "upgrade_in_place",
                                IndexRecord.KEY_STEP, "mappings_updated",
                                IndexRecord.KEY_UPDATED_AT, "2026-11-17T10:00:00Z"));

        Optional<IndexRecord> record = this.setupStatusIndex.getIndexRecord("wazuh-states-sca");

        assertTrue(record.isPresent());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, record.get().status());
        assertEquals("mappings_updated", record.get().step());
        ArgumentCaptor<GetRequest> captor = ArgumentCaptor.forClass(GetRequest.class);
        verify(this.client).get(captor.capture());
        assertEquals(SetupStatusIndex.INDEX_NAME, captor.getValue().index());
        assertEquals("wazuh-states-sca", captor.getValue().id());

        when(response.isExists()).thenReturn(false);
        assertFalse(this.setupStatusIndex.getIndexRecord("wazuh-states-sca").isPresent());
    }
}
