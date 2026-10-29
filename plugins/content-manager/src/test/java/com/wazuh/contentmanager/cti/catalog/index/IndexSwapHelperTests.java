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
package com.wazuh.contentmanager.cti.catalog.index;

import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequestBuilder;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.admin.indices.refresh.RefreshRequestBuilder;
import org.opensearch.action.admin.indices.refresh.RefreshResponse;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IndexSwapHelper}. Validates shadow name resolution, covering both the
 * normal case (alias → -a → shadow is -b and vice versa) and error cases (unrecognized suffix,
 * multiple concrete indices).
 */
public class IndexSwapHelperTests extends OpenSearchTestCase {

    private Client client;
    private AutoCloseable closeable;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        PluginSettings.getInstance(Settings.EMPTY);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** When the alias points to suffix -a, the shadow name should be suffix -b. */
    public void testResolveShadowName_AToB() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_A;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String shadow = IndexSwapHelper.resolveShadowName(this.client, alias);
        assertEquals(alias + ContentIndex.SUFFIX_B, shadow);
    }

    /** When the alias points to suffix -b, the shadow name should be suffix -a. */
    public void testResolveShadowName_BToA() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_B;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String shadow = IndexSwapHelper.resolveShadowName(this.client, alias);
        assertEquals(alias + ContentIndex.SUFFIX_A, shadow);
    }

    /** When the alias resolves to multiple indices, an IllegalStateException must be thrown. */
    public void testResolveShadowName_MultipleIndices() {
        String alias = "wazuh-threatintel-rules";

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices())
                .thenReturn(new String[] {alias + ContentIndex.SUFFIX_A, alias + ContentIndex.SUFFIX_B});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        expectThrows(
                IllegalStateException.class, () -> IndexSwapHelper.resolveShadowName(this.client, alias));
    }

    /** When the physical index does not end with -a or -b, an IllegalStateException is thrown. */
    public void testResolveShadowName_UnrecognizedSuffix() {
        String alias = "wazuh-threatintel-rules";

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {alias});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        expectThrows(
                IllegalStateException.class, () -> IndexSwapHelper.resolveShadowName(this.client, alias));
    }

    /** resolveLivePhysicalName should return the concrete index the alias points to. */
    public void testResolveLivePhysicalName() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_A;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String result = IndexSwapHelper.resolveLivePhysicalName(this.client, alias);
        assertEquals(livePhysical, result);
    }

    /**
     * A leftover in the staging slot, which the alias does not point at, is deleted before the shadow
     * index is created; otherwise the creation fails with resource_already_exists.
     */
    @SuppressWarnings("unchecked")
    public void testCreateShadowIndices_DeletesLeftoverInStagingSlot() throws Exception {
        String alias = "wazuh-threatintel-rules";
        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {alias + ContentIndex.SUFFIX_B});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);
        when(this.client
                        .admin()
                        .indices()
                        .prepareExists(alias + ContentIndex.SUFFIX_A)
                        .get()
                        .isExists())
                .thenReturn(true);
        when(this.client.admin().indices().prepareDelete(anyString()))
                .thenReturn(mock(DeleteIndexRequestBuilder.class));
        CreateIndexResponse created =
                new CreateIndexResponse(true, true, alias + ContentIndex.SUFFIX_A);
        ActionFuture<CreateIndexResponse> future = mock(ActionFuture.class);
        when(future.get(anyLong(), any(TimeUnit.class))).thenReturn(created);
        when(this.client.admin().indices().create(any(CreateIndexRequest.class))).thenReturn(future);

        Map<String, ContentIndex> shadows =
                IndexSwapHelper.createShadowIndices(
                        this.client, Map.of("rule", "/mappings/cti-rules-mappings.json"), t -> alias);

        verify(this.client.admin().indices()).prepareDelete(alias + ContentIndex.SUFFIX_A);
        assertEquals(alias + ContentIndex.SUFFIX_A, shadows.get("rule").getPhysicalName());
    }

    /** shadowIndexExists checks the slot the alias does not point at. */
    public void testShadowIndexExists_ChecksTheOtherSlot() {
        String alias = "wazuh-threatintel-rules";
        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {alias + ContentIndex.SUFFIX_B});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);
        when(this.client
                        .admin()
                        .indices()
                        .prepareExists(alias + ContentIndex.SUFFIX_A)
                        .get()
                        .isExists())
                .thenReturn(true);

        assertTrue(IndexSwapHelper.shadowIndexExists(this.client, alias));
    }

    /** refreshIndices refreshes every given index in one request. */
    public void testRefreshIndices_RefreshesEveryIndex() throws Exception {
        RefreshRequestBuilder request = mock(RefreshRequestBuilder.class);
        RefreshResponse response = mock(RefreshResponse.class);
        when(response.getFailedShards()).thenReturn(0);
        when(request.get(any(TimeValue.class))).thenReturn(response);
        when(this.client.admin().indices().prepareRefresh("rules-b", "iocs-b")).thenReturn(request);

        IndexSwapHelper.refreshIndices(this.client, List.of("rules-b", "iocs-b"), 30);

        verify(request).get(TimeValue.timeValueSeconds(30));
    }

    /** A shard that fails to refresh fails the call, so its index is not switched to. */
    public void testRefreshIndices_FailedShardThrows() {
        RefreshResponse response = mock(RefreshResponse.class);
        when(response.getFailedShards()).thenReturn(1);
        when(this.client.admin().indices().prepareRefresh("rules-b").get(any(TimeValue.class)))
                .thenReturn(response);

        expectThrows(
                IllegalStateException.class,
                () -> IndexSwapHelper.refreshIndices(this.client, List.of("rules-b"), 30));
    }

    /**
     * Stubs the reindex of user content to answer with the given counts of failures.
     *
     * @return the future the reindex waits on.
     */
    @SuppressWarnings("unchecked")
    private ActionFuture<BulkByScrollResponse> stubReindex(
            List<BulkItemResponse.Failure> bulkFailures,
            List<ScrollableHitSource.SearchFailure> searchFailures,
            boolean timedOut) {
        BulkByScrollResponse response = mock(BulkByScrollResponse.class);
        when(response.getBulkFailures()).thenReturn(bulkFailures);
        when(response.getSearchFailures()).thenReturn(searchFailures);
        when(response.isTimedOut()).thenReturn(timedOut);
        ActionFuture<BulkByScrollResponse> future = mock(ActionFuture.class);
        when(future.actionGet(any(TimeValue.class))).thenReturn(response);
        when(this.client.execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class)))
                .thenReturn(future);
        return future;
    }

    /** A clean reindex copies every live index into its staging index, within the timeout. */
    public void testReindexUserContent_CopiesEveryIndex() {
        ActionFuture<BulkByScrollResponse> future = this.stubReindex(List.of(), List.of(), false);

        IndexSwapHelper.reindexUserContent(
                this.client, Map.of("rules-a", "rules-b", "decoders-a", "decoders-b"), 30);

        verify(future, times(2)).actionGet(TimeValue.timeValueSeconds(30));
    }

    /**
     * A user document the staging mapping rejects fails the call, so the swap rolls back instead of
     * deleting the live index that still holds the document.
     */
    public void testReindexUserContent_BulkFailureThrows() {
        this.stubReindex(
                List.of(
                        new BulkItemResponse.Failure(
                                "filters-b",
                                "user-filter",
                                new IllegalArgumentException("strict_dynamic_mapping_exception"))),
                List.of(),
                false);

        IllegalStateException e =
                expectThrows(
                        IllegalStateException.class,
                        () ->
                                IndexSwapHelper.reindexUserContent(
                                        this.client, Map.of("filters-a", "filters-b"), 30));
        assertTrue(e.getMessage(), e.getMessage().contains("user-filter"));
    }

    /** A live index that cannot be read in full fails the call. */
    public void testReindexUserContent_SearchFailureThrows() {
        this.stubReindex(
                List.of(),
                List.of(new ScrollableHitSource.SearchFailure(new IllegalStateException("shard failed"))),
                false);

        expectThrows(
                IllegalStateException.class,
                () -> IndexSwapHelper.reindexUserContent(this.client, Map.of("rules-a", "rules-b"), 30));
    }

    /** A reindex that timed out may have copied only part of the documents: it fails the call. */
    public void testReindexUserContent_TimeoutThrows() {
        this.stubReindex(List.of(), List.of(), true);

        expectThrows(
                IllegalStateException.class,
                () -> IndexSwapHelper.reindexUserContent(this.client, Map.of("rules-a", "rules-b"), 30));
    }

    /**
     * A reindex that does not answer within the timeout fails the call naming the indices and the
     * deadline: the wait ends there, but the reindex is still running on the node, so a bare "Timeout
     * waiting for task." would leave nothing to act on.
     */
    @SuppressWarnings("unchecked")
    public void testReindexUserContent_ClientTimeoutThrows() {
        ActionFuture<BulkByScrollResponse> future = mock(ActionFuture.class);
        when(future.actionGet(any(TimeValue.class)))
                .thenThrow(new OpenSearchTimeoutException("Timeout waiting for task."));
        when(this.client.execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class)))
                .thenReturn(future);

        IllegalStateException e =
                expectThrows(
                        IllegalStateException.class,
                        () ->
                                IndexSwapHelper.reindexUserContent(
                                        this.client, Map.of("filters-a", "filters-b"), 30));
        assertTrue(e.getMessage(), e.getMessage().contains("filters-a"));
        assertTrue(e.getMessage(), e.getMessage().contains("filters-b"));
        assertTrue(e.getMessage(), e.getMessage().contains("30"));
    }

    /**
     * Every failing document is named, not only the first: otherwise a copy that several documents
     * block takes one swap per document to clear.
     */
    public void testReindexUserContent_NamesEveryFailingDocument() {
        this.stubReindex(
                List.of(
                        new BulkItemResponse.Failure(
                                "filters-b", "first-filter", new IllegalArgumentException("rejected")),
                        new BulkItemResponse.Failure(
                                "filters-b", "second-filter", new IllegalArgumentException("rejected"))),
                List.of(),
                false);

        IllegalStateException e =
                expectThrows(
                        IllegalStateException.class,
                        () ->
                                IndexSwapHelper.reindexUserContent(
                                        this.client, Map.of("filters-a", "filters-b"), 30));
        assertTrue(e.getMessage(), e.getMessage().contains("first-filter"));
        assertTrue(e.getMessage(), e.getMessage().contains("second-filter"));
    }
}
