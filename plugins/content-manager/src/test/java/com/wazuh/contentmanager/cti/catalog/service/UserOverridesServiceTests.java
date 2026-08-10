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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link UserOverridesService}. */
public class UserOverridesServiceTests extends OpenSearchTestCase {

    private Client client;
    private SpaceService spaceService;
    private UserOverridesService service;

    @Before
    public void setUpService() {
        this.client = mock(Client.class);
        this.spaceService = mock(SpaceService.class);
        this.service = new UserOverridesService(this.client, this.spaceService);
    }

    /** Stubs the registry GET as absent. */
    private void stubRegistryMissing() {
        GetResponse missing = mock(GetResponse.class);
        when(missing.isExists()).thenReturn(false);
        stubGet(missing);
    }

    /** Stubs the registry GET as present, with the given source and concurrency metadata. */
    private void stubRegistryPresent(String source, long seqNo, long primaryTerm) {
        GetResponse present = mock(GetResponse.class);
        when(present.isExists()).thenReturn(true);
        when(present.getSourceAsString()).thenReturn(source);
        when(present.getSeqNo()).thenReturn(seqNo);
        when(present.getPrimaryTerm()).thenReturn(primaryTerm);
        stubGet(present);
    }

    private void stubGet(GetResponse response) {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<GetResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .get(any(GetRequest.class), any());
    }

    /** Stubs a successful index call, capturing the request. */
    private void stubIndexSucceeding(ArgumentCaptor<IndexRequest> captor) {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndexResponse>>getArgument(1)
                                    .onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(this.client)
                .index(captor.capture(), any());
    }

    /** A mutator that pins {@code enabled} and leaves the filters alone. */
    private static UserOverrides pinEnabled(UserOverrides current) {
        return new UserOverrides(
                new UserOverrides.PolicySettings(Boolean.FALSE, null, null, null), current.getFilters());
    }

    /** A cluster that has never stored an override reads as empty, not as an error. */
    public void testReadReturnsEmptyWhenTheRegistryDoesNotExist() {
        stubRegistryMissing();

        PlainActionFuture<UserOverrides> future = PlainActionFuture.newFuture();
        this.service.read("standard", future);

        UserOverrides overrides = future.actionGet();
        assertNull(overrides.getPolicy());
        assertTrue(overrides.getFilters().isEmpty());
    }

    /** Reading returns only the requested space's overrides. */
    public void testReadReturnsOnlyTheRequestedSpace() {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false}},"
                        + "\"draft\":{\"policy\":{\"enabled\":true}}}}",
                4L,
                1L);

        PlainActionFuture<UserOverrides> future = PlainActionFuture.newFuture();
        this.service.read("standard", future);

        assertEquals(Boolean.FALSE, future.actionGet().getPolicy().getEnabled());
    }

    /**
     * The written document must not carry a {@code space} field, and must land on the reserved id.
     * The pre-snapshot wipe selects by {@code space.name}, so adding one would make the registry
     * delete itself on the next sync.
     */
    public void testUpdateWritesADocumentWithoutASpaceField() {
        stubRegistryMissing();
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);
        future.actionGet();

        String written = captor.getValue().source().utf8ToString();
        assertFalse("the registry must not carry a space field", written.contains("\"space\""));
        assertTrue(written.contains("\"user_overrides\""));
        assertEquals(Constants.USER_OVERRIDES_DOC_ID, captor.getValue().id());
        assertEquals(Constants.INDEX_POLICIES, captor.getValue().index());
    }

    /**
     * The first write uses {@code opType=CREATE}, so two callers racing to create the registry cannot
     * both succeed with one silently overwriting the other.
     */
    public void testFirstWriteUsesCreateOpType() {
        stubRegistryMissing();
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);
        future.actionGet();

        assertEquals(DocWriteRequest.OpType.CREATE, captor.getValue().opType());
    }

    /**
     * A write against an existing registry carries the sequence number and primary term read from the
     * GET, so a concurrent writer's change cannot be lost.
     */
    public void testUpdateOfAnExistingRegistryUsesOptimisticConcurrency() {
        stubRegistryPresent("{\"user_overrides\":{}}", 7L, 3L);
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);
        future.actionGet();

        assertEquals(7L, captor.getValue().ifSeqNo());
        assertEquals(3L, captor.getValue().ifPrimaryTerm());
    }

    /**
     * A version conflict re-reads and retries, rather than dropping the user's change. This is what
     * replaces a mutex: the read-modify-write is repeated against the winner's document.
     */
    public void testUpdateRetriesOnVersionConflict() {
        stubRegistryPresent("{\"user_overrides\":{}}", 7L, 3L);

        AtomicInteger attempts = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            if (attempts.incrementAndGet() == 1) {
                                listener.onFailure(
                                        new VersionConflictEngineException(
                                                new ShardId(Constants.INDEX_POLICIES, "_na_", 0), "conflict", "reason"));
                            } else {
                                listener.onResponse(mock(IndexResponse.class));
                            }
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);
        future.actionGet();

        assertEquals("the write must be retried once", 2, attempts.get());
        // The retry must re-read, not reuse the stale document.
        verify(this.client, times(2)).get(any(GetRequest.class), any());
    }

    /** Retries are bounded: a permanently conflicting document fails instead of looping forever. */
    public void testUpdateGivesUpAfterTheRetryLimit() {
        stubRegistryPresent("{\"user_overrides\":{}}", 7L, 3L);

        AtomicInteger attempts = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            attempts.incrementAndGet();
                            invocation
                                    .<ActionListener<IndexResponse>>getArgument(1)
                                    .onFailure(
                                            new VersionConflictEngineException(
                                                    new ShardId(Constants.INDEX_POLICIES, "_na_", 0), "conflict", "reason"));
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);

        expectThrows(VersionConflictEngineException.class, future::actionGet);
        assertEquals(Constants.MAX_USER_OVERRIDES_UPDATE_ATTEMPTS, attempts.get());
    }

    /**
     * Updating one space must leave the others untouched. The registry is a single shared document,
     * so a write that rebuilt it from scratch would silently discard the other spaces.
     */
    public void testUpdateLeavesOtherSpacesUntouched() {
        stubRegistryPresent(
                "{\"user_overrides\":{\"draft\":{\"policy\":{\"enabled\":true},"
                        + "\"filters\":[{\"id\":\"d1\",\"document\":\"{}\"}]}}}",
                2L,
                1L);
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update("standard", UserOverridesServiceTests::pinEnabled, future);
        future.actionGet();

        String written = captor.getValue().source().utf8ToString();
        assertTrue("the draft space must survive", written.contains("\"draft\""));
        assertTrue("its stored filter must survive", written.contains("\"d1\""));
        assertTrue(written.contains("\"standard\""));
    }

    /** The mutator receives the overrides currently stored, not an empty instance. */
    public void testMutatorSeesTheStoredOverrides() {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"filters\":"
                        + "[{\"id\":\"existing\",\"document\":\"{}\"}]}}}",
                5L,
                1L);
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        List<String> seen = new ArrayList<>();
        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.update(
                "standard",
                current -> {
                    current.getFilters().forEach(filter -> seen.add(filter.getId()));
                    return new UserOverrides(
                            new UserOverrides.PolicySettings(
                                    null, null, null, new UserOverrides.EnrichmentDelta(Set.of("geo"), Set.of())),
                            current.getFilters());
                },
                future);
        future.actionGet();

        assertEquals(List.of("existing"), seen);
        assertTrue(captor.getValue().source().utf8ToString().contains("\"existing\""));
    }

    // --- Filter mutators ---------------------------------------------------------------------

    /** Storing a filter adds it, keeping the policy settings the user had already saved. */
    public void testStoreFilterAddsItAndKeepsThePolicySettings() {
        UserOverrides current =
                new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.FALSE, null, null, null), new ArrayList<>());

        UserOverrides result =
                UserOverridesService.storeFilter("f1", "{\"document\":{\"name\":\"filter/a/0\"}}")
                        .apply(current);

        assertEquals(1, result.getFilters().size());
        assertEquals("f1", result.getFilters().get(0).getId());
        assertTrue(result.getFilters().get(0).getDocument().contains("filter/a/0"));
        assertEquals(
                "storing a filter must not drop the policy settings",
                Boolean.FALSE,
                result.getPolicy().getEnabled());
    }

    /** Storing the same id twice refreshes the copy instead of duplicating the entry. */
    public void testStoreFilterRefreshesAnExistingEntry() {
        UserOverrides current =
                new UserOverrides(
                        null, new ArrayList<>(List.of(new UserOverrides.StoredFilter("f1", "{\"old\":true}"))));

        UserOverrides result = UserOverridesService.storeFilter("f1", "{\"new\":true}").apply(current);

        assertEquals(1, result.getFilters().size());
        assertEquals("{\"new\":true}", result.getFilters().get(0).getDocument());
    }

    /** Storing one filter leaves the others alone. */
    public void testStoreFilterKeepsTheOtherFilters() {
        UserOverrides current =
                new UserOverrides(
                        null, new ArrayList<>(List.of(new UserOverrides.StoredFilter("f1", "{}"))));

        UserOverrides result = UserOverridesService.storeFilter("f2", "{}").apply(current);

        assertEquals(2, result.getFilters().size());
    }

    /** Removing a filter prunes only that one, and keeps the policy settings. */
    public void testRemoveFilterPrunesOnlyTheMatchingEntry() {
        UserOverrides current =
                new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.TRUE, null, null, null),
                        new ArrayList<>(
                                List.of(
                                        new UserOverrides.StoredFilter("f1", "{}"),
                                        new UserOverrides.StoredFilter("f2", "{}"))));

        UserOverrides result = UserOverridesService.removeFilter("f1").apply(current);

        assertEquals(1, result.getFilters().size());
        assertEquals("f2", result.getFilters().get(0).getId());
        assertEquals(Boolean.TRUE, result.getPolicy().getEnabled());
    }

    /** Removing a filter that was never stored is a no-op, not an error. */
    public void testRemoveFilterOfAnUnknownIdIsANoOp() {
        UserOverrides current =
                new UserOverrides(
                        null, new ArrayList<>(List.of(new UserOverrides.StoredFilter("f1", "{}"))));

        UserOverrides result = UserOverridesService.removeFilter("nope").apply(current);

        assertEquals(1, result.getFilters().size());
    }

    /** The mutators must not modify the instance they are given. */
    public void testFilterMutatorsDoNotMutateTheirInput() {
        List<UserOverrides.StoredFilter> original =
                new ArrayList<>(List.of(new UserOverrides.StoredFilter("f1", "{}")));
        UserOverrides current = new UserOverrides(null, original);

        UserOverridesService.storeFilter("f2", "{}").apply(current);
        UserOverridesService.removeFilter("f1").apply(current);

        assertEquals("the input list must be untouched", 1, original.size());
        assertEquals("f1", original.get(0).getId());
    }

    // --- apply -------------------------------------------------------------------------------

    /** Stubs the rebuilt policy that {@code apply} merges into, and its real document id. */
    private void stubRebuiltPolicy(String source) throws Exception {
        Map<String, Object> policyMap =
                new ObjectMapper().readValue(source, new TypeReference<Map<String, Object>>() {});
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Map<String, Object>>>getArgument(1).onResponse(policyMap);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any());
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<String>>getArgument(3).onResponse("real-policy-id");
                            return null;
                        })
                .when(this.spaceService)
                .findDocumentIdAsync(any(), any(), any(), any());
    }

    private void stubBulkSucceeding(ArgumentCaptor<BulkRequest> captor) {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<BulkResponse>>getArgument(1)
                                    .onResponse(mock(BulkResponse.class));
                            return null;
                        })
                .when(this.client)
                .bulk(captor.capture(), any());
    }

    /** Runs apply against the stubs and returns the policy document that was written back. */
    private String applyAndCaptureWrittenPolicy() {
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.apply("standard", future);
        future.actionGet();

        return captor.getValue().source().utf8ToString();
    }

    /** An empty registry means nothing to do: no writes at all. */
    public void testApplyDoesNothingWhenTheRegistryIsEmpty() {
        stubRegistryMissing();

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.apply("standard", future);
        future.actionGet();

        verify(this.client, never()).index(any(IndexRequest.class), any());
        verify(this.client, never()).bulk(any(BulkRequest.class), any());
        verify(this.spaceService, never()).getPolicy(any(), any());
    }

    /**
     * The user's booleans are written over CTI's, and the enrichment delta is resolved against the
     * list CTI just published rather than against a stored copy.
     */
    public void testApplyOverwritesTheSettingsAndResolvesTheEnrichmentDelta() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false,"
                        + "\"enrichments\":{\"removed\":[\"geo\"],\"added\":[]}},\"filters\":[]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enabled\":true,\"index_unclassified_events\":true,"
                        + "\"enrichments\":[\"geo\",\"connection\",\"asn\"],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"stale\"},\"space\":{\"name\":\"standard\"},\"offset\":640}");

        String written = applyAndCaptureWrittenPolicy();

        assertTrue("the user's choice must win", written.contains("\"enabled\":false"));
        assertFalse("the removed enrichment must be gone", written.contains("\"geo\""));
        assertTrue("CTI's other enrichments must stay", written.contains("\"connection\""));
        assertTrue("an enrichment CTI added later must come through", written.contains("\"asn\""));
    }

    /** A setting the user never decided is left exactly as CTI published it. */
    public void testApplyLeavesUndecidedSettingsAsCtiPublishedThem() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false},\"filters\":[]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enabled\":true,\"index_unclassified_events\":true,"
                        + "\"index_discarded_events\":true,\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"}}");

        String written = applyAndCaptureWrittenPolicy();

        assertTrue(written.contains("\"enabled\":false"));
        assertTrue(
                "index_unclassified_events was never decided by the user",
                written.contains("\"index_unclassified_events\":true"));
        assertTrue(
                "index_discarded_events was never decided by the user",
                written.contains("\"index_discarded_events\":true"));
    }

    /** The policy write carries a freshly computed hash, not the one the rebuild left. */
    public void testApplyRecomputesThePolicyHash() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false},\"filters\":[]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enabled\":true,\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"stale\"},\"space\":{\"name\":\"standard\"}}");

        String written = applyAndCaptureWrittenPolicy();

        assertFalse("the stale hash must not survive", written.contains("stale"));
        assertTrue(written.contains("\"sha256\""));
    }

    /** A stored filter is recreated under its original id, and its id attached to the policy. */
    public void testApplyRestoresAStoredFilterAndAttachesItsId() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"filters\":"
                        + "[{\"id\":\"f1\",\"document\":\"{\\\"document\\\":{\\\"name\\\":\\\"filter/a/0\\\"}}\"}]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"}}");
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        stubBulkSucceeding(bulkCaptor);

        String written = applyAndCaptureWrittenPolicy();

        assertEquals("one filter must be recreated", 1, bulkCaptor.getValue().numberOfActions());
        assertEquals("f1", bulkCaptor.getValue().requests().get(0).id());
        assertEquals(Constants.INDEX_FILTERS, bulkCaptor.getValue().requests().get(0).index());
        assertTrue("the policy must reference the restored filter", written.contains("\"f1\""));
    }

    /** Applying twice must not duplicate a filter id in the policy's array. */
    public void testApplyIsIdempotentForTheFilterArray() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"filters\":"
                        + "[{\"id\":\"f1\",\"document\":\"{\\\"document\\\":{}}\"}]}}}",
                1L,
                1L);
        // The policy already lists f1, as it would after a previous apply.
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enrichments\":[],\"filters\":[\"f1\"]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"}}");
        stubBulkSucceeding(ArgumentCaptor.forClass(BulkRequest.class));

        String written = applyAndCaptureWrittenPolicy();

        assertEquals("f1 must appear exactly once", 1, written.split("\"f1\"", -1).length - 1);
    }

    /** An unparseable stored filter is skipped, and the rest are still restored. */
    public void testApplySkipsAnUnparseableStoredFilter() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"filters\":"
                        + "[{\"id\":\"bad\",\"document\":\"not json\"},"
                        + "{\"id\":\"good\",\"document\":\"{\\\"document\\\":{}}\"}]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"}}");
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        stubBulkSucceeding(bulkCaptor);

        String written = applyAndCaptureWrittenPolicy();

        assertEquals("only the parseable one is restored", 1, bulkCaptor.getValue().numberOfActions());
        assertEquals("good", bulkCaptor.getValue().requests().get(0).id());
        assertTrue(written.contains("\"good\""));
        assertFalse(written.contains("\"bad\""));
    }

    /**
     * A missing policy is not an error. The registry is durable, so the next sync applies the
     * overrides; failing here would abort a sync for something that self-heals.
     */
    public void testApplyDoesNothingWhenThePolicyIsMissing() {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false},\"filters\":[]}}}",
                1L,
                1L);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Map<String, Object>>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any());

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.apply("standard", future);
        future.actionGet();

        verify(this.client, never()).index(any(IndexRequest.class), any());
    }

    /** The restored policy is written under the real document id, not the logical one. */
    public void testApplyWritesUnderTheRealDocumentId() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false},\"filters\":[]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"}}");

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        stubIndexSucceeding(captor);

        PlainActionFuture<Void> future = PlainActionFuture.newFuture();
        this.service.apply("standard", future);
        future.actionGet();

        assertEquals("real-policy-id", captor.getValue().id());
        assertEquals(Constants.INDEX_POLICIES, captor.getValue().index());
    }

    /** The space and offset the rebuild wrote must survive the merge untouched. */
    public void testApplyPreservesTheSpaceAndOffset() throws Exception {
        stubRegistryPresent(
                "{\"user_overrides\":{\"standard\":{\"policy\":{\"enabled\":false},\"filters\":[]}}}",
                1L,
                1L);
        stubRebuiltPolicy(
                "{\"document\":{\"id\":\"p1\",\"enrichments\":[],\"filters\":[]},"
                        + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"standard\"},\"offset\":640}");

        String written = applyAndCaptureWrittenPolicy();

        assertTrue(written.contains("\"space\""));
        assertTrue(written.contains("\"standard\""));
        assertTrue(written.contains("640"));
    }
}
