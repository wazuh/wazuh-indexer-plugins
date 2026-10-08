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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.get.GetResult;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.lang.reflect.Field;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link PolicyLinks}. */
public class PolicyLinksTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_DOC_ID = "draft-policy-doc";
    private static final String MISSING_POLICY = Constants.E_500_MISSING_DRAFT_POLICY;

    private Client client;

    /** Policy versions served by successive GETs. */
    private Deque<GetResponse> gets;

    /** Outcomes of successive index calls: {@code null} succeeds, anything else fails with it. */
    private Deque<Exception> writeOutcomes;

    private List<String> searchedSpaces;
    private List<IndexRequest> writes;

    /** Delays of the retries scheduled on the thread pool, which runs them inline. */
    private List<TimeValue> retryDelays;

    @Before
    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.gets = new ArrayDeque<>();
        this.writeOutcomes = new ArrayDeque<>();
        this.searchedSpaces = new ArrayList<>();
        this.writes = new ArrayList<>();
        this.retryDelays = new ArrayList<>();
        this.stubSearch(true);

        ThreadPool threadPool = mock(ThreadPool.class);
        doAnswer(
                        invocation -> {
                            this.retryDelays.add(invocation.getArgument(1));
                            invocation.<Runnable>getArgument(0).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        when(this.client.threadPool()).thenReturn(threadPool);

        doAnswer(
                        invocation -> {
                            GetRequest request = invocation.getArgument(0);
                            assertEquals(POLICY_DOC_ID, request.id());
                            invocation.<ActionListener<GetResponse>>getArgument(1).onResponse(this.gets.pop());
                            return null;
                        })
                .when(this.client)
                .get(any(GetRequest.class), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            this.writes.add(invocation.getArgument(0));
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            Exception outcome = this.writeOutcomes.isEmpty() ? null : this.writeOutcomes.pop();
                            if (outcome == null) {
                                l.onResponse(mock(IndexResponse.class));
                            } else {
                                l.onFailure(outcome);
                            }
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any(ActionListener.class));
    }

    @After
    @Override
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @SuppressWarnings("unchecked")
    private void stubSearch(boolean policyExists) {
        doAnswer(
                        invocation -> {
                            SearchRequest request = invocation.getArgument(0);
                            assertEquals(Constants.INDEX_POLICIES, request.indices()[0]);
                            JsonNode query = MAPPER.readTree(request.source().query().toString());
                            this.searchedSpaces.add(
                                    query.path("term").path(Constants.Q_SPACE_NAME).path("value").asText());
                            SearchHit[] hits =
                                    policyExists
                                            ? new SearchHit[] {
                                                new SearchHit(
                                                        0, POLICY_DOC_ID, Collections.emptyMap(), Collections.emptyMap())
                                            }
                                            : new SearchHit[0];
                            SearchResponse response = mock(SearchResponse.class);
                            when(response.getHits())
                                    .thenReturn(
                                            new SearchHits(
                                                    hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 0.0f));
                            invocation.<ActionListener<SearchResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));
    }

    /** Queues a policy version with the given filters and no integrations for the next GET. */
    private void servePolicy(long seqNo, String... filters) {
        this.servePolicy(seqNo, List.of(filters), List.of());
    }

    /** Queues a policy version for the next GET; a {@code null} list leaves that key out. */
    private void servePolicy(long seqNo, List<String> filters, List<String> integrations) {
        ObjectNode document = MAPPER.createObjectNode().put("id", "p");
        if (filters != null) {
            document.set(Constants.KEY_FILTERS, MAPPER.valueToTree(filters));
        }
        if (integrations != null) {
            document.set(Constants.KEY_INTEGRATIONS, MAPPER.valueToTree(integrations));
        }
        String source =
                "{\"document\":"
                        + document
                        + ",\"hash\":{\"sha256\":\"old\"},\"space\":{\"name\":\"draft\"}}";
        this.gets.add(
                new GetResponse(
                        new GetResult(
                                Constants.INDEX_POLICIES,
                                POLICY_DOC_ID,
                                seqNo,
                                1L,
                                seqNo + 1,
                                true,
                                new BytesArray(source),
                                Collections.emptyMap(),
                                Collections.emptyMap())));
    }

    private static VersionConflictEngineException conflict() {
        return new VersionConflictEngineException(
                new ShardId(Constants.INDEX_POLICIES, "_na_", 0), POLICY_DOC_ID, "conflict");
    }

    private static List<String> writtenFilters(IndexRequest request) throws Exception {
        return writtenList(request, Constants.KEY_FILTERS);
    }

    private static List<String> writtenList(IndexRequest request, String listKey) throws Exception {
        List<String> ids = new ArrayList<>();
        MAPPER
                .readTree(request.source().utf8ToString())
                .path(Constants.KEY_DOCUMENT)
                .path(listKey)
                .forEach(n -> ids.add(n.asText()));
        return ids;
    }

    /** Links or unlinks a filter. */
    private Exception run(boolean link, String space, String filterId) {
        return this.run(link, space, Constants.KEY_FILTERS, filterId);
    }

    private Exception run(boolean link, String space, String listKey, String id) {
        AtomicReference<Exception> failure = new AtomicReference<>();
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        ActionListener<Void> listener = ActionListener.wrap(v -> done.set(true), e -> failure.set(e));
        if (link) {
            PolicyLinks.link(this.client, space, listKey, id, MISSING_POLICY, listener);
        } else {
            PolicyLinks.unlink(this.client, space, listKey, id, MISSING_POLICY, listener);
        }
        assertTrue("listener must be notified", done.get() || failure.get() != null);
        return failure.get();
    }

    /** Link targets the given space's policy and writes with the sequence number it read. */
    public void testLink_appendsAndWritesGuardedBySeqNo() throws Exception {
        this.servePolicy(7, "a");

        assertNull(this.run(true, "draft", "b"));

        assertEquals(List.of("draft"), this.searchedSpaces);
        assertEquals(1, this.writes.size());
        IndexRequest write = this.writes.get(0);
        assertEquals(POLICY_DOC_ID, write.id());
        assertEquals(7L, write.ifSeqNo());
        assertEquals(1L, write.ifPrimaryTerm());
        assertEquals(List.of("a", "b"), writtenFilters(write));
        JsonNode written = MAPPER.readTree(write.source().utf8ToString());
        assertNotEquals("old", written.at("/hash/sha256").asText());
    }

    /**
     * A version conflict re-reads the policy and applies the change to the winner's document, so a
     * concurrent writer's filter is kept rather than overwritten with the stale copy.
     */
    public void testLink_conflictRereadsAndKeepsConcurrentChange() throws Exception {
        this.servePolicy(7, "a");
        // Another request linked "x" in between.
        this.servePolicy(8, "a", "x");
        this.writeOutcomes.add(conflict());

        assertNull(this.run(true, "draft", "b"));

        assertEquals(2, this.writes.size());
        assertEquals(7L, this.writes.get(0).ifSeqNo());
        assertEquals(8L, this.writes.get(1).ifSeqNo());
        assertEquals(List.of("a", "x", "b"), writtenFilters(this.writes.get(1)));
    }

    /** Linking an id the policy already lists writes nothing. */
    @SuppressWarnings("unchecked")
    public void testLink_alreadyListedIsNoop() {
        this.servePolicy(7, "a", "b");

        assertNull(this.run(true, "draft", "b"));

        verify(this.client, never()).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** Unlink removes the id and keeps the rest. */
    public void testUnlink_removes() throws Exception {
        this.servePolicy(3, "a", "b", "c");

        assertNull(this.run(false, "standard", "b"));

        assertEquals(List.of("standard"), this.searchedSpaces);
        assertEquals(List.of("a", "c"), writtenFilters(this.writes.get(0)));
        assertEquals(3L, this.writes.get(0).ifSeqNo());
    }

    /**
     * Two deletes racing on one policy: the loser re-reads the winner's document instead of writing
     * back its stale copy, which would put the winner's id back into the list.
     */
    public void testUnlink_conflictDoesNotResurrectConcurrentRemoval() throws Exception {
        this.servePolicy(3, "a", "b", "c");
        // Another request removed "a" in between.
        this.servePolicy(4, "b", "c");
        this.writeOutcomes.add(conflict());

        assertNull(this.run(false, "draft", "b"));

        assertEquals(List.of("c"), writtenFilters(this.writes.get(1)));
    }

    /** Unlinking an id the policy does not list writes nothing. */
    @SuppressWarnings("unchecked")
    public void testUnlink_absentIsNoop() {
        this.servePolicy(3, "a");

        assertNull(this.run(false, "draft", "b"));

        verify(this.client, never()).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** The retry is bounded, and running out of attempts surfaces as a generic failure. */
    public void testConflictRetriesAreBounded() {
        for (int i = 0; i < Constants.POLICY_LINKS_MAX_UPDATE_ATTEMPTS; i++) {
            this.servePolicy(i, "a");
            this.writeOutcomes.add(conflict());
        }

        Exception failure = this.run(true, "draft", "b");

        assertEquals(Constants.POLICY_LINKS_MAX_UPDATE_ATTEMPTS, this.writes.size());
        // Reported as a plain IllegalStateException with no conflict in its causes, so the transport
        // actions answer the generic 500 rather than a 409 carrying OpenSearch's raw message.
        assertTrue(failure instanceof IllegalStateException);
        assertNull(failure.getCause());
        assertNull(TransportActionHelper.classifyException(failure));
    }

    /** A space without a policy fails the request and writes nothing. */
    @SuppressWarnings("unchecked")
    public void testMissingPolicyFails() {
        this.stubSearch(false);

        Exception failure = this.run(true, "draft", "b");

        assertTrue(failure instanceof IllegalStateException);
        assertEquals(MISSING_POLICY, failure.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /**
     * An integration link that loses a conflict to a filter link keeps that filter: both lists live
     * in the same policy document, so a blind rewrite of one drops the other's concurrent change.
     */
    public void testLinkIntegration_conflictKeepsConcurrentFilter() throws Exception {
        this.servePolicy(7, List.of("a"), List.of("i1"));
        // A filter create linked "x" in between.
        this.servePolicy(8, List.of("a", "x"), List.of("i1"));
        this.writeOutcomes.add(conflict());

        assertNull(this.run(true, "draft", Constants.KEY_INTEGRATIONS, "i2"));

        IndexRequest last = this.writes.get(1);
        assertEquals(8L, last.ifSeqNo());
        assertEquals(List.of("i1", "i2"), writtenList(last, Constants.KEY_INTEGRATIONS));
        assertEquals(List.of("a", "x"), writtenFilters(last));
    }

    /**
     * The other direction: a filter link that loses to an integration link keeps that integration.
     */
    public void testLinkFilter_conflictKeepsConcurrentIntegration() throws Exception {
        this.servePolicy(7, List.of("a"), List.of());
        // An integration create linked "i9" in between.
        this.servePolicy(8, List.of("a"), List.of("i9"));
        this.writeOutcomes.add(conflict());

        assertNull(this.run(true, "draft", "b"));

        IndexRequest last = this.writes.get(1);
        assertEquals(List.of("a", "b"), writtenFilters(last));
        assertEquals(List.of("i9"), writtenList(last, Constants.KEY_INTEGRATIONS));
    }

    /**
     * An integration unlink that loses to a filter link keeps the filter and still removes its id.
     */
    public void testUnlinkIntegration_conflictKeepsConcurrentFilter() throws Exception {
        this.servePolicy(3, List.of("a"), List.of("i1", "i2"));
        this.servePolicy(4, List.of("a", "x"), List.of("i1", "i2"));
        this.writeOutcomes.add(conflict());

        assertNull(this.run(false, "draft", Constants.KEY_INTEGRATIONS, "i1"));

        IndexRequest last = this.writes.get(1);
        assertEquals(List.of("i2"), writtenList(last, Constants.KEY_INTEGRATIONS));
        assertEquals(List.of("a", "x"), writtenFilters(last));
    }

    /** A policy without the list gets it created with the new id. */
    public void testLinkIntegration_missingListIsCreated() throws Exception {
        this.servePolicy(1, List.of("a"), null);

        assertNull(this.run(true, "draft", Constants.KEY_INTEGRATIONS, "i1"));

        assertEquals(List.of("i1"), writtenList(this.writes.get(0), Constants.KEY_INTEGRATIONS));
        assertEquals(List.of("a"), writtenFilters(this.writes.get(0)));
    }

    /**
     * Every retry after a conflict is scheduled with a backoff delay within the configured bounds.
     */
    public void testConflictRetryIsScheduledWithBackoff() throws Exception {
        this.servePolicy(7, "a");
        this.servePolicy(8, "a", "x");
        this.servePolicy(9, "a", "x", "y");
        this.writeOutcomes.add(conflict());
        this.writeOutcomes.add(conflict());

        assertNull(this.run(true, "draft", "b"));

        assertEquals(2, this.retryDelays.size());
        for (int attempt = 1; attempt <= 2; attempt++) {
            long millis = this.retryDelays.get(attempt - 1).millis();
            assertTrue(millis >= 1);
            assertTrue(millis <= Constants.POLICY_LINKS_RETRY_BASE_DELAY_MS << (attempt - 1));
        }
        assertEquals(List.of("a", "x", "y", "b"), writtenFilters(this.writes.get(2)));
    }

    /** The backoff grows with the attempt and never exceeds the cap. */
    public void testBackoffBounds() {
        for (int attempt = 1; attempt <= 30; attempt++) {
            long ceiling =
                    Math.min(
                            Constants.POLICY_LINKS_RETRY_MAX_DELAY_MS,
                            Constants.POLICY_LINKS_RETRY_BASE_DELAY_MS << Math.min(attempt - 1, 20));
            for (int i = 0; i < 50; i++) {
                long millis = PolicyLinks.backoff(attempt).millis();
                assertTrue(millis >= 1 && millis <= ceiling);
            }
        }
    }

    /**
     * Fake policy store for the queue tests: GETs are held until released, and a write succeeds only
     * with the sequence number of the stored version, as OpenSearch does.
     */
    private final class Store {
        ObjectNode document = MAPPER.createObjectNode().put("id", "p");
        long seqNo = 0;
        int conflicts = 0;
        final Deque<ActionListener<GetResponse>> heldGets = new ArrayDeque<>();

        @SuppressWarnings("unchecked")
        Store() {
            this.document.putArray(Constants.KEY_FILTERS);
            this.document.putArray(Constants.KEY_INTEGRATIONS);
            doAnswer(
                            invocation -> {
                                this.heldGets.add(invocation.getArgument(1));
                                return null;
                            })
                    .when(PolicyLinksTests.this.client)
                    .get(any(GetRequest.class), any(ActionListener.class));
            doAnswer(
                            invocation -> {
                                IndexRequest request = invocation.getArgument(0);
                                ActionListener<IndexResponse> l = invocation.getArgument(1);
                                if (request.ifSeqNo() != this.seqNo) {
                                    this.conflicts++;
                                    l.onFailure(conflict());
                                    return null;
                                }
                                this.document =
                                        (ObjectNode)
                                                MAPPER
                                                        .readTree(request.source().utf8ToString())
                                                        .get(Constants.KEY_DOCUMENT);
                                this.seqNo++;
                                l.onResponse(mock(IndexResponse.class));
                                return null;
                            })
                    .when(PolicyLinksTests.this.client)
                    .index(any(IndexRequest.class), any(ActionListener.class));
        }

        /** Answers the oldest held GET with the version stored right now. */
        void releaseGet() {
            String source =
                    "{\"document\":"
                            + this.document
                            + ",\"hash\":{\"sha256\":\"h\"},\"space\":{\"name\":\"draft\"}}";
            this.heldGets
                    .pop()
                    .onResponse(
                            new GetResponse(
                                    new GetResult(
                                            Constants.INDEX_POLICIES,
                                            POLICY_DOC_ID,
                                            this.seqNo,
                                            1L,
                                            this.seqNo + 1,
                                            true,
                                            new BytesArray(source),
                                            Collections.emptyMap(),
                                            Collections.emptyMap())));
        }

        List<String> list(String key) {
            List<String> ids = new ArrayList<>();
            this.document.path(key).forEach(n -> ids.add(n.asText()));
            return ids;
        }
    }

    /**
     * A burst of changes to one space's policy runs one at a time on this node: only one read is in
     * flight at any moment, so none of them conflicts and every id ends up listed. Without the queue
     * all of them read the same version and all but one conflict.
     */
    public void testConcurrentChangesToOneSpaceAreSerialized() {
        Store store = new Store();
        List<Exception> failures = new ArrayList<>();
        int[] succeeded = {0};
        ActionListener<Void> listener = ActionListener.wrap(v -> succeeded[0]++, failures::add);

        for (int i = 0; i < 10; i++) {
            PolicyLinks.link(
                    this.client, "draft", Constants.KEY_FILTERS, "f" + i, MISSING_POLICY, listener);
            PolicyLinks.link(
                    this.client, "draft", Constants.KEY_INTEGRATIONS, "i" + i, MISSING_POLICY, listener);
        }

        for (int round = 0; round < 20; round++) {
            assertEquals("exactly one change in flight per space", 1, store.heldGets.size());
            store.releaseGet();
        }

        assertTrue(store.heldGets.isEmpty());
        assertEquals(List.of(), failures);
        assertEquals(20, succeeded[0]);
        assertEquals(0, store.conflicts);
        assertEquals(10, store.list(Constants.KEY_FILTERS).size());
        assertEquals(10, store.list(Constants.KEY_INTEGRATIONS).size());

        // And the unlinks, likewise.
        for (int i = 0; i < 10; i++) {
            PolicyLinks.unlink(
                    this.client, "draft", Constants.KEY_FILTERS, "f" + i, MISSING_POLICY, listener);
        }
        for (int round = 0; round < 10; round++) {
            assertEquals(1, store.heldGets.size());
            store.releaseGet();
        }
        assertEquals(0, store.conflicts);
        assertEquals(List.of(), store.list(Constants.KEY_FILTERS));
        assertEquals(10, store.list(Constants.KEY_INTEGRATIONS).size());
    }

    /** Different spaces have separate queues: a pending change in one does not hold up another. */
    public void testDifferentSpacesDoNotWaitForEachOther() {
        Store store = new Store();
        ActionListener<Void> listener = ActionListener.wrap(v -> {}, e -> fail(e.getMessage()));

        PolicyLinks.link(this.client, "draft", Constants.KEY_FILTERS, "a", MISSING_POLICY, listener);
        PolicyLinks.link(this.client, "standard", Constants.KEY_FILTERS, "b", MISSING_POLICY, listener);

        assertEquals(2, store.heldGets.size());
        store.releaseGet();
        store.releaseGet();
    }

    /** A failed change does not stall the queue: the next one runs. */
    public void testQueueMovesOnAfterFailure() {
        this.stubSearch(false);
        List<Exception> failures = new ArrayList<>();
        ActionListener<Void> listener = ActionListener.wrap(v -> {}, failures::add);

        PolicyLinks.link(this.client, "draft", Constants.KEY_FILTERS, "a", MISSING_POLICY, listener);
        PolicyLinks.link(this.client, "draft", Constants.KEY_FILTERS, "b", MISSING_POLICY, listener);

        assertEquals(2, failures.size());
        assertEquals(List.of("draft", "draft"), this.searchedSpaces);
    }
}
