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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.get.GetResult;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
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
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link PolicyFilters}. */
public class PolicyFiltersTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_DOC_ID = "draft-policy-doc";

    private Client client;

    /** Policy versions served by successive GETs, as {seqNo, filters...}. */
    private Deque<GetResponse> gets;

    /** Outcomes of successive index calls: {@code null} succeeds, anything else fails with it. */
    private Deque<Exception> writeOutcomes;

    private List<String> searchedSpaces;
    private List<IndexRequest> writes;

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
        this.stubSearch(true);

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

    /** Queues a policy version for the next GET. */
    private void servePolicy(long seqNo, String... filters) {
        String source =
                "{\"document\":{\"id\":\"p\",\"filters\":"
                        + MAPPER.valueToTree(List.of(filters))
                        + "},\"hash\":{\"sha256\":\"old\"},\"space\":{\"name\":\"draft\"}}";
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
        List<String> ids = new ArrayList<>();
        MAPPER
                .readTree(request.source().utf8ToString())
                .path(Constants.KEY_DOCUMENT)
                .path(Constants.KEY_FILTERS)
                .forEach(n -> ids.add(n.asText()));
        return ids;
    }

    private Exception run(boolean link, String space, String filterId) {
        AtomicReference<Exception> failure = new AtomicReference<>();
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        ActionListener<Void> listener = ActionListener.wrap(v -> done.set(true), e -> failure.set(e));
        if (link) {
            PolicyFilters.link(this.client, space, filterId, listener);
        } else {
            PolicyFilters.unlink(this.client, space, filterId, listener);
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

    /** The retry is bounded: after the last attempt the conflict is reported. */
    public void testConflictRetriesAreBounded() {
        for (int i = 0; i < Constants.POLICY_FILTERS_MAX_UPDATE_ATTEMPTS; i++) {
            this.servePolicy(i, "a");
            this.writeOutcomes.add(conflict());
        }

        Exception failure = this.run(true, "draft", "b");

        assertTrue(failure instanceof VersionConflictEngineException);
        assertEquals(Constants.POLICY_FILTERS_MAX_UPDATE_ATTEMPTS, this.writes.size());
    }

    /** A space without a policy fails the request and writes nothing. */
    @SuppressWarnings("unchecked")
    public void testMissingPolicyFails() {
        this.stubSearch(false);

        Exception failure = this.run(true, "draft", "b");

        assertTrue(failure instanceof IllegalStateException);
        assertTrue(failure.getMessage().contains("draft"));
        verify(this.client, never()).index(any(IndexRequest.class), any(ActionListener.class));
    }
}
