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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.index.get.GetResult;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for the scoped-clear helpers of {@link IntegrationService}. */
public class IntegrationServiceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String INTEGRATION_ID = "int-1";

    private Client client;
    private IntegrationService service;
    private List<IndexRequest> indexed;
    private List<DeleteRequest> deleted;

    @Before
    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.indexed = new ArrayList<>();
        this.deleted = new ArrayList<>();
        this.service = new IntegrationService(this.client);

        doAnswer(
                        invocation -> {
                            this.indexed.add(invocation.getArgument(0));
                            invocation
                                    .<ActionListener<IndexResponse>>getArgument(1)
                                    .onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        doAnswer(
                        invocation -> {
                            this.deleted.add(invocation.getArgument(0));
                            invocation
                                    .<ActionListener<DeleteResponse>>getArgument(1)
                                    .onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(this.client)
                .delete(any(DeleteRequest.class), any());
    }

    @SuppressWarnings("unchecked")
    private void stubGet(ObjectNode document) {
        String source =
                "{\"document\":"
                        + document
                        + ",\"hash\":{\"sha256\":\"old\"},\"space\":{\"name\":\"draft\"}}";
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<GetResponse>>getArgument(1)
                                    .onResponse(
                                            new GetResponse(
                                                    new GetResult(
                                                            Constants.INDEX_INTEGRATIONS,
                                                            INTEGRATION_ID,
                                                            0L,
                                                            1L,
                                                            1L,
                                                            true,
                                                            new BytesArray(source),
                                                            Collections.emptyMap(),
                                                            Collections.emptyMap())));
                            return null;
                        })
                .when(this.client)
                .get(any(GetRequest.class), any());
    }

    private static ObjectNode integrationDoc(
            List<String> decoders, List<String> rules, List<String> kvdbs, String mode) {
        ObjectNode doc = MAPPER.createObjectNode().put("id", INTEGRATION_ID);
        doc.set(Constants.KEY_DECODERS, MAPPER.valueToTree(decoders));
        doc.set(Constants.KEY_RULES, MAPPER.valueToTree(rules));
        doc.set(Constants.KEY_KVDBS, MAPPER.valueToTree(kvdbs));
        if (mode != null) {
            doc.put(Constants.KEY_MODE, mode);
        }
        return doc;
    }

    private IntegrationService.EmptyResult runEmptyFields(Set<String> keys) {
        AtomicReference<IntegrationService.EmptyResult> result = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        this.service.emptyFieldsAsync(
                INTEGRATION_ID, keys, ActionListener.wrap(result::set, failure::set));
        if (failure.get() != null) {
            fail(failure.get().getMessage());
        }
        assertNotNull(result.get());
        return result.get();
    }

    /**
     * emptyFieldsAsync blanks the given lists, keeps the rest, and reports not-empty if rules stay.
     */
    public void testEmptyFieldsAsync_emptiesGivenListsAndKeepsRules() throws Exception {
        stubGet(integrationDoc(List.of("d1"), List.of("r1"), List.of("k1"), null));

        IntegrationService.EmptyResult result =
                runEmptyFields(Set.of(Constants.KEY_DECODERS, Constants.KEY_KVDBS));

        assertFalse(result.isProtected());
        assertFalse("rules remain, so the integration is not left empty", result.nowEmpty());
        assertEquals(1, this.indexed.size());
        @SuppressWarnings("unchecked")
        Map<String, Object> written =
                (Map<String, Object>) this.indexed.get(0).sourceAsMap().get(Constants.KEY_DOCUMENT);
        assertTrue(((List<?>) written.get(Constants.KEY_DECODERS)).isEmpty());
        assertTrue(((List<?>) written.get(Constants.KEY_KVDBS)).isEmpty());
        assertEquals(1, ((List<?>) written.get(Constants.KEY_RULES)).size());
    }

    /** When clearing a field leaves all three lists empty, nowEmpty is reported true. */
    public void testEmptyFieldsAsync_reportsNowEmptyWhenAllListsCleared() {
        stubGet(integrationDoc(List.of("d1"), List.of(), List.of(), null));

        IntegrationService.EmptyResult result = runEmptyFields(Set.of(Constants.KEY_DECODERS));

        assertTrue(result.nowEmpty());
    }

    /** A protected integration is reported as protected (it is still emptied). */
    public void testEmptyFieldsAsync_reportsProtected() {
        stubGet(integrationDoc(List.of("d1"), List.of(), List.of(), Constants.MODE_PROTECTED));

        IntegrationService.EmptyResult result = runEmptyFields(Set.of(Constants.KEY_DECODERS));

        assertTrue(result.isProtected());
    }

    /** listIntegrationIdsAsync returns the OpenSearch _id of every integration in the space. */
    @SuppressWarnings("unchecked")
    public void testListIntegrationIdsAsync_returnsHitIds() {
        SearchHit[] hits = {
            new SearchHit(0, "A", Collections.emptyMap(), Collections.emptyMap()),
            new SearchHit(1, "B", Collections.emptyMap(), Collections.emptyMap())
        };
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits())
                .thenReturn(new SearchHits(hits, new TotalHits(2, TotalHits.Relation.EQUAL_TO), 0.0f));
        doAnswer(
                        invocation -> {
                            SearchRequest request = invocation.getArgument(0);
                            assertEquals(Constants.INDEX_INTEGRATIONS, request.indices()[0]);
                            invocation.<ActionListener<SearchResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());

        AtomicReference<List<String>> ids = new AtomicReference<>();
        this.service.listIntegrationIdsAsync(
                "draft", ActionListener.wrap(ids::set, e -> fail(e.getMessage())));

        assertEquals(List.of("A", "B"), ids.get());
    }

    /** deleteIntegrationDocAsync deletes the integration document by its id. */
    public void testDeleteIntegrationDocAsync_deletesById() {
        AtomicReference<Boolean> done = new AtomicReference<>(false);

        this.service.deleteIntegrationDocAsync(
                INTEGRATION_ID, ActionListener.wrap(v -> done.set(true), e -> fail(e.getMessage())));

        assertTrue(done.get());
        assertEquals(1, this.deleted.size());
        assertEquals(Constants.INDEX_INTEGRATIONS, this.deleted.get(0).index());
        assertEquals(INTEGRATION_ID, this.deleted.get(0).id());
    }
}
