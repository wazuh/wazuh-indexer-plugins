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
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.get.GetResult;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.action.ContentCreateRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.doAnswer;

public class TransportCreateFilterActionTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String FILTER_PAYLOAD =
            "{\"space\":\"draft\",\"resource\":{"
                    + "\"name\":\"filter/test/0\","
                    + "\"metadata\":{\"title\":\"Test Filter\","
                    + "\"author\":{\"name\":\"Wazuh\",\"email\":\"info@wazuh.com\"}}}}";

    private Client client;
    private EngineService engine;
    private UserOverridesService overridesService;
    private TransportCreateFilterAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.engine.mock", true).build());
        this.client = mock(Client.class);
        stubResourceLock(this.client);
        TransportService transportService = mock(TransportService.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        // ResourceLockService stashes the caller's context around every lock operation.
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        when(transportService.getThreadPool()).thenReturn(threadPool);
        this.overridesService = mock(UserOverridesService.class);
        this.engine = mock(EngineService.class);
        this.action =
                new TransportCreateFilterAction(
                        transportService,
                        mock(ActionFilters.class),
                        this.client,
                        this.engine,
                        mock(EngineContentLoader.class),
                        this.overridesService);

        // Recording an override succeeds by default, so the tests that predate the registry are
        // unaffected by it.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any(ActionListener.class));
    }

    @After
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

    /**
     * Stubs the resource-creation-lock plumbing (ResourceLockService) so create actions can
     * acquire/release the lock without NPEs: the lock index is reported as already existing, and lock
     * acquire/release always succeed.
     */
    @SuppressWarnings("unchecked")
    private static void stubResourceLock(Client client) {
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doAnswer(
                        invocation -> {
                            ActionListener<IndicesExistsResponse> l = invocation.getArgument(1);
                            l.onResponse(existsResponse);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(), any(ActionListener.class));
        AdminClient adminClient = mock(AdminClient.class);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(client.admin()).thenReturn(adminClient);

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_maxFiltersReached() {
        PluginSettings.getInstance().setMaxFilters(0);
        try {
            // Draft policy exists (async search on the policies index).
            doAnswer(
                            invocation -> {
                                SearchRequest req = invocation.getArgument(0);
                                ActionListener<SearchResponse> l = invocation.getArgument(1);
                                long total =
                                        req.indices().length > 0 && Constants.INDEX_POLICIES.equals(req.indices()[0])
                                                ? 1
                                                : 0;
                                SearchResponse resp = mock(SearchResponse.class);
                                when(resp.getHits())
                                        .thenReturn(
                                                new SearchHits(
                                                        new SearchHit[0],
                                                        new TotalHits(total, TotalHits.Relation.EQUAL_TO),
                                                        0.0f));
                                l.onResponse(resp);
                                return null;
                            })
                    .when(this.client)
                    .search(any(), any(ActionListener.class));

            // Existing-filter count for the limit check (blocking one-arg search). count=0 >= max=0 →
            // rejected.
            SearchResponse countResp = mock(SearchResponse.class);
            when(countResp.getHits())
                    .thenReturn(
                            new SearchHits(
                                    new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f));
            ActionFuture<SearchResponse> countFuture = mock(ActionFuture.class);
            when(countFuture.actionGet()).thenReturn(countResp);
            when(this.client.search(
                            argThat(
                                    r ->
                                            r != null
                                                    && r.indices().length > 0
                                                    && Constants.INDEX_FILTERS.equals(r.indices()[0]))))
                    .thenReturn(countFuture);

            ContentCreateRequest request =
                    new ContentCreateRequest(
                            RestRequest.Method.POST, FILTER_PAYLOAD.getBytes(StandardCharsets.UTF_8), "json");

            ActionListener<ContentResponse> listener = mock(ActionListener.class);
            this.action.doExecute(mock(Task.class), request, listener);

            verify(listener)
                    .onResponse(
                            argThat(
                                    response -> {
                                        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                        Assert.assertTrue(response.getMessage().contains("allowed filters [0]"));
                                        return true;
                                    }));
        } finally {
            PluginSettings.getInstance().setMaxFilters(PluginSettings.DEFAULT_MAX_FILTERS);
        }
    }

    private static String filterPayload(String space) {
        return "{\"space\":\""
                + space
                + "\",\"resource\":{"
                + "\"name\":\"filter/test/0\","
                + "\"metadata\":{\"title\":\"Test Filter\",\"author\":\"Wazuh\"}}}";
    }

    /**
     * Regression test for a create in one space being linked into the other space's policy.
     *
     * <p>The action is a singleton, so a draft create that is still waiting for its filter document
     * to be indexed must not pick up the space of a standard create that runs to completion
     * meanwhile: when it resumes, it has to link the filter into the draft policy.
     */
    @SuppressWarnings("unchecked")
    public void testDoExecute_concurrentCreateInOtherSpaceDoesNotChangeLinkTarget() throws Exception {
        when(this.engine.validateResource(anyString(), any()))
                .thenReturn(new RestResponse("OK", RestStatus.OK.getStatus()));

        // Every policy search finds one policy, and records the space it asked for.
        List<String> policySearchSpaces = new ArrayList<>();
        doAnswer(
                        invocation -> {
                            SearchRequest req = invocation.getArgument(0);
                            ActionListener<SearchResponse> l = invocation.getArgument(1);
                            SearchHit[] hits = new SearchHit[0];
                            if (Constants.INDEX_POLICIES.equals(req.indices()[0])) {
                                JsonNode query = MAPPER.readTree(req.source().query().toString());
                                policySearchSpaces.add(
                                        query.path("term").path(Constants.Q_SPACE_NAME).path("value").asText());
                                hits =
                                        new SearchHit[] {
                                            new SearchHit(0, "policy-doc", Collections.emptyMap(), Collections.emptyMap())
                                        };
                            }
                            SearchResponse resp = mock(SearchResponse.class);
                            when(resp.getHits())
                                    .thenReturn(
                                            new SearchHits(
                                                    hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 0.0f));
                            l.onResponse(resp);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            String source =
                                    "{\"document\":{\"id\":\"p\",\"filters\":[]},"
                                            + "\"hash\":{\"sha256\":\"x\"},\"space\":{\"name\":\"any\"}}";
                            invocation
                                    .<ActionListener<GetResponse>>getArgument(1)
                                    .onResponse(
                                            new GetResponse(
                                                    new GetResult(
                                                            Constants.INDEX_POLICIES,
                                                            "policy-doc",
                                                            1L,
                                                            1L,
                                                            1L,
                                                            true,
                                                            new BytesArray(source),
                                                            Collections.emptyMap(),
                                                            Collections.emptyMap())));
                            return null;
                        })
                .when(this.client)
                .get(any(GetRequest.class), any(ActionListener.class));

        // The first filter document write (the draft create's) is held until released below.
        AtomicReference<ActionListener<IndexResponse>> heldDraftWrite = new AtomicReference<>();
        doAnswer(
                        invocation -> {
                            IndexRequest req = invocation.getArgument(0);
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            if (Constants.INDEX_FILTERS.equals(req.index())
                                    && heldDraftWrite.compareAndSet(null, l)) {
                                return null;
                            }
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        this.action.doExecute(
                mock(Task.class),
                new ContentCreateRequest(
                        RestRequest.Method.POST,
                        filterPayload("draft").getBytes(StandardCharsets.UTF_8),
                        "json"),
                mock(ActionListener.class));
        assertNotNull("the draft create should be waiting on its filter write", heldDraftWrite.get());

        this.action.doExecute(
                mock(Task.class),
                new ContentCreateRequest(
                        RestRequest.Method.POST,
                        filterPayload("standard").getBytes(StandardCharsets.UTF_8),
                        "json"),
                mock(ActionListener.class));

        int resumedAt = policySearchSpaces.size();
        heldDraftWrite.get().onResponse(mock(IndexResponse.class));

        assertTrue(
                "the draft create should have linked its filter", policySearchSpaces.size() > resumedAt);
        assertEquals(
                "the draft filter must be linked into the draft policy",
                "draft",
                policySearchSpaces.get(resumedAt));
    }
}
