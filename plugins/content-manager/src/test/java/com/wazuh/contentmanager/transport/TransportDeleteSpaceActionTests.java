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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.get.GetResult;
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
import java.util.Collections;
import java.util.Locale;

import com.wazuh.contentmanager.action.DeleteSpaceRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.SpaceClearScope;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.*;

public class TransportDeleteSpaceActionTests extends OpenSearchTestCase {
    private TransportDeleteSpaceAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        // Enable engine mock so constructor uses MockSecurityAnalyticsService
        Settings settings = Settings.builder().put("plugins.content_manager.engine.mock", true).build();
        PluginSettings.getInstance(settings);
        this.action =
                new TransportDeleteSpaceAction(
                        mock(TransportService.class), mock(ActionFilters.class), mock(Client.class));
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

    public void testDoExecute_InvalidSpace() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("invalid_space");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Invalid space"));
                                    return true;
                                }));
    }

    public void testDoExecute_NonDraftSpace() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("standard");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }

    public void testDoExecute_TestSpaceNotAllowed() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("test");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }

    /** The draft-only restriction applies to the scoped normalization clear too. */
    public void testDoExecute_NormalizationScopeNonDraftRejected() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("test", SpaceClearScope.NORMALIZATION);

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }

    /** The draft-only restriction applies to the scoped detection clear too. */
    public void testDoExecute_DetectionScopeNonDraftRejected() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("standard", SpaceClearScope.DETECTION);

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }

    /** scope=NORMALIZATION on draft routes to the normalization clear and reports success. */
    public void testDoExecute_NormalizationScopeClearsAndReports() {
        ThreadPool threadPool = lockThreadPool();
        TransportDeleteSpaceAction act = actionWith(stubbedClient(threadPool), threadPool);
        DeleteSpaceRequest request = new DeleteSpaceRequest("draft", SpaceClearScope.NORMALIZATION);

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        act.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    Assert.assertTrue(
                                            response.getMessage().toLowerCase(Locale.ROOT).contains("normalization"));
                                    return true;
                                }));
    }

    /** scope=DETECTION on draft routes to the detection clear and reports success. */
    public void testDoExecute_DetectionScopeClearsAndReports() {
        ThreadPool threadPool = lockThreadPool();
        TransportDeleteSpaceAction act = actionWith(stubbedClient(threadPool), threadPool);
        DeleteSpaceRequest request = new DeleteSpaceRequest("draft", SpaceClearScope.DETECTION);

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        act.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    Assert.assertTrue(
                                            response.getMessage().toLowerCase(Locale.ROOT).contains("detection"));
                                    return true;
                                }));
    }

    private TransportDeleteSpaceAction actionWith(Client client, ThreadPool threadPool) {
        TransportService transportService = mock(TransportService.class);
        when(transportService.getThreadPool()).thenReturn(threadPool);
        return new TransportDeleteSpaceAction(transportService, mock(ActionFilters.class), client);
    }

    /** A thread pool whose context is available and whose schedule() runs the task immediately. */
    private static ThreadPool lockThreadPool() {
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        return threadPool;
    }

    /** A client wired so a scoped clear of an empty draft completes without touching real indices. */
    @SuppressWarnings("unchecked")
    private static Client stubbedClient(ThreadPool threadPool) {
        Client client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        // The resource-lock index is reported as already existing so the space lock can be acquired.
        IndicesExistsResponse exists = mock(IndicesExistsResponse.class);
        when(exists.isExists()).thenReturn(true);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<IndicesExistsResponse>>getArgument(1).onResponse(exists);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());

        when(client.threadPool()).thenReturn(threadPool);

        // The space lock: acquire indexes the lock document, release deletes it. Both succeed here.
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndexResponse>>getArgument(1)
                                    .onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any());
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<DeleteResponse>>getArgument(1)
                                    .onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any());

        doAnswer(
                        invocation -> {
                            SearchRequest request = invocation.getArgument(0);
                            SearchHit[] hits =
                                    Constants.INDEX_POLICIES.equals(request.indices()[0])
                                            ? new SearchHit[] {
                                                new SearchHit(
                                                        0, "draft-policy-doc", Collections.emptyMap(), Collections.emptyMap())
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
                .when(client)
                .search(any(SearchRequest.class), any());

        doAnswer(
                        invocation -> {
                            String source =
                                    "{\"document\":{\"id\":\"p\"},\"hash\":{\"sha256\":\"old\"},"
                                            + "\"space\":{\"name\":\"draft\"}}";
                            invocation
                                    .<ActionListener<GetResponse>>getArgument(1)
                                    .onResponse(
                                            new GetResponse(
                                                    new GetResult(
                                                            Constants.INDEX_POLICIES,
                                                            "draft-policy-doc",
                                                            1L,
                                                            1L,
                                                            2L,
                                                            true,
                                                            new BytesArray(source),
                                                            Collections.emptyMap(),
                                                            Collections.emptyMap())));
                            return null;
                        })
                .when(client)
                .get(any(GetRequest.class), any());

        return client;
    }
}
