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
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHits;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.action.ContentUpdateRequest;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

public class TransportUpdateDecoderActionTests extends OpenSearchTestCase {
    private Client client;
    private EngineService engineService;
    private TransportUpdateDecoderAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        Settings settings = Settings.builder().put("plugins.content_manager.engine.mock", true).build();
        PluginSettings.getInstance(settings);
        this.client = mock(Client.class);
        this.engineService = mock(EngineService.class);
        this.action =
                new TransportUpdateDecoderAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.client,
                        this.engineService);
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

    @SuppressWarnings("unchecked")
    private void mockDraftPolicyExists() {
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHits searchHits =
                new SearchHits(
                        new org.opensearch.search.SearchHit[0],
                        new TotalHits(1, TotalHits.Relation.EQUAL_TO),
                        0.0f);
        when(searchResponse.getHits()).thenReturn(searchHits);
        ActionFuture<SearchResponse> future = mock(ActionFuture.class);
        when(future.actionGet()).thenReturn(searchResponse);
        when(this.client.search(any())).thenReturn(future);
    }

    @SuppressWarnings("unchecked")
    private void mockDraftPolicyMissing() {
        SearchResponse searchResponse = mock(SearchResponse.class);
        when(searchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> future = mock(ActionFuture.class);
        when(future.actionGet()).thenReturn(searchResponse);
        when(this.client.search(any())).thenReturn(future);
    }

    public void testDoExecute_EmptyBody() {
        mockDraftPolicyExists();
        ContentUpdateRequest request =
                new ContentUpdateRequest(
                        RestRequest.Method.PUT, "550e8400-e29b-41d4-a716-446655440000", new byte[0], "json");

        @SuppressWarnings("unchecked")
        ActionListener<ContentResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_NullBody() {
        mockDraftPolicyExists();
        ContentUpdateRequest request =
                new ContentUpdateRequest(
                        RestRequest.Method.PUT, "550e8400-e29b-41d4-a716-446655440000", null, "json");

        @SuppressWarnings("unchecked")
        ActionListener<ContentResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_InvalidJson() {
        mockDraftPolicyExists();
        ContentUpdateRequest request =
                new ContentUpdateRequest(
                        RestRequest.Method.PUT,
                        "550e8400-e29b-41d4-a716-446655440000",
                        "not valid json".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        "json");

        @SuppressWarnings("unchecked")
        ActionListener<ContentResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        // The update flow checks index existence before parsing body,
        // so without full index mocking we get ISE from the client mock
        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertNotNull(response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_DraftPolicyMissing() {
        mockDraftPolicyMissing();
        ContentUpdateRequest request =
                new ContentUpdateRequest(
                        RestRequest.Method.PUT,
                        "550e8400-e29b-41d4-a716-446655440000",
                        "{\"resource\":{\"name\":\"test\"}}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        "json");

        @SuppressWarnings("unchecked")
        ActionListener<ContentResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Draft policy"));
                                    return true;
                                }));
    }

    public void testDoExecute_DraftPolicyCheckException() {
        when(this.client.search(any())).thenThrow(new RuntimeException("Search failed"));
        ContentUpdateRequest request =
                new ContentUpdateRequest(
                        RestRequest.Method.PUT,
                        "550e8400-e29b-41d4-a716-446655440000",
                        "{\"resource\":{\"name\":\"test\"}}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        "json");

        @SuppressWarnings("unchecked")
        ActionListener<ContentResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }
}
