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
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import com.wazuh.contentmanager.action.ContentCreateRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

public class TransportCreateFilterActionTests extends OpenSearchTestCase {

    private static final String FILTER_PAYLOAD =
            "{\"space\":\"draft\",\"resource\":{"
                    + "\"name\":\"filter/test/0\","
                    + "\"metadata\":{\"title\":\"Test Filter\","
                    + "\"author\":{\"name\":\"Wazuh\",\"email\":\"info@wazuh.com\"}}}}";

    private Client client;
    private TransportCreateFilterAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.engine.mock", true).build());
        this.client = mock(Client.class);
        this.action =
                new TransportCreateFilterAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.client,
                        mock(EngineService.class));
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
    public void testDoExecute_maxFiltersReached() {
        PluginSettings.getInstance().setMaxFilters(0);
        try {
            SearchResponse policyResp = mock(SearchResponse.class);
            when(policyResp.getHits())
                    .thenReturn(
                            new SearchHits(
                                    new SearchHit[0], new TotalHits(1, TotalHits.Relation.EQUAL_TO), 0.0f));
            ActionFuture<SearchResponse> policyFuture = mock(ActionFuture.class);
            when(policyFuture.actionGet()).thenReturn(policyResp);
            when(this.client.search(
                            argThat(
                                    r ->
                                            r != null
                                                    && r.indices().length > 0
                                                    && Constants.INDEX_POLICIES.equals(r.indices()[0]))))
                    .thenReturn(policyFuture);

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
}
