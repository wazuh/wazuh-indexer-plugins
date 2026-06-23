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
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
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
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.action.ContentCreateRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class TransportCreateRuleActionTests extends OpenSearchTestCase {

    // logsource.product must match the integration's document.metadata.title
    private static final String RULE_PAYLOAD =
            "{\"integration\":\"int-1\",\"resource\":{"
                    + "\"metadata\":{\"title\":\"Test Rule\"},"
                    + "\"logsource\":{\"product\":\"test-product\"}}}";

    private Client client;
    private TransportCreateRuleAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.engine.mock", true).build());
        this.client = mock(Client.class);
        this.action =
                new TransportCreateRuleAction(
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

    /**
     * INDEX_RULES is searched twice: once by validateDuplicateTitle (0 hits → no conflict) and once
     * for the count check (0 hits with max=0 → rejected). The same argThat stub covers both. The
     * integration prepareGet stub covers both validateDocumentInSpace and the logsource.product
     * check, so the source map carries both space and document.metadata.title.
     */
    @SuppressWarnings("unchecked")
    public void testDoExecute_maxRulesReached() {
        PluginSettings.getInstance().setMaxRules(0);
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

            // 0 hits serves both the duplicate-title check (no conflict) and the count check
            // (count=0 >= max=0 → rejected).
            SearchResponse rulesResp = mock(SearchResponse.class);
            when(rulesResp.getHits())
                    .thenReturn(
                            new SearchHits(
                                    new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f));
            ActionFuture<SearchResponse> rulesFuture = mock(ActionFuture.class);
            when(rulesFuture.actionGet()).thenReturn(rulesResp);
            when(this.client.search(
                            argThat(
                                    r ->
                                            r != null
                                                    && r.indices().length > 0
                                                    && Constants.INDEX_RULES.equals(r.indices()[0]))))
                    .thenReturn(rulesFuture);

            // Integration document: space.name=draft for validateDocumentInSpace,
            // document.metadata.title="test-product" for the logsource.product check.
            GetResponse integResp = mock(GetResponse.class);
            when(integResp.isExists()).thenReturn(true);
            Map<String, Object> metadataMap = new HashMap<>();
            metadataMap.put(Constants.KEY_TITLE, "test-product");
            Map<String, Object> documentMap = new HashMap<>();
            documentMap.put(Constants.KEY_METADATA, metadataMap);
            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, "draft"));
            source.put(Constants.KEY_DOCUMENT, documentMap);
            when(integResp.getSourceAsMap()).thenReturn(source);
            GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
            when(this.client.prepareGet(eq(Constants.INDEX_INTEGRATIONS), anyString()))
                    .thenReturn(getBuilder);
            when(getBuilder.get()).thenReturn(integResp);

            ContentCreateRequest request =
                    new ContentCreateRequest(
                            RestRequest.Method.POST, RULE_PAYLOAD.getBytes(StandardCharsets.UTF_8), "json");

            ActionListener<ContentResponse> listener = mock(ActionListener.class);
            this.action.doExecute(mock(Task.class), request, listener);

            verify(listener)
                    .onResponse(
                            argThat(
                                    response -> {
                                        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                        Assert.assertTrue(response.getMessage().contains("allowed rules [0]"));
                                        return true;
                                    }));
        } finally {
            PluginSettings.getInstance().setMaxRules(PluginSettings.DEFAULT_MAX_RULES);
        }
    }
}
