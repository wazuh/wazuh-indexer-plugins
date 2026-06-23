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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.PutPolicyRequest;
import com.wazuh.contentmanager.action.PutPolicyResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TransportPutPolicyAction}, which performs the policy update (validation,
 * write, and standard-space hash recalculation) gated behind the {@code
 * plugin:content_manager/policy/update} permission and the lockdown setting.
 */
public class TransportPutPolicyActionTests extends OpenSearchTestCase {
    private SpaceService service;
    private TransportPutPolicyAction action;
    private Client client;
    private AutoCloseable mocks;

    @Mock private IndexResponse indexResponse;
    @Mock private SearchResponse searchResponse;

    private static final String DRAFT_JSON =
            "{"
                    + "\"type\": \"policy\","
                    + "\"resource\": {"
                    + "\"title\": \"Test Policy\","
                    + "\"root_decoder\": \"decoder/integrations/0\","
                    + "\"integrations\": [\"integration-1\"],"
                    + "\"filters\": [],"
                    + "\"enrichments\": [],"
                    + "\"enabled\": true,"
                    + "\"index_unclassified_events\": false,"
                    + "\"index_discarded_events\": false,"
                    + "\"author\": \"Wazuh Inc.\","
                    + "\"description\": \"Test policy\","
                    + "\"documentation\": \"Test documentation\","
                    + "\"references\": [\"Test references\"]"
                    + "}"
                    + "}";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        this.service = mock(SpaceService.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);

        this.action =
                new TransportPutPolicyAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.client, this.service);

        // Default draft policy returned by the SpaceService mock.
        when(this.service.getPolicy(anyString())).thenReturn(draftPolicy(Collections.emptyList()));

        SearchHit searchHit =
                new SearchHit(0, "draft-policy-id", Collections.emptyMap(), Collections.emptyMap());
        SearchHits searchHits =
                new SearchHits(
                        new SearchHit[] {searchHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);
        when(this.searchResponse.getHits()).thenReturn(searchHits);

        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        if (this.mocks != null) {
            this.mocks.close();
        }
        super.tearDown();
    }

    // ---- helpers ----------------------------------------------------------

    private static Map<String, Object> draftPolicy(List<String> filters) {
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "12345");
        document.put(Constants.KEY_INTEGRATIONS, List.of("integration-1"));
        document.put("filters", filters);
        document.put("enrichments", Collections.emptyList());
        hash.put("sha256", "12345");
        space.put(Constants.KEY_NAME, Space.DRAFT.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        return policy;
    }

    private void mockStandardPolicy(
            List<String> filters, List<String> enrichments, List<String> integrations)
            throws IOException {
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "standard-doc-id");
        document.put(Constants.KEY_TITLE, "Standard Policy Title");
        document.put(Constants.KEY_AUTHOR, "Original Author");
        document.put(Constants.KEY_DESCRIPTION, "Original description");
        document.put("documentation", "Original documentation");
        document.put("references", List.of("https://original.ref"));
        document.put("root_decoder", "decoder/original/0");
        document.put("date", "2025-01-01T00:00:00Z");
        document.put(Constants.KEY_INTEGRATIONS, integrations);
        document.put(Constants.KEY_FILTERS, filters);
        document.put(Constants.KEY_ENRICHMENTS, enrichments);
        hash.put("sha256", "standard-hash-value");
        space.put(Constants.KEY_NAME, Space.STANDARD.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);
    }

    private void mockIndex(String id) {
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn(id);
    }

    private PutPolicyResponse execute(String space, String json) {
        PlainActionFuture<PutPolicyResponse> future = PlainActionFuture.newFuture();
        this.action.doExecute(mock(Task.class), new PutPolicyRequest(space, json), future);
        return future.actionGet();
    }

    // ---- lockdown ---------------------------------------------------------

    public void testDoExecute_Locked_Forbidden() {
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.sensitive_config.locked", true).build());

        PutPolicyResponse response = this.execute("draft", DRAFT_JSON);

        Assert.assertEquals(RestStatus.FORBIDDEN, response.getStatus());
        Assert.assertEquals(Constants.E_403_SENSITIVE_CONFIG_LOCKED, response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    // ---- draft space ------------------------------------------------------

    public void testPutPolicy_UpdateModifiesIntegrations_400() {
        String json =
                "{\"resource\": {\"integrations\": [\"integration/wazuh-core/0\"], \"filters\": [],"
                        + " \"enrichments\": [], \"enabled\": true, \"index_unclassified_events\": false,"
                        + " \"index_discarded_events\": false, \"author\": \"Wazuh Inc.\", \"description\":"
                        + " \"Test policy\", \"documentation\": \"d\", \"references\": [\"r\"]}}";
        this.mockIndex("test-policy-id");

        PutPolicyResponse response = this.execute("draft", json);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.E_400_INVALID_REQUEST_BODY));
    }

    public void testPutPolicy_UpdateExisting_200() {
        this.mockIndex("test-policy-id");

        PutPolicyResponse response = this.execute("draft", DRAFT_JSON);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());
        verify(this.service).calculateAndUpdate(anyList());
    }

    public void testPutPolicy_NoContent_400() {
        PutPolicyResponse response = this.execute("draft", null);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_InvalidSpace_400() {
        PutPolicyResponse response = this.execute("bogus", DRAFT_JSON);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_InvalidJson_400() {
        PutPolicyResponse response = this.execute("draft", "{invalid json content");

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.E_400_INVALID_REQUEST_BODY));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_MissingResourceField_400() {
        PutPolicyResponse response = this.execute("draft", "{\"type\": \"policy\"}");

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_MissingRequiredFields_400() {
        String json =
                "{\"resource\": {\"title\": \"t\", \"root_decoder\": \"d\", \"integrations\": []}}";

        PutPolicyResponse response = this.execute("draft", json);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_IndexingFails_500() {
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onFailure(new IOException("Indexing failed"));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        PutPolicyResponse response = this.execute("draft", DRAFT_JSON);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    public void testPutPolicy_InvalidEnrichmentType_400() {
        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet()))
                .thenReturn(
                        new RestResponse(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_INVALID_ENRICHMENT,
                                        "invalid-type",
                                        "connection, hash_sha1"),
                                400));
        this.action.setPayloadValidations(payloadValidations);

        PutPolicyResponse response = this.execute("draft", DRAFT_JSON);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertEquals(
                String.format(
                        Locale.ROOT,
                        Constants.E_400_INVALID_ENRICHMENT,
                        "invalid-type",
                        "connection, hash_sha1"),
                response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutPolicy_AddFilter_400() throws IOException {
        when(this.service.getPolicy(anyString())).thenReturn(draftPolicy(List.of("uuid-1")));
        String json =
                "{\"resource\": {\"integrations\": [\"integration-1\"], \"filters\": [\"uuid-1\","
                        + " \"uuid-2\"], \"enrichments\": [], \"enabled\": true,"
                        + " \"index_unclassified_events\": false, \"index_discarded_events\": false,"
                        + " \"author\": \"a\", \"description\": \"d\", \"documentation\": \"d\","
                        + " \"references\": [\"r\"]}}";

        PutPolicyResponse response = this.execute("draft", json);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.E_400_INVALID_REQUEST_BODY));
    }

    public void testPutPolicy_ReorderFilters_200() throws IOException {
        when(this.service.getPolicy(anyString())).thenReturn(draftPolicy(List.of("uuid-1", "uuid-2")));
        this.mockIndex("test-policy-id");

        String json =
                "{\"resource\": {\"integrations\": [\"integration-1\"], \"filters\": [\"uuid-2\","
                        + " \"uuid-1\"], \"enrichments\": [], \"enabled\": true,"
                        + " \"index_unclassified_events\": false, \"index_discarded_events\": false,"
                        + " \"author\": \"a\", \"description\": \"d\", \"documentation\": \"d\","
                        + " \"references\": [\"r\"]}}";

        PutPolicyResponse response = this.execute("draft", json);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
    }

    public void testPutDraftPolicy_NoReload() {
        this.mockIndex("test-policy-id");
        when(this.service.calculateAndUpdate(anyList())).thenReturn(Collections.emptySet());

        PutPolicyResponse response = this.execute("draft", DRAFT_JSON);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        Assert.assertFalse(response.shouldReloadEngine());
    }

    // ---- standard space ---------------------------------------------------

    private static final String STANDARD_JSON =
            "{\"resource\": {\"enrichments\": [], \"filters\": [], \"enabled\": true,"
                    + " \"index_unclassified_events\": false, \"index_discarded_events\": false}}";

    public void testPutStandardPolicy_Update_200() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");
        this.mockIndex("standard-policy-os-id");

        PutPolicyResponse response = this.execute("standard", STANDARD_JSON);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        Assert.assertEquals("standard-policy-os-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
        verify(this.service).calculateAndUpdate(List.of("standard"));
    }

    public void testPutStandardPolicy_AddFilter_400() throws IOException {
        this.mockStandardPolicy(List.of("uuid-1"), Collections.emptyList(), List.of("int-1"));
        String json =
                "{\"resource\": {\"enrichments\": [], \"filters\": [\"uuid-1\", \"uuid-2\"], \"enabled\":"
                        + " true, \"index_unclassified_events\": false, \"index_discarded_events\": false}}";

        PutPolicyResponse response = this.execute("standard", json);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutStandardPolicy_MissingEnabled_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        String json =
                "{\"resource\": {\"enrichments\": [], \"filters\": [],"
                        + " \"index_unclassified_events\": false, \"index_discarded_events\": false}}";

        PutPolicyResponse response = this.execute("standard", json);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    public void testPutStandardPolicy_HashChanged_SignalsReload() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");
        when(this.service.calculateAndUpdate(anyList())).thenReturn(Set.of(Space.STANDARD.toString()));
        this.mockIndex("standard-policy-os-id");

        PutPolicyResponse response = this.execute("standard", STANDARD_JSON);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        Assert.assertTrue(response.shouldReloadEngine());
    }

    public void testPutStandardPolicy_HashUnchanged_NoReload() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");
        when(this.service.calculateAndUpdate(anyList())).thenReturn(Collections.emptySet());
        this.mockIndex("standard-policy-os-id");

        PutPolicyResponse response = this.execute("standard", STANDARD_JSON);

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        Assert.assertFalse(response.shouldReloadEngine());
    }
}
