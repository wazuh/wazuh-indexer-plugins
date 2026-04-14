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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LogtestService}. Tests the orchestration of engine processing, integration
 * lookup, rule fetching, and SAP evaluation.
 */
public class LogtestServiceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LogtestService service;
    private AutoCloseable closeable;

    @Mock private EngineService engine;
    @Mock private SecurityAnalyticsService securityAnalytics;
    @Mock private Client client;
    @Mock private SearchRequestBuilder searchRequestBuilder;

    private static final String INTEGRATION_ID = "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509";
    private static final String RULE_ID = "85bba177-a2e9-4468-9d59-26f4798906c9";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.service = new LogtestService(this.engine, this.securityAnalytics, this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Helper methods */
    private ObjectNode createEnginePayload() throws Exception {
        // spotless:off
        return (ObjectNode) MAPPER.readTree(
            """
            {
              "space": "test",
              "queue": 1,
              "location": "/var/log/cassandra/system.log",
              "event": "INFO  [main] 2026-03-31 10:00:00 StorageService.java:123 - Node is ready to serve",
              "trace_level": "NONE"
            }
            """
        );
        // spotless:on
    }

    private SearchHit createHit(int docId, String id, String sourceJson) {
        SearchHit hit = new SearchHit(docId, id, Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray(sourceJson.getBytes(StandardCharsets.UTF_8)));
        return hit;
    }

    private SearchResponse createSearchResponse(SearchHit... hits) {
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(searchHits);
        return response;
    }

    private SearchResponse createEmptySearchResponse() {
        SearchHits searchHits =
                new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f);
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(searchHits);
        return response;
    }

    private void mockClientSearch(SearchResponse... responses) {
        when(this.client.prepareSearch(anyString())).thenReturn(this.searchRequestBuilder);
        when(this.searchRequestBuilder.setSource(any(SearchSourceBuilder.class)))
                .thenReturn(this.searchRequestBuilder);
        if (responses.length == 1) {
            when(this.searchRequestBuilder.get()).thenReturn(responses[0]);
        } else {
            var stub = when(this.searchRequestBuilder.get());
            for (SearchResponse r : responses) {
                stub = stub.thenReturn(r);
            }
        }
    }

    private RestResponse createEngineSuccess(String outputJson) {
        RestResponse response = new RestResponse();
        response.setStatus(RestStatus.OK.getStatus());
        response.setMessage(outputJson);
        return response;
    }

    private RestResponse createEngineError(String message) {
        RestResponse response = new RestResponse();
        response.setStatus(RestStatus.BAD_REQUEST.getStatus());
        response.setMessage(String.format(Locale.ROOT, "{\"message\": \"%s\"}", message));
        return response;
    }

    /** Integration not found returns 400. */
    public void testIntegrationNotFound() throws Exception {
        mockClientSearch(createEmptySearchResponse());

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains(INTEGRATION_ID));
        verify(this.engine, never()).logtest(any());
    }

    /** Integration search failure returns 500. */
    public void testIntegrationSearchFailure() throws Exception {
        when(this.client.prepareSearch(anyString())).thenReturn(this.searchRequestBuilder);
        when(this.searchRequestBuilder.setSource(any(SearchSourceBuilder.class)))
                .thenReturn(this.searchRequestBuilder);
        when(this.searchRequestBuilder.get()).thenThrow(new RuntimeException("search failed"));

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        verify(this.engine, never()).logtest(any());
    }

    /** When engine returns HTTP error, SAP is skipped. */
    public void testEngineHttpErrorSkipsSA() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            String.format(Locale.ROOT, """
            {"document": {"rules": ["%s"]}}
            """, RULE_ID));
        SearchHit ruleHit = createHit(2, "rule-1",
            """
            {"document": {"detection": {"selection": {"event.kind": "event"}, "condition": "selection"}, "logsource": {"product": "test"}, "level": "low", "status": "experimental"}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit), createSearchResponse(ruleHit));

        when(this.engine.logtest(any(JsonNode.class)))
                .thenReturn(createEngineError("Engine processing failed"));

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("\"skipped\""));
        Assert.assertTrue(response.getMessage().contains("Engine processing failed"));
        verify(this.securityAnalytics, never()).evaluateRules(anyString(), anyList());
    }

    /** When engine throws exception, SAP is skipped. */
    public void testEngineExceptionSkipsSA() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            """
            {"document": {"rules": []}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit));

        when(this.engine.logtest(any(JsonNode.class)))
                .thenThrow(new RuntimeException("socket timeout"));

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("\"skipped\""));
        Assert.assertTrue(response.getMessage().contains("socket timeout"));
        verify(this.securityAnalytics, never()).evaluateRules(anyString(), anyList());
    }

    /** Integration with no rules returns success with zero matches. */
    public void testNoRulesReturnsEmptyMatches() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            """
            {"document": {}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit));

        // spotless:off
        when(this.engine.logtest(any(JsonNode.class)))
            .thenReturn(createEngineSuccess(
                """
                {"output": {"event": {"kind": "event"}}, "asset_traces": []}
                """
            ));
        // spotless:on

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("\"rules_evaluated\":0"));
        Assert.assertTrue(response.getMessage().contains("\"rules_matched\":0"));
        Assert.assertTrue(response.getMessage().contains("\"success\""));
        verify(this.securityAnalytics, never()).evaluateRules(anyString(), anyList());
    }

    /** Full flow: engine success + SAP evaluation. */
    public void testFullFlowWithRules() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            String.format(Locale.ROOT, """
            {"document": {"rules": ["%s"]}}
            """, RULE_ID));
        SearchHit ruleHit = createHit(2, "rule-1",
            """
            {"document": {"detection": {"selection": {"event.kind": "event"}, "condition": "selection"}, "logsource": {"product": "test"}, "level": "low", "status": "experimental"}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit), createSearchResponse(ruleHit));

        // spotless:off
        when(this.engine.logtest(any(JsonNode.class)))
            .thenReturn(createEngineSuccess(
                """
                {"output": {"event": {"kind": "event", "category": ["database"]}}, "asset_traces": []}
                """
            ));
        when(this.securityAnalytics.evaluateRules(anyString(), anyList()))
            .thenReturn(
                """
                {"status":"success","rules_evaluated":1,"rules_matched":1,"matches":[{"rule_name":"Test Rule"}],"evaluation_time_ms":10}
                """
            );
        // spotless:on

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("normalization"));
        Assert.assertTrue(response.getMessage().contains("detection"));
        Assert.assertTrue(response.getMessage().contains("\"rules_matched\":1"));
        verify(this.securityAnalytics, times(1)).evaluateRules(anyString(), anyList());
    }

    /** Normalized event from engine output is passed to SAP. */
    public void testNormalizedEventPassedToSA() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            String.format(Locale.ROOT, """
            {"document": {"rules": ["%s"]}}
            """, RULE_ID));
        SearchHit ruleHit = createHit(2, "rule-1",
            """
            {"document": {"detection": {"selection": {"event.kind": "event"}, "condition": "selection"}, "logsource": {"product": "test"}, "level": "low", "status": "experimental"}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit), createSearchResponse(ruleHit));

        // spotless:off
        when(this.engine.logtest(any(JsonNode.class)))
            .thenReturn(createEngineSuccess(
                """
                {"output": {"event": {"kind": "event"}, "custom_field": "value"}, "asset_traces": []}
                """
            ));
        when(this.securityAnalytics.evaluateRules(anyString(), anyList()))
            .thenReturn("{\"status\":\"success\",\"rules_evaluated\":0,\"rules_matched\":0,\"matches\":[]}");
        // spotless:on

        this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());

        // Verify the normalized event (output node) was passed to SAP
        var eventCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(this.securityAnalytics).evaluateRules(eventCaptor.capture(), anyList());
        String normalizedEvent = eventCaptor.getValue();
        Assert.assertTrue(normalizedEvent.contains("custom_field"));
        Assert.assertTrue(normalizedEvent.contains("event"));
    }

    /** Integration with rules but rule index unavailable still returns empty SAP matches. */
    public void testRuleFetchFailureReturnsEmptyMatches() throws Exception {
        // Integration has rules, but we mock an empty rule fetch result (simulating failure)
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            String.format(Locale.ROOT, """
            {"document": {"rules": ["%s"]}}
            """, RULE_ID));
        // spotless:on
        // Return integration, then empty rules (simulates no rules found)
        mockClientSearch(createSearchResponse(integrationHit), createEmptySearchResponse());

        // spotless:off
        when(this.engine.logtest(any(JsonNode.class)))
            .thenReturn(createEngineSuccess(
                """
                {"output": {"event": {"kind": "event"}}, "asset_traces": []}
                """
            ));
        // spotless:on

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("\"rules_evaluated\":0"));
        verify(this.securityAnalytics, never()).evaluateRules(anyString(), anyList());
    }

    /** SAP evaluation error returns error SAP result but still 200. */
    public void testSAEvaluationErrorReturns200() throws Exception {
        // spotless:off
        SearchHit integrationHit = createHit(1, "int-1",
            String.format(Locale.ROOT, """
            {"document": {"rules": ["%s"]}}
            """, RULE_ID));
        SearchHit ruleHit = createHit(2, "rule-1",
            """
            {"document": {"detection": {"selection": {"event.kind": "event"}, "condition": "selection"}, "logsource": {"product": "test"}, "level": "low", "status": "experimental"}}
            """);
        // spotless:on
        mockClientSearch(createSearchResponse(integrationHit), createSearchResponse(ruleHit));

        // spotless:off
        when(this.engine.logtest(any(JsonNode.class)))
            .thenReturn(createEngineSuccess(
                """
                {"output": {"event": {"kind": "event"}}, "asset_traces": []}
                """
            ));
        // spotless:on
        // SAP returns unparseable response
        when(this.securityAnalytics.evaluateRules(anyString(), anyList())).thenReturn("not valid json");

        RestResponse response =
                this.service.executeLogtest(INTEGRATION_ID, Space.TEST, createEnginePayload());
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("\"error\""));
    }
}
