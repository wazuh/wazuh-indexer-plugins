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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.*;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service that orchestrates logtest execution by combining Wazuh Engine event processing with
 * Security Analytics Plugin (SAP) Sigma rule evaluation.
 *
 * <p>Steps:
 *
 * <ol>
 *   <li>Look up the integration in the {@code wazuh-threatintel-integrations} index (test or
 *       standard space)
 *   <li>Send the event to the Wazuh Engine for decoding and normalization
 *   <li>Extract rule IDs from the integration and fetch rule bodies from {@code
 *       wazuh-threatintel-rules}
 *   <li>Evaluate the Sigma rules against the Engine's normalized event via SAP
 *   <li>Return a combined response with both engine and SAP results
 * </ol>
 *
 * <p>If the Engine fails, SAP evaluation is skipped. If the integration has no rules, the SAP
 * result returns zero matches with a success status.
 */
public class LogtestService {
    private static final Logger log = LogManager.getLogger(LogtestService.class);

    private final EngineService engine;
    private final SecurityAnalyticsService securityAnalytics;
    private final Client client;

    /**
     * Constructs a new LogtestService.
     *
     * @param engine the Engine service for event decoding and normalization
     * @param securityAnalytics the SAP service for Sigma rule evaluation
     * @param client the OpenSearch client for index queries
     */
    public LogtestService(
            EngineService engine, SecurityAnalyticsService securityAnalytics, Client client) {
        this.engine = engine;
        this.securityAnalytics = securityAnalytics;
        this.client = client;
    }

    /**
     * Executes the full logtest flow: integration lookup, engine processing, rule fetching, and SAP
     * evaluation.
     *
     * @param integrationId the integration document ID to look up
     * @param space the space to search in (test or standard)
     * @param enginePayload the request payload to forward to the Engine (without the integration
     *     field)
     * @return a {@link RestResponse} containing the combined engine and SAP results as JSON
     */
    public RestResponse executeLogtest(String integrationId, Space space, ObjectNode enginePayload) {
        // If no integration provided, run engine only and skip detection
        if (integrationId == null) {
            return executeEngineOnly(enginePayload);
        }

        // 1. Look up integration from wazuh-threatintel-integrations by document.id + space
        SearchResponse integrationSearchResponse;
        ObjectMapper mapper = new ObjectMapper();
        try {
            integrationSearchResponse =
                    this.client
                            .prepareSearch(Constants.INDEX_INTEGRATIONS)
                            .setSource(
                                    new SearchSourceBuilder()
                                            .query(
                                                    QueryBuilders.boolQuery()
                                                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, integrationId))
                                                            .must(
                                                                    QueryBuilders.termQuery(
                                                                            Constants.Q_SPACE_NAME, space.toString())))
                                            .size(1))
                            .get();
        } catch (Exception e) {
            log.error("Failed to look up integration [{}]: {}", integrationId, e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (Objects.requireNonNull(integrationSearchResponse.getHits().getTotalHits()).value() == 0) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INTEGRATION_NOT_FOUND, integrationId, space),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. Send event to Engine
        Map<String, Object> engineResult = executeEngine(enginePayload);

        // If engine failed, skip SAP evaluation
        if ("error".equals(engineResult.get(Constants.KEY_STATUS))) {
            Map<String, Object> sapResult = new LinkedHashMap<>();
            sapResult.put(Constants.KEY_STATUS, "skipped");
            sapResult.put("reason", "Engine processing failed");
            return buildCombinedResponse(engineResult, sapResult);
        }

        // 3. Fetch rule IDs from integration
        Map<String, Object> integrationSource =
                integrationSearchResponse.getHits().getAt(0).getSourceAsMap();
        List<String> ruleIds = extractRuleIds(integrationSource);
        List<String> ruleBodies =
                ruleIds.isEmpty() ? List.of() : fetchRuleBodies(integrationId, ruleIds, space);

        // 4. Extract normalized event for SAP evaluation
        String normalizedEventJson = (String) engineResult.remove("_normalized_event");

        // 5. Evaluate rules
        Map<String, Object> sapResult;
        if (ruleBodies.isEmpty()) {
            sapResult = createEmptySapResult();
        } else {
            String saResultJson = this.securityAnalytics.evaluateRules(normalizedEventJson, ruleBodies);
            try {
                sapResult = mapper.readValue(saResultJson, Map.class);
            } catch (Exception e) {
                sapResult = createErrorSapResult();
            }
        }

        return buildCombinedResponse(engineResult, sapResult);
    }

    /**
     * Executes engine normalization only, returning the engine's response directly.
     *
     * @param enginePayload the payload to send to the Engine
     * @return a {@link RestResponse} with the engine normalization result
     */
    public RestResponse executeNormalization(ObjectNode enginePayload) {
        try {
            RestResponse engineResponse = this.engine.logtest(enginePayload);
            return engineResponse.parseMessageAsJson();
        } catch (Exception e) {
            log.error("Engine normalization failed: {}", e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Executes detection only: looks up integration, fetches rules, evaluates via SAP.
     *
     * @param integrationId the integration document ID to look up
     * @param space the space to search in (test or standard)
     * @param inputEvent the normalized event JSON object to evaluate
     * @return a {@link RestResponse} with the SAP detection result
     */
    public RestResponse executeDetection(String integrationId, Space space, JsonNode inputEvent) {
        ObjectMapper mapper = new ObjectMapper();

        // 1. Look up integration
        SearchResponse integrationSearchResponse;
        try {
            integrationSearchResponse =
                    this.client
                            .prepareSearch(Constants.INDEX_INTEGRATIONS)
                            .setSource(
                                    new SearchSourceBuilder()
                                            .query(
                                                    QueryBuilders.boolQuery()
                                                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, integrationId))
                                                            .must(
                                                                    QueryBuilders.termQuery(
                                                                            Constants.Q_SPACE_NAME, space.toString())))
                                            .size(1))
                            .get();
        } catch (Exception e) {
            log.error("Failed to look up integration [{}]: {}", integrationId, e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (Objects.requireNonNull(integrationSearchResponse.getHits().getTotalHits()).value() == 0) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INTEGRATION_NOT_FOUND, integrationId, space),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. Fetch rule IDs from integration
        Map<String, Object> integrationSource =
                integrationSearchResponse.getHits().getAt(0).getSourceAsMap();
        List<String> ruleIds = extractRuleIds(integrationSource);
        List<String> ruleBodies =
                ruleIds.isEmpty() ? List.of() : fetchRuleBodies(integrationId, ruleIds, space);

        // 3. Convert input event to JSON string for SAP
        String eventJson = inputEvent.toString();

        // 4. Evaluate rules
        Map<String, Object> sapResult;
        if (ruleBodies.isEmpty()) {
            sapResult = createEmptySapResult();
        } else {
            String saResultJson = this.securityAnalytics.evaluateRules(eventJson, ruleBodies);
            try {
                sapResult = mapper.readValue(saResultJson, Map.class);
            } catch (Exception e) {
                sapResult = createErrorSapResult();
            }
        }

        try {
            String json = mapper.writeValueAsString(sapResult);
            return new RestResponse(json, RestStatus.OK.getStatus()).parseMessageAsJson();
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Sends the event payload to the Wazuh Engine and builds the engine result map.
     *
     * <p>On success, the normalized event JSON is stored under the internal key {@code
     * _normalized_event} for later SAP evaluation. This key is removed before building the final
     * response.
     *
     * @param enginePayload the payload to send to the Engine
     * @return engine result map with status, processed event or error details
     */
    private Map<String, Object> executeEngine(ObjectNode enginePayload) {
        Map<String, Object> engineResult = new LinkedHashMap<>();
        ObjectMapper mapper = new ObjectMapper();

        RestResponse engineResponse;
        try {
            engineResponse = this.engine.logtest(enginePayload);
        } catch (Exception e) {
            return buildEngineErrorResult("ENGINE_ERROR", e.getMessage(), engineResult);
        }

        try {
            JsonNode engineJson = mapper.readTree(engineResponse.getMessage());

            if (engineResponse.getStatus() >= 400) {
                String errorMsg =
                        engineJson.has("message")
                                ? engineJson.get("message").asText()
                                : engineResponse.getMessage();
                return buildEngineErrorResult("ENGINE_ERROR", errorMsg, engineResult);
            }

            Map<String, Object> processedEvent = mapper.readValue(engineResponse.getMessage(), Map.class);
            engineResult.putAll(processedEvent);

            engineResult.put(
                    "_normalized_event", extractNormalizedEvent(engineJson, engineResponse.getMessage()));

        } catch (Exception e) {
            return buildEngineErrorResult("PARSE_ERROR", engineResponse.getMessage(), engineResult);
        }

        return engineResult;
    }

    /**
     * Extracts the normalized event from the Engine response JSON. Looks for the {@code output} field
     * at the top level. Falls back to the raw engine response message if not found.
     *
     * @param engineJson the parsed Engine response
     * @param rawResponse the raw Engine response
     * @return the normalized event as a JSON string
     */
    private String extractNormalizedEvent(JsonNode engineJson, String rawResponse) {
        JsonNode directOutput = engineJson.at("/output");
        if (!directOutput.isMissingNode()) {
            return directOutput.isTextual() ? directOutput.asText() : directOutput.toString();
        }

        return rawResponse;
    }

    /**
     * Populates the engine result map with error details.
     *
     * @param code the error code (e.g., {@code "ENGINE_ERROR"} or {@code "PARSE_ERROR"})
     * @param message the error message
     * @param engineResult the result map to populate
     * @return the populated engine result map
     */
    private Map<String, Object> buildEngineErrorResult(
            String code, String message, Map<String, Object> engineResult) {
        Map<String, Object> errorDetail = new LinkedHashMap<>();
        errorDetail.put("message", message);
        errorDetail.put("code", code);
        engineResult.put(Constants.KEY_STATUS, "error");
        engineResult.put("error", errorDetail);
        return engineResult;
    }

    /**
     * Builds the final combined JSON response with engine and SAP results.
     *
     * @param engineResult the engine result map
     * @param sapResult the Security Analytics result map
     * @return a {@link RestResponse} with HTTP 200 and the combined JSON, or 500 on serialization
     *     failure
     */
    private RestResponse buildCombinedResponse(
            Map<String, Object> engineResult, Map<String, Object> sapResult) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> combinedResponse = new LinkedHashMap<>();
        combinedResponse.put("normalization", engineResult);
        combinedResponse.put("detection", sapResult);

        try {
            String json = mapper.writeValueAsString(combinedResponse);
            return new RestResponse(json, RestStatus.OK.getStatus()).parseMessageAsJson();
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Extracts rule IDs from the integration document. Rules are stored as a list under the {@code
     * document.rules} field.
     *
     * @param integrationSource the integration document source map
     * @return list of rule document IDs (may be empty if the integration has no rules)
     */
    private List<String> extractRuleIds(Map<String, Object> integrationSource) {
        List<String> ruleIds = new ArrayList<>();
        Object documentObj = integrationSource.get(Constants.KEY_DOCUMENT);
        if (documentObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> document = (Map<String, Object>) documentObj;
            Object rulesObj = document.get(Constants.KEY_RULES);
            if (rulesObj instanceof List) {
                for (Object ruleId : (List<?>) rulesObj) {
                    ruleIds.add(ruleId.toString());
                }
            }
        }

        return ruleIds;
    }

    /**
     * Fetches Sigma rule bodies from the {@code wazuh-threatintel-rules} index by document ID.
     *
     * <p>Each rule document's {@code document} field contains the raw Sigma rule content (JSON or
     * YAML). If a rule cannot be fetched, it is silently skipped.
     *
     * @param integrationId the integration ID (used for logging on failure)
     * @param ruleIds the list of rule document IDs to fetch
     * @param space the space to filter rules by
     * @return list of rule body strings (may be smaller than ruleIds if some rules were not found)
     */
    private List<String> fetchRuleBodies(String integrationId, List<String> ruleIds, Space space) {
        ObjectMapper mapper = new ObjectMapper();
        List<String> ruleBodies = new ArrayList<>();
        try {
            SearchResponse rulesSearchResponse =
                    this.client
                            .prepareSearch(Constants.INDEX_RULES)
                            .setSource(
                                    new SearchSourceBuilder()
                                            .query(
                                                    QueryBuilders.boolQuery()
                                                            .must(QueryBuilders.termsQuery(Constants.Q_DOCUMENT_ID, ruleIds))
                                                            .must(
                                                                    QueryBuilders.termQuery(
                                                                            Constants.Q_SPACE_NAME, space.toString())))
                                            .size(ruleIds.size()))
                            .get();
            for (SearchHit hit : rulesSearchResponse.getHits().getHits()) {
                Map<String, Object> ruleSource = hit.getSourceAsMap();
                Object ruleDocObj = ruleSource.get(Constants.KEY_DOCUMENT);
                if (ruleDocObj != null) {
                    ruleBodies.add(
                            ruleDocObj instanceof Map
                                    ? mapper.writeValueAsString(ruleDocObj)
                                    : ruleDocObj.toString());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to fetch rules for integration [{}]: {}", integrationId, e.getMessage());
        }
        return ruleBodies;
    }

    /**
     * Executes engine normalization only, skipping integration lookup and rule evaluation. Used when
     * no integration ID is provided in the request.
     *
     * @param enginePayload the payload to send to the Engine
     * @return a {@link RestResponse} with engine results and a skipped detection section
     */
    private RestResponse executeEngineOnly(ObjectNode enginePayload) {
        Map<String, Object> engineResult = executeEngine(enginePayload);
        engineResult.remove("_normalized_event");

        Map<String, Object> sapResult = new LinkedHashMap<>();
        sapResult.put(Constants.KEY_STATUS, "skipped");
        sapResult.put("reason", "integration field not provided");

        return buildCombinedResponse(engineResult, sapResult);
    }

    /** Creates a success SAP result with zero matches. */
    private Map<String, Object> createEmptySapResult() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(Constants.KEY_STATUS, "success");
        response.put("rules_evaluated", 0);
        response.put("rules_matched", 0);
        response.put("matches", List.of());
        return response;
    }

    /** Creates an error SAP result. */
    private Map<String, Object> createErrorSapResult() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(Constants.KEY_STATUS, "error");
        response.put("rules_evaluated", 0);
        response.put("rules_matched", 0);
        response.put("matches", List.of());
        return response;
    }
}
