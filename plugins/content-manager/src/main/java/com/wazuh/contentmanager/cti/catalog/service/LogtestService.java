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
import org.opensearch.core.action.ActionListener;
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
     * @param listener the listener to be notified with the combined engine and SAP results
     */
    public void executeLogtest(
            String integrationId,
            Space space,
            ObjectNode enginePayload,
            ActionListener<RestResponse> listener) {
        if (integrationId == null) {
            listener.onResponse(executeEngineOnly(enginePayload));
            return;
        }

        this.client
                .prepareSearch(Constants.INDEX_INTEGRATIONS)
                .setSource(
                        new SearchSourceBuilder()
                                .query(
                                        QueryBuilders.boolQuery()
                                                .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, integrationId))
                                                .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString())))
                                .size(1))
                .execute(
                        ActionListener.wrap(
                                integrationSearchResponse -> {
                                    if (Objects.requireNonNull(integrationSearchResponse.getHits().getTotalHits())
                                                    .value()
                                            == 0) {
                                        listener.onResponse(
                                                new RestResponse(
                                                        String.format(
                                                                Locale.ROOT,
                                                                Constants.E_400_INTEGRATION_NOT_FOUND,
                                                                integrationId,
                                                                space),
                                                        RestStatus.BAD_REQUEST.getStatus()));
                                        return;
                                    }

                                    Map<String, Object> engineResult = executeEngine(enginePayload);
                                    if ("error".equals(engineResult.get(Constants.KEY_STATUS))) {
                                        Map<String, Object> sapResult = new LinkedHashMap<>();
                                        sapResult.put(Constants.KEY_STATUS, "skipped");
                                        sapResult.put("reason", "Engine processing failed");
                                        listener.onResponse(buildCombinedResponse(engineResult, sapResult));
                                        return;
                                    }

                                    Map<String, Object> integrationSource =
                                            integrationSearchResponse.getHits().getAt(0).getSourceAsMap();
                                    List<String> ruleIds = extractRuleIds(integrationSource);
                                    String normalizedEventJson = (String) engineResult.remove("_normalized_event");

                                    if (ruleIds.isEmpty()) {
                                        listener.onResponse(
                                                buildCombinedResponse(engineResult, createEmptySapResult()));
                                        return;
                                    }

                                    fetchRuleBodiesAsync(
                                            integrationId,
                                            ruleIds,
                                            space,
                                            ActionListener.wrap(
                                                    ruleBodies ->
                                                            evaluateAndRespond(
                                                                    engineResult, normalizedEventJson, ruleBodies, listener),
                                                    e -> {
                                                        log.warn(
                                                                "Failed to fetch rules for" + " integration [{}]: {}",
                                                                integrationId,
                                                                e.getMessage());
                                                        listener.onResponse(
                                                                buildCombinedResponse(engineResult, createEmptySapResult()));
                                                    }));
                                },
                                e -> {
                                    log.error(
                                            "Failed to look up integration [{}]: {}", integrationId, e.getMessage());
                                    listener.onResponse(
                                            new RestResponse(
                                                    Constants.E_500_INTERNAL_SERVER_ERROR,
                                                    RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                                }));
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
     * @param space the space to search in (test, standard, or custom)
     * @param inputEvent the normalized event JSON object to evaluate
     * @param listener the listener to be notified with the SAP detection result
     */
    public void executeDetectionAsync(
            String integrationId,
            Space space,
            JsonNode inputEvent,
            ActionListener<RestResponse> listener) {
        String eventJson = inputEvent.toString();

        this.client
                .prepareSearch(Constants.INDEX_INTEGRATIONS)
                .setSource(
                        new SearchSourceBuilder()
                                .query(
                                        QueryBuilders.boolQuery()
                                                .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, integrationId))
                                                .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString())))
                                .size(1))
                .execute(
                        ActionListener.wrap(
                                integrationSearchResponse -> {
                                    if (Objects.requireNonNull(integrationSearchResponse.getHits().getTotalHits())
                                                    .value()
                                            == 0) {
                                        listener.onResponse(
                                                new RestResponse(
                                                        String.format(
                                                                Locale.ROOT,
                                                                Constants.E_400_INTEGRATION_NOT_FOUND,
                                                                integrationId,
                                                                space),
                                                        RestStatus.BAD_REQUEST.getStatus()));
                                        return;
                                    }

                                    Map<String, Object> integrationSource =
                                            integrationSearchResponse.getHits().getAt(0).getSourceAsMap();
                                    List<String> ruleIds = extractRuleIds(integrationSource);

                                    if (ruleIds.isEmpty()) {
                                        listener.onResponse(buildDetectionResponse(createEmptySapResult()));
                                        return;
                                    }

                                    fetchRuleBodiesAsync(
                                            integrationId,
                                            ruleIds,
                                            space,
                                            ActionListener.wrap(
                                                    ruleBodies -> evaluateDetectionRules(eventJson, ruleBodies, listener),
                                                    e -> {
                                                        log.warn(
                                                                "Failed to fetch rules for" + " integration [{}]: {}",
                                                                integrationId,
                                                                e.getMessage());
                                                        listener.onResponse(buildDetectionResponse(createEmptySapResult()));
                                                    }));
                                },
                                e -> {
                                    log.error(
                                            "Failed to look up integration [{}]: {}", integrationId, e.getMessage());
                                    listener.onResponse(
                                            new RestResponse(
                                                    Constants.E_500_INTERNAL_SERVER_ERROR,
                                                    RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                                }));
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

    private void fetchRuleBodiesAsync(
            String integrationId,
            List<String> ruleIds,
            Space space,
            ActionListener<List<String>> listener) {
        this.client
                .prepareSearch(Constants.INDEX_RULES)
                .setSource(
                        new SearchSourceBuilder()
                                .query(
                                        QueryBuilders.boolQuery()
                                                .must(QueryBuilders.termsQuery(Constants.Q_DOCUMENT_ID, ruleIds))
                                                .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()))
                                                .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ENABLED, true)))
                                .size(ruleIds.size()))
                .execute(
                        ActionListener.wrap(
                                rulesSearchResponse -> {
                                    ObjectMapper mapper = new ObjectMapper();
                                    List<String> ruleBodies = new ArrayList<>();
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
                                    listener.onResponse(ruleBodies);
                                },
                                listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private void evaluateAndRespond(
            Map<String, Object> engineResult,
            String normalizedEventJson,
            List<String> ruleBodies,
            ActionListener<RestResponse> listener) {
        if (ruleBodies.isEmpty()) {
            listener.onResponse(buildCombinedResponse(engineResult, createEmptySapResult()));
            return;
        }

        this.securityAnalytics.evaluateRulesAsync(
                normalizedEventJson,
                ruleBodies,
                ActionListener.wrap(
                        saResultJson -> {
                            ObjectMapper mapper = new ObjectMapper();
                            Map<String, Object> sapResult;
                            try {
                                sapResult = mapper.readValue(saResultJson, Map.class);
                            } catch (Exception e) {
                                sapResult = createErrorSapResult();
                            }
                            listener.onResponse(buildCombinedResponse(engineResult, sapResult));
                        },
                        e -> {
                            log.error("Failed to evaluate rules: {}", e.getMessage());
                            listener.onResponse(buildCombinedResponse(engineResult, createErrorSapResult()));
                        }));
    }

    @SuppressWarnings("unchecked")
    private void evaluateDetectionRules(
            String eventJson, List<String> ruleBodies, ActionListener<RestResponse> listener) {
        if (ruleBodies.isEmpty()) {
            listener.onResponse(buildDetectionResponse(createEmptySapResult()));
            return;
        }

        this.securityAnalytics.evaluateRulesAsync(
                eventJson,
                ruleBodies,
                ActionListener.wrap(
                        saResultJson -> {
                            ObjectMapper mapper = new ObjectMapper();
                            Map<String, Object> sapResult;
                            try {
                                sapResult = mapper.readValue(saResultJson, Map.class);
                            } catch (Exception e) {
                                sapResult = createErrorSapResult();
                            }
                            listener.onResponse(buildDetectionResponse(sapResult));
                        },
                        e -> {
                            log.error("Failed to evaluate rules: {}", e.getMessage());
                            listener.onResponse(buildDetectionResponse(createErrorSapResult()));
                        }));
    }

    private RestResponse buildDetectionResponse(Map<String, Object> sapResult) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            String json = mapper.writeValueAsString(sapResult);
            return new RestResponse(json, RestStatus.OK.getStatus()).parseMessageAsJson();
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
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
        sapResult.put("reason", "'integration' field not provided");

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
