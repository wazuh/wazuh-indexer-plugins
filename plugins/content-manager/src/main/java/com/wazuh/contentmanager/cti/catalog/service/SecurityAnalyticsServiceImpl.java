/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.*;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.securityanalytics.action.*;
import com.wazuh.securityanalytics.model.Integration;

/**
 * Implementation of the SecurityAnalyticsService. Handles the direct execution of SAP actions using
 * the OpenSearch Client, providing both synchronous and asynchronous methods.
 */
public class SecurityAnalyticsServiceImpl implements SecurityAnalyticsService {
    private static final Logger log = LogManager.getLogger(SecurityAnalyticsServiceImpl.class);

    private final Client client;

    /**
     * Constructs a SecurityAnalyticsServiceImpl.
     *
     * @param client The OpenSearch client used to execute SAP actions.
     */
    public SecurityAnalyticsServiceImpl(Client client) {
        this.client = client;
    }

    @Override
    public void upsertIntegration(JsonNode doc, Space space, Method method) {
        WIndexIntegrationRequest request = this.buildIntegrationRequest(doc, space, method);
        if (request != null) {
            this.client.execute(WIndexIntegrationAction.INSTANCE, request).actionGet();
        }
    }

    @Override
    public void upsertIntegrationAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener) {
        WIndexIntegrationRequest request = this.buildIntegrationRequest(doc, space, method);
        if (request != null) {
            this.executeAsync(WIndexIntegrationAction.INSTANCE, request, listener);
        } else {
            listener.onResponse(null);
        }
    }

    /**
     * Builds a {@link WIndexIntegrationRequest} from the given document and parameters.
     *
     * @param doc The JSON document containing the integration data.
     * @param space The space of the integration.
     * @param method The HTTP method (POST/PUT).
     * @return The built request, or {@code null} if the document is missing an ID.
     */
    private WIndexIntegrationRequest buildIntegrationRequest(
            JsonNode doc, Space space, Method method) {
        // Fail-fast.
        if (!doc.has(Constants.KEY_ID)) {
            log.error(Constants.E_LOG_MISSING_FIELD, Constants.KEY_ID);
            return null;
        }
        if (!doc.has(Constants.KEY_METADATA) && !doc.get(Constants.KEY_METADATA).isObject()) {
            log.error(Constants.E_LOG_MISSING_OBJECT, Constants.KEY_METADATA);
            return null;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        JsonNode metadata = doc.get(Constants.KEY_METADATA);
        String name =
                metadata.has(Constants.KEY_TITLE) ? metadata.get(Constants.KEY_TITLE).asText() : "";
        String description =
                metadata.has(Constants.KEY_DESCRIPTION)
                        ? metadata.get(Constants.KEY_DESCRIPTION).asText()
                        : "";
        String category = this.formatCategory(doc, false);

        log.info(Constants.I_LOG_SAP_SEND, "integration", name, id);
        return new WIndexIntegrationRequest(
                id,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                method,
                new Integration(
                        null,
                        null,
                        name,
                        description,
                        category,
                        space.asSecurityAnalyticsSource(),
                        new HashMap<>(),
                        id));
    }

    @Override
    public void deleteIntegration(String id, Space space) {
        try {
            if (Space.STANDARD.equals(space)) {
                this.deleteDetector(id);
            }
            // Use document.id + source=<space> (via space.asSecurityAnalyticsSource()) to find and delete
            // the document in Security Analytics.
            String source = space.asSecurityAnalyticsSource();
            this.client
                    .execute(
                            WDeleteIntegrationAction.INSTANCE,
                            new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, id, source))
                    .actionGet();
            log.info(Constants.I_LOG_SAP_DELETED, "Integration", id, ", source=" + source);
        } catch (Exception e) {
            String message =
                    String.format(
                            Locale.ROOT,
                            "Failed to delete %s with id [%s] in space [%s]: %s",
                            "integration",
                            id,
                            space.asSecurityAnalyticsSource(),
                            e.getMessage());
            log.error(message);
            throw new OpenSearchException(message);
        }
    }

    @Override
    public void deleteIntegrationAsync(
            String id, Space space, ActionListener<? extends ActionResponse> listener) {
        String source = space.asSecurityAnalyticsSource();
        if (Space.STANDARD.equals(space)) {
            // Delete detector first, then delete integration on success.
            this.deleteDetectorAsync(
                    id,
                    ActionListener.wrap(
                            detectorResponse -> {
                                log.info("Detector [{}] deleted. Now deleting integration.", id);
                                this.executeAsync(
                                        WDeleteIntegrationAction.INSTANCE,
                                        new WDeleteIntegrationRequest(
                                                id, WriteRequest.RefreshPolicy.IMMEDIATE, id, source),
                                        listener);
                            },
                            listener::onFailure));
        } else {
            this.executeAsync(
                    WDeleteIntegrationAction.INSTANCE,
                    new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, id, source),
                    listener);
        }
    }

    @Override
    public void upsertRule(JsonNode doc, Space space, Method method) {
        if (!doc.has(Constants.KEY_ID)) {
            log.error(Constants.E_LOG_MISSING_FIELD, Constants.KEY_ID);
            return;
        }
        if (!doc.has(Constants.KEY_METADATA) && !doc.get(Constants.KEY_METADATA).isObject()) {
            log.error(Constants.E_LOG_MISSING_OBJECT, Constants.KEY_METADATA);
            return;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String title = doc.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText("");
        String product = ContentIndex.extractProduct(doc);
        String body = doc.toString();
        String sourceName = space.asSecurityAnalyticsSource();

        log.info(Constants.I_LOG_SAP_SEND, "rule", title, id);
        if (space != Space.STANDARD) {
            this.client
                    .execute(
                            WIndexCustomRuleAction.INSTANCE,
                            new WIndexCustomRuleRequest(
                                    id,
                                    WriteRequest.RefreshPolicy.IMMEDIATE,
                                    product,
                                    method,
                                    body,
                                    true,
                                    id,
                                    sourceName))
                    .actionGet();
        } else {
            this.client
                    .execute(
                            WIndexRuleAction.INSTANCE,
                            new WIndexRuleRequest(
                                    id,
                                    WriteRequest.RefreshPolicy.IMMEDIATE,
                                    product,
                                    method,
                                    body,
                                    true,
                                    id,
                                    sourceName))
                    .actionGet();
        }
    }

    @Override
    public void upsertRuleAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener) {
        if (!doc.has(Constants.KEY_ID)) {
            log.error(Constants.E_LOG_MISSING_FIELD, Constants.KEY_ID);
            return;
        }
        if (!doc.has(Constants.KEY_METADATA) && !doc.get(Constants.KEY_METADATA).isObject()) {
            log.error(Constants.E_LOG_MISSING_OBJECT, Constants.KEY_METADATA);
            return;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String title = doc.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText("");
        String product = ContentIndex.extractProduct(doc);
        String body = doc.toString();
        String sourceName = space.asSecurityAnalyticsSource();

        log.info(Constants.I_LOG_SAP_SEND, "rule", title, id);
        if (space != Space.STANDARD) {
            this.executeAsync(
                    WIndexCustomRuleAction.INSTANCE,
                    new WIndexCustomRuleRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            product,
                            method,
                            body,
                            true,
                            id,
                            sourceName),
                    listener);
        } else {
            this.executeAsync(
                    WIndexRuleAction.INSTANCE,
                    new WIndexRuleRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            product,
                            method,
                            body,
                            true,
                            id,
                            sourceName),
                    listener);
        }
    }

    @Override
    public void deleteRule(String id, Space space) {
        String source = space.asSecurityAnalyticsSource();
        try {
            if (Space.STANDARD.equals(space)) {
                this.client
                        .execute(
                                WDeleteRuleAction.INSTANCE,
                                new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true, id, source))
                        .actionGet();
            } else {
                this.client
                        .execute(
                                WDeleteCustomRuleAction.INSTANCE,
                                new WDeleteCustomRuleRequest(
                                        id, WriteRequest.RefreshPolicy.IMMEDIATE, true, id, source))
                        .actionGet();
            }
            log.info(Constants.I_LOG_SAP_DELETED, "Rule", id, ", source=" + source);
        } catch (Exception e) {
            String message =
                    String.format(
                            Locale.ROOT,
                            "Failed to delete %s with id [%s] in space [%s]: %s",
                            "rule",
                            id,
                            space.asSecurityAnalyticsSource(),
                            e.getMessage());
            log.error(message);
            throw new OpenSearchException(message);
        }
    }

    @Override
    public void deleteRuleAsync(
            String id, Space space, ActionListener<? extends ActionResponse> listener) {
        String source = space.asSecurityAnalyticsSource();
        if (Space.STANDARD.equals(space)) {
            this.executeAsync(
                    WDeleteRuleAction.INSTANCE,
                    new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true, id, source),
                    listener);
        } else {
            this.executeAsync(
                    WDeleteCustomRuleAction.INSTANCE,
                    new WDeleteCustomRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true, id, source),
                    listener);
        }
        log.info(Constants.I_LOG_SAP_DELETE_ASYNC, "rule", id, ", source=" + source);
    }

    @Override
    public void upsertDetector(JsonNode doc, boolean rawCategory, Method method) {
        WIndexDetectorRequest request = this.buildDetectorRequest(doc, rawCategory);
        if (request != null) {
            this.client.execute(WIndexDetectorAction.INSTANCE, request).actionGet();
        }
    }

    @Override
    public void upsertDetectorAsync(
            JsonNode doc,
            boolean rawCategory,
            Method method,
            ActionListener<? extends ActionResponse> listener) {
        WIndexDetectorRequest request = this.buildDetectorRequest(doc, rawCategory);
        if (request != null) {
            this.executeAsync(WIndexDetectorAction.INSTANCE, request, listener);
        } else {
            listener.onResponse(null);
        }
    }

    /**
     * Builds a {@link WIndexDetectorRequest} from the given document.
     *
     * @param doc The JSON document containing the detector data.
     * @param rawCategory Whether to use the raw category string (true) or formatted/pretty (false).
     * @return The built request, or {@code null} if the document is missing an ID or has no rules.
     */
    public WIndexDetectorRequest buildDetectorRequest(JsonNode doc, boolean rawCategory) {
        // Fail-fast.
        if (!doc.has(Constants.KEY_ID)) {
            log.error(Constants.E_LOG_MISSING_FIELD, Constants.KEY_ID);
            return null;
        }
        if (!doc.has(Constants.KEY_METADATA) && !doc.get(Constants.KEY_METADATA).isObject()) {
            log.error(Constants.E_LOG_MISSING_OBJECT, Constants.KEY_METADATA);
            return null;
        }
        if (!doc.has(Constants.KEY_RULES)) {
            log.error(Constants.E_LOG_MISSING_FIELD, Constants.KEY_RULES);
            return null;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        JsonNode metadata = doc.get(Constants.KEY_METADATA);
        String title =
                metadata.has(Constants.KEY_TITLE) ? metadata.get(Constants.KEY_TITLE).asText() : "";
        String category = this.formatCategory(doc, rawCategory);
        List<String> rules = fetchEnabledRuleIds(doc.get(Constants.KEY_RULES));
        if (rules.isEmpty()) {
            log.debug("Detector [{}] has no enabled rules. Skipping creation.", id);
            return null;
        }

        log.info(Constants.I_LOG_SAP_SEND, "detector", title, id);
        return new WIndexDetectorRequest(
                id, title, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
    }

    /**
     * Queries the {@code wazuh-threatintel-rules} index for documents whose {@code _id} matches the
     * given rule IDs and whose {@code document.enabled} is {@code true}. Filtering is done entirely
     * using an IDs query combined with a term filter; no source is fetched — only the matching {@code
     * _id} values are collected.
     *
     * @param rulesNode the JSON array of candidate rule IDs from the integration document
     * @return list of enabled rule IDs (may be empty)
     */
    private List<String> fetchEnabledRuleIds(JsonNode rulesNode) {
        List<String> candidateIds = new ArrayList<>();
        rulesNode.forEach(item -> candidateIds.add(item.asText()));
        if (candidateIds.isEmpty()) {
            return candidateIds;
        }

        try {
            SearchResponse response =
                    this.client
                            .prepareSearch(Constants.INDEX_RULES)
                            .setSource(
                                    new SearchSourceBuilder()
                                            .query(
                                                    QueryBuilders.boolQuery()
                                                            .must(
                                                                    QueryBuilders.idsQuery()
                                                                            .addIds(candidateIds.toArray(String[]::new)))
                                                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ENABLED, true)))
                                            .fetchSource(false)
                                            .size(candidateIds.size()))
                            .get();
            List<String> enabledIds = new ArrayList<>();
            for (SearchHit hit : response.getHits().getHits()) {
                enabledIds.add(hit.getId());
            }
            int filtered = candidateIds.size() - enabledIds.size();
            if (filtered > 0) {
                log.info("Filtered {} disabled rule(s) from detector rule list", filtered);
            }
            return enabledIds;
        } catch (Exception e) {
            log.error("Failed to fetch enabled rule IDs: {}", e.getMessage());
            return candidateIds;
        }
    }

    @Override
    public void deleteDetector(String id) {
        try {
            this.client
                    .execute(
                            WDeleteDetectorAction.INSTANCE,
                            new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();
            log.info(Constants.I_LOG_SAP_DELETED, "Detector", id, "");
        } catch (Exception e) {
            String message =
                    String.format(
                            Locale.ROOT, "Failed to delete %s with id [%s]: %s", "detector", id, e.getMessage());
            log.error(message);
            throw new OpenSearchException(message);
        }
    }

    @Override
    public void deleteDetectorAsync(String id, ActionListener<? extends ActionResponse> listener) {
        this.executeAsync(
                WDeleteDetectorAction.INSTANCE,
                new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                listener);
        log.info(Constants.I_LOG_SAP_DELETE_ASYNC, "detector", id, "");
    }

    @Override
    public void deleteSpaceResources(Space space) {
        // Translate STANDARD to SIGMA for SAP operations, matching the source name used
        // when the resources were originally indexed.
        Space sapSpace = (space == Space.STANDARD) ? Space.SIGMA : space;

        try {
            String source = sapSpace.asSecurityAnalyticsSource();
            WDeleteSpaceResourcesResponse response =
                    this.client
                            .execute(
                                    WDeleteSpaceResourcesAction.INSTANCE,
                                    new WDeleteSpaceResourcesRequest(source, WriteRequest.RefreshPolicy.IMMEDIATE))
                            .actionGet();

            if (response.hasFailures()) {
                log.warn(
                        "Partial failures deleting SAP resources for space [{}]: {}",
                        space,
                        response.getFailureMessage());
            }

            log.info(
                    "Deleted [{}] integrations and [{}] rules from Security Analytics for space [{}]",
                    response.getDeletedIntegrations(),
                    response.getDeletedRules(),
                    space);
        } catch (Exception e) {
            String message =
                    String.format(
                            Locale.ROOT,
                            "Failed to delete Security Analytics resources for space [%s]: %s",
                            space,
                            e.getMessage());
            log.error(message);
            throw new OpenSearchException(message, e);
        }
    }

    /**
     * Executes an action asynchronously, bridging between the wildcard listener from the interface
     * and the concrete response type required by {@link Client#execute}.
     *
     * @param <Req> The request type.
     * @param <Resp> The response type.
     * @param action The action to execute.
     * @param request The request to send.
     * @param listener The listener to notify on completion.
     */
    @SuppressWarnings("unchecked")
    private <Req extends ActionRequest, Resp extends ActionResponse> void executeAsync(
            ActionType<Resp> action, Req request, ActionListener<? extends ActionResponse> listener) {
        this.client.execute(action, request, (ActionListener<Resp>) listener);
    }

    @Override
    public String evaluateRules(String eventJson, java.util.List<String> ruleBodies) {
        try {
            WEvaluateRulesRequest request = new WEvaluateRulesRequest(eventJson, ruleBodies);
            WEvaluateRulesResponse response =
                    this.client.execute(WEvaluateRulesAction.INSTANCE, request).actionGet();
            return response.getResultJson();
        } catch (Exception e) {
            log.error("Failed to evaluate rules via SAP transport action.", e);
            return "{\"status\":\"error\",\"rules_evaluated\":0,\"rules_matched\":0,\"matches\":[]}";
        }
    }

    /**
     * Formats category strings from CTI documents. Transforms raw category identifiers into
     * human-readable format. This method was moved from CategoryFormatter.
     *
     * @param doc The JSON document containing the category field.
     * @param isDetector If true, returns the raw category without formatting.
     * @return The formatted category string, or the raw category for detectors.
     */
    private String formatCategory(JsonNode doc, boolean isDetector) {
        if (!doc.has(Constants.KEY_CATEGORY)) {
            return "";
        }
        String rawCategory = doc.get(Constants.KEY_CATEGORY).asText();

        // Do not pretty print category for detectors
        if (isDetector) {
            return rawCategory;
        }

        return Arrays.stream(rawCategory.split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }
}
