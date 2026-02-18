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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.RestRequest.Method;
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

    // ========================================================================
    // Integration operations
    // ========================================================================

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
            executeAsync(WIndexIntegrationAction.INSTANCE, request, listener);
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
    public WIndexIntegrationRequest buildIntegrationRequest(
            JsonNode doc, Space space, Method method) {
        if (!doc.has(Constants.KEY_ID)) {
            log.warn("Integration document missing ID. Skipping upsert.");
            return null;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String name = doc.has(Constants.KEY_TITLE) ? doc.get(Constants.KEY_TITLE).asText() : "";
        String description =
                doc.has(Constants.KEY_DESCRIPTION) ? doc.get(Constants.KEY_DESCRIPTION).asText() : "";
        String category = this.formatCategory(doc, false);

        log.info("Creating/Updating Integration [{}] in SAP - ID: {}", name, id);

        return new WIndexIntegrationRequest(
                id,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                method,
                new Integration(
                        id,
                        null,
                        name,
                        description,
                        category,
                        space.asSecurityAnalyticsSource(),
                        new HashMap<>()));
    }

    @Override
    public void deleteIntegration(String id, boolean isStandard) {
        try {
            if (isStandard) {
                this.deleteDetector(id);
            }
            this.client
                    .execute(
                            WDeleteIntegrationAction.INSTANCE,
                            new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();
            log.info("Integration [{}] deleted successfully.", id);
        } catch (Exception e) {
            log.error("Failed to delete Integration [{}]: {}", id, e.getMessage());
            throw new OpenSearchException("Failed to delete Integration", e.getMessage());
        }
    }

    @Override
    public void deleteIntegrationAsync(
            String id, boolean isStandard, ActionListener<? extends ActionResponse> listener) {
        if (isStandard) {
            // Delete detector first, then delete integration on success.
            this.deleteDetectorAsync(
                    id,
                    ActionListener.wrap(
                            detectorResponse -> {
                                log.info("Detector [{}] deleted. Now deleting integration.", id);
                                executeAsync(
                                        WDeleteIntegrationAction.INSTANCE,
                                        new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                                        listener);
                            },
                            listener::onFailure));
        } else {
            executeAsync(
                    WDeleteIntegrationAction.INSTANCE,
                    new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                    listener);
        }
    }

    // ========================================================================
    // Rule operations
    // ========================================================================

    @Override
    public void upsertRule(JsonNode doc, Space space, Method method) {
        if (!doc.has(Constants.KEY_ID)) {
            log.warn("Rule document missing ID. Skipping upsert.");
            return;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String product = ContentIndex.extractProduct(doc);
        String body = doc.toString();

        log.info("Creating/Updating Rule [{}] in SAP", id);

        if (space != Space.STANDARD) {
            this.client
                    .execute(
                            WIndexCustomRuleAction.INSTANCE,
                            new WIndexCustomRuleRequest(
                                    id, WriteRequest.RefreshPolicy.IMMEDIATE, product, method, body, true))
                    .actionGet();
        } else {
            this.client
                    .execute(
                            WIndexRuleAction.INSTANCE,
                            new WIndexRuleRequest(
                                    id, WriteRequest.RefreshPolicy.IMMEDIATE, product, method, body, true))
                    .actionGet();
        }
    }

    @Override
    public void upsertRuleAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener) {
        if (!doc.has(Constants.KEY_ID)) {
            log.warn("Rule document missing ID. Skipping upsert.");
            return;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String product = ContentIndex.extractProduct(doc);
        String body = doc.toString();

        log.info("Async creating/updating Rule [{}] in SAP", id);

        if (space != Space.STANDARD) {
            executeAsync(
                    WIndexCustomRuleAction.INSTANCE,
                    new WIndexCustomRuleRequest(
                            id, WriteRequest.RefreshPolicy.IMMEDIATE, product, method, body, true),
                    listener);
        } else {
            executeAsync(
                    WIndexRuleAction.INSTANCE,
                    new WIndexRuleRequest(
                            id, WriteRequest.RefreshPolicy.IMMEDIATE, product, method, body, true),
                    listener);
        }
    }

    @Override
    public void deleteRule(String id, boolean isStandard) {
        try {
            if (isStandard) {
                log.info("Deleting Standard Rule [{}] from SAP", id);
                this.client
                        .execute(
                                WDeleteRuleAction.INSTANCE,
                                new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true))
                        .actionGet();
            } else {
                log.info("Deleting Custom Rule [{}] from SAP", id);
                this.client
                        .execute(
                                WDeleteCustomRuleAction.INSTANCE,
                                new WDeleteCustomRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true))
                        .actionGet();
            }
            log.info("Rule [{}] deleted successfully.", id);
        } catch (Exception e) {
            log.error("Failed to delete Rule [{}]: {}", id, e.getMessage());
            throw new OpenSearchException("Failed to delete Rule", e.getMessage());
        }
    }

    @Override
    public void deleteRuleAsync(
            String id, boolean isStandard, ActionListener<? extends ActionResponse> listener) {
        if (isStandard) {
            log.info("Async deleting Standard Rule [{}] from SAP", id);
            executeAsync(
                    WDeleteRuleAction.INSTANCE,
                    new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true),
                    listener);
        } else {
            log.info("Async deleting Custom Rule [{}] from SAP", id);
            executeAsync(
                    WDeleteCustomRuleAction.INSTANCE,
                    new WDeleteCustomRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true),
                    listener);
        }
    }

    // ========================================================================
    // Detector operations
    // ========================================================================

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
            executeAsync(WIndexDetectorAction.INSTANCE, request, listener);
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
        if (!doc.has(Constants.KEY_ID)) {
            log.warn("Detector document missing ID. Skipping upsert.");
            return null;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String name = doc.has(Constants.KEY_TITLE) ? doc.get(Constants.KEY_TITLE).asText() : "";
        String category = this.formatCategory(doc, rawCategory);
        List<String> rules = new ArrayList<>();

        if (doc.has(Constants.KEY_RULES)) {
            doc.get(Constants.KEY_RULES).forEach(item -> rules.add(item.asText()));
        }
        if (rules.isEmpty()) {
            return null;
        }

        log.info("Creating/Updating Detector [{}] for Integration", name);

        return new WIndexDetectorRequest(
                id, name, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
    }

    @Override
    public void deleteDetector(String id) {
        try {
            log.info("Deleting Detector [{}] from SAP", id);
            this.client
                    .execute(
                            WDeleteDetectorAction.INSTANCE,
                            new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();
            log.info("Detector [{}] deleted successfully.", id);
        } catch (Exception e) {
            log.error("Failed to delete Detector [{}]: {}", id, e.getMessage());
            throw new OpenSearchException("Failed to delete Detector", e.getMessage());
        }
    }

    @Override
    public void deleteDetectorAsync(String id, ActionListener<? extends ActionResponse> listener) {
        log.info("Async deleting Detector [{}] from SAP", id);
        executeAsync(
                WDeleteDetectorAction.INSTANCE,
                new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                listener);
    }

    // ========================================================================
    // Utility methods
    // ========================================================================

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

        // TODO remove when CTI applies the changes to the categorization.
        // Remove subcategory. Currently only cloud-services has subcategories (aws, gcp, azure).
        if (rawCategory.contains("cloud-services")) {
            rawCategory = rawCategory.substring(0, 14);
        }
        return Arrays.stream(rawCategory.split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }
}
