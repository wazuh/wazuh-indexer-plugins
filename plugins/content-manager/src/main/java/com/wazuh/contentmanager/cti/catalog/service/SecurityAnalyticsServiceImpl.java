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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.transport.client.Client;

import java.util.*;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.CategoryFormatter;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.securityanalytics.action.*;
import com.wazuh.securityanalytics.model.Integration;

/**
 * Implementation of the SecurityAnalyticsService. Handles the direct execution of SAP actions using
 * the OpenSearch Client.
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
        String category = CategoryFormatter.format(doc, false);

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
    public void deleteIntegration(String id) {
        try {
            // Delete detector first
            this.deleteDetector(id);

            // Then delete integration
            log.info("Deleting Integration [{}] from SAP", id);
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
    public void upsertRule(JsonNode doc, Space space) {
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
                                    id, WriteRequest.RefreshPolicy.IMMEDIATE, product, Method.POST, body, true))
                    .actionGet();
        } else {
            this.client
                    .execute(
                            WIndexRuleAction.INSTANCE,
                            new WIndexRuleRequest(
                                    id, WriteRequest.RefreshPolicy.IMMEDIATE, product, Method.POST, body, true))
                    .actionGet();
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
    public void upsertDetector(JsonNode doc, boolean rawCategory) {
        WIndexDetectorRequest request = this.buildDetectorRequest(doc, rawCategory);
        if (request != null) {
            this.client.execute(WIndexDetectorAction.INSTANCE, request).actionGet();
        }
    }

    public WIndexDetectorRequest buildDetectorRequest(JsonNode doc, boolean rawCategory) {
        if (!doc.has(Constants.KEY_ID)) {
            log.warn("Detector document missing ID. Skipping upsert.");
            return null;
        }

        String id = doc.get(Constants.KEY_ID).asText();
        String name = doc.has(Constants.KEY_TITLE) ? doc.get(Constants.KEY_TITLE).asText() : "";
        String category = CategoryFormatter.format(doc, rawCategory);
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
}
