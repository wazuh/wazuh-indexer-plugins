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

import com.google.gson.JsonObject;
import com.sun.jdi.InternalException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.transport.client.Client;

import java.util.*;

import com.wazuh.securityanalytics.action.*;
import com.wazuh.securityanalytics.model.Integration;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * Implementation of the SecurityAnalyticsService. Handles the direct execution of SAP actions using
 * the OpenSearch Client.
 */
public class SecurityAnalyticsServiceImpl implements SecurityAnalyticsService {
    private static final Logger log = LogManager.getLogger(SecurityAnalyticsServiceImpl.class);

    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_ID_KEY = "id";
    private static final String JSON_CATEGORY_KEY = "category";
    private static final String JSON_PRODUCT_KEY = "product";
    private static final String JSON_RULES_KEY = "rules";
    private static final String JSON_LOGSOURCE_KEY = "logsource";

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
    public void upsertIntegration(JsonObject doc) {
        try {
            if (!doc.has(JSON_DOCUMENT_KEY)) {
                return;
            }
            JsonObject innerDoc = doc.getAsJsonObject(JSON_DOCUMENT_KEY);
            String id = innerDoc.get(JSON_ID_KEY).getAsString();
            String name = innerDoc.get("title").getAsString();
            String description = innerDoc.get("description").getAsString();
            String category = this.getCategory(innerDoc, false);
            List<String> rules = new ArrayList<>();

            if (innerDoc.has(JSON_RULES_KEY)) {
                innerDoc
                        .get(JSON_RULES_KEY)
                        .getAsJsonArray()
                        .forEach(item -> rules.add(item.getAsString()));
            }
            if (rules.isEmpty()) {
                return;
            }

            log.info("Creating/Updating Integration [{}] in SAP - ID: {}", name, id);

            WIndexIntegrationRequest request =
                    new WIndexIntegrationRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            POST,
                            new Integration(
                                    id, null, name, description, category, "Sigma", rules, new HashMap<>()));
            this.client.execute(
                    WIndexIntegrationAction.INSTANCE,
                    request,
                    new ActionListener<WIndexIntegrationResponse>() {
                        @Override
                        public void onResponse(WIndexIntegrationResponse wIndexIntegrationResponse) {
                            log.info("Integration [{}] synced successfully.", name);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to upsert Integration: {}", e.getMessage());
                        }
                    });

        } catch (Exception e) {
            log.error("Failed to upsert Integration: {}", e.getMessage());
        }
    }

    @Override
    public void deleteIntegration(String id) {
        try {
            // Delete detector first
            this.deleteDetector(id);

            // Then delete integration
            log.info("Deleting Integration [{}] from SAP", id);
            this.client.execute(
                    WDeleteIntegrationAction.INSTANCE,
                    new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                    new ActionListener<WDeleteIntegrationResponse>() {
                        @Override
                        public void onResponse(WDeleteIntegrationResponse wDeleteIntegrationResponse) {
                            log.info("Integration [{}] deleted successfully.", id);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to delete Integration [{}]: {}", id, e.getMessage());
                        }
                    });
        } catch (Exception e) {
            log.error("Failed to delete Integration [{}]: {}", id, e.getMessage());
            throw new InternalException("Failed to delete Integration");
        }
    }

    @Override
    public void upsertRule(JsonObject doc) {
        try {
            if (!doc.has(JSON_DOCUMENT_KEY)) {
                return;
            }
            JsonObject innerDoc = doc.getAsJsonObject(JSON_DOCUMENT_KEY);
            String id = innerDoc.get(JSON_ID_KEY).getAsString();

            String product = "linux";
            if (innerDoc.has(JSON_LOGSOURCE_KEY)) {
                JsonObject logsource = innerDoc.getAsJsonObject(JSON_LOGSOURCE_KEY);
                if (logsource.has(JSON_PRODUCT_KEY)) {
                    product = logsource.get(JSON_PRODUCT_KEY).getAsString();
                } else if (logsource.has(JSON_CATEGORY_KEY)) {
                    product = logsource.get(JSON_CATEGORY_KEY).getAsString();
                }
            }

            log.info("Creating/Updating Rule [{}] in SAP", id);

            WIndexRuleRequest ruleRequest =
                    new WIndexRuleRequest(
                            id, WriteRequest.RefreshPolicy.IMMEDIATE, product, POST, innerDoc.toString(), true);
            this.client.execute(
                    WIndexRuleAction.INSTANCE,
                    ruleRequest,
                    new ActionListener<WIndexRuleResponse>() {
                        @Override
                        public void onResponse(WIndexRuleResponse wIndexRuleResponse) {
                            log.info("Rule [{}] synced successfully.", id);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to upsert Rule: {}", e.getMessage());
                        }
                    });

        } catch (Exception e) {
            log.error("Failed to upsert Rule: {}", e.getMessage());
        }
    }

    @Override
    public void deleteRule(String id) {
        try {
            log.info("Deleting Rule [{}] from SAP", id);
            this.client.execute(
                    WDeleteRuleAction.INSTANCE,
                    new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true),
                    new ActionListener<WDeleteRuleResponse>() {
                        @Override
                        public void onResponse(WDeleteRuleResponse wDeleteRuleResponse) {
                            log.info("Rule [{}] deleted successfully.", id);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to delete Rule [{}]: {}", id, e.getMessage());
                        }
                    });
        } catch (Exception e) {
            log.error("Failed to delete Rule [{}]: {}", id, e.getMessage());
        }
    }

    @Override
    public void upsertDetector(JsonObject doc, boolean rawCategory) {
        try {
            if (!doc.has(JSON_DOCUMENT_KEY)) {
                return;
            }
            JsonObject innerDoc = doc.getAsJsonObject(JSON_DOCUMENT_KEY);
            String id = innerDoc.get(JSON_ID_KEY).getAsString();
            String name = innerDoc.has("title") ? innerDoc.get("title").getAsString() : "";
            String category = this.getCategory(innerDoc, rawCategory);
            List<String> rules = new ArrayList<>();

            if (innerDoc.has(JSON_RULES_KEY)) {
                innerDoc
                        .get(JSON_RULES_KEY)
                        .getAsJsonArray()
                        .forEach(item -> rules.add(item.getAsString()));
            }
            if (rules.isEmpty()) {
                return;
            }

            log.info("Creating/Updating Detector [{}] for Integration", name);

            WIndexDetectorRequest request =
                    new WIndexDetectorRequest(
                            id, name, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client.execute(
                    WIndexDetectorAction.INSTANCE,
                    request,
                    new ActionListener<WIndexDetectorResponse>() {
                        @Override
                        public void onResponse(WIndexDetectorResponse wIndexDetectorResponse) {
                            log.info("Detector [{}] synced successfully.", name);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to upsert Detector: {}", e.getMessage());
                        }
                    });
            log.info("Detector [{}] synced successfully.", name);

        } catch (Exception e) {
            log.error("Failed to upsert Detector: {}", e.getMessage());
        }
    }

    @Override
    public void deleteDetector(String id) {
        try {
            log.info("Deleting Detector [{}] from SAP", id);
            this.client.execute(
                    WDeleteDetectorAction.INSTANCE,
                    new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE),
                    new ActionListener<WDeleteDetectorResponse>() {
                        @Override
                        public void onResponse(WDeleteDetectorResponse wDeleteDetectorResponse) {
                            log.info("Detector [{}] deleted successfully.", id);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to delete Detector [{}]: {}", id, e.getMessage());
                        }
                    });
        } catch (Exception e) {
            log.error("Failed to delete Detector [{}]: {}", id, e.getMessage());
        }
    }

    /**
     * Retrieves the category from the document.
     *
     * @param doc The JSON document.
     * @param raw Whether to return the raw category string.
     * @return The category string.
     */
    private String getCategory(JsonObject doc, boolean raw) {
        String rawCategory = doc.get(JSON_CATEGORY_KEY).getAsString();

        if (raw) {
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
