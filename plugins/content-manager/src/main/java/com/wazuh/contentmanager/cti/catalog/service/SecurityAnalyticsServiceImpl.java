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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
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
    public void upsertIntegration(JsonObject doc, Space space, Method method) {
        try {
            if (!doc.has(Constants.KEY_ID)) {
                log.warn("Integration document missing ID. Skipping upsert.");
                return;
            }

            String id = doc.get(Constants.KEY_ID).getAsString();
            String name = doc.has(Constants.KEY_TITLE) ? doc.get(Constants.KEY_TITLE).getAsString() : "";
            String description =
                    doc.has(Constants.KEY_DESCRIPTION)
                            ? doc.get(Constants.KEY_DESCRIPTION).getAsString()
                            : "";
            String category = CategoryFormatter.format(doc, false);

            log.info("Creating/Updating Integration [{}] in SAP - ID: {}", name, id);

            WIndexIntegrationRequest request =
                    new WIndexIntegrationRequest(
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
            throw new OpenSearchException("Failed to delete Integration");
        }
    }

    @Override
    public void upsertRule(JsonObject doc, Space space) {
        try {
            if (!doc.has(Constants.KEY_ID)) {
                log.warn("Rule document missing ID. Skipping upsert.");
                return;
            }

            String id = doc.get(Constants.KEY_ID).getAsString();
            String product = ContentIndex.extractProduct(doc);

            log.info("Creating/Updating Rule [{}] in SAP", id);

            if (space != Space.STANDARD) {
                WIndexCustomRuleRequest ruleRequest =
                        new WIndexCustomRuleRequest(
                                id,
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                product,
                                Method.POST,
                                doc.toString(),
                                true);
                this.client.execute(
                        WIndexCustomRuleAction.INSTANCE,
                        ruleRequest,
                        new ActionListener<WIndexRuleResponse>() {
                            @Override
                            public void onResponse(WIndexRuleResponse wIndexRuleResponse) {
                                log.info("Custom Rule [{}] synced successfully.", id);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("Failed to upsert Custom Rule: {}", e.getMessage());
                            }
                        });
            } else {
                WIndexRuleRequest ruleRequest =
                        new WIndexRuleRequest(
                                id,
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                product,
                                Method.POST,
                                doc.toString(),
                                true);
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
            }

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
            if (!doc.has(Constants.KEY_ID)) {
                log.warn("Detector document missing ID. Skipping upsert.");
                return;
            }

            String id = doc.get(Constants.KEY_ID).getAsString();
            String name = doc.has(Constants.KEY_TITLE) ? doc.get(Constants.KEY_TITLE).getAsString() : "";
            String category = CategoryFormatter.format(doc, rawCategory);
            List<String> rules = new ArrayList<>();

            if (doc.has(Constants.KEY_RULES)) {
                doc.get(Constants.KEY_RULES)
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
}
