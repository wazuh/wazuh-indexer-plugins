/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.setup.index;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.client.Client;

import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.IndexTemplateUtils;

/**
 * This class contains the logic to create the index templates and the indices required by Wazuh.
 */
public class WazuhIndices {
    private static final Logger log = LogManager.getLogger(WazuhIndices.class);
    private final int timeout;

    /**
     * | Key | value | | ------------------- | ---------- | | Index template name | [index name, ] |
     * Map where the key is the index template name, and the value is a list of index names
     */
    public final Map<String, List<String>> indexTemplates = new HashMap<>();

    private final Client client;
    private final ClusterService clusterService;

    /**
     * Constructor
     *
     * @param client Client
     * @param clusterService object containing the cluster service
     * @param pluginSettings object containing the plugin settings
     */
    public WazuhIndices(Client client, ClusterService clusterService, PluginSettings pluginSettings) {
        this.client = client;
        this.clusterService = clusterService;
        this.timeout = pluginSettings.getTimeout();

        // Create Index Templates - Indices map
        this.indexTemplates.put("index-template-alerts", List.of("wazuh-alerts-5.x-0001", "wazuh-archives-5.x-0001"));
        this.indexTemplates.put("index-template-fim-files", List.of("wazuh-states-fim-files"));
        this.indexTemplates.put(
                "index-template-fim-registries", List.of("wazuh-states-fim-registries"));
        this.indexTemplates.put("index-template-hardware", List.of("wazuh-states-inventory-hardware"));
        this.indexTemplates.put("index-template-hotfixes", List.of("wazuh-states-inventory-hotfixes"));
        this.indexTemplates.put(
                "index-template-interfaces", List.of("wazuh-states-inventory-interfaces"));
        this.indexTemplates.put("index-template-networks", List.of("wazuh-states-inventory-networks"));
        this.indexTemplates.put("index-template-packages", List.of("wazuh-states-inventory-packages"));
        this.indexTemplates.put("index-template-ports", List.of("wazuh-states-inventory-ports"));
        this.indexTemplates.put(
                "index-template-processes", List.of("wazuh-states-inventory-processes"));
        this.indexTemplates.put(
                "index-template-protocols", List.of("wazuh-states-inventory-protocols"));
        this.indexTemplates.put("index-template-system", List.of("wazuh-states-inventory-system"));
        this.indexTemplates.put(
                "index-template-vulnerabilities", List.of("wazuh-states-vulnerabilities"));
    }

    /**
     * Inserts an index template
     *
     * @param templateName: The name if the index template to load
     */
    @SuppressWarnings("unchecked")
    public void putTemplate(String templateName) {
        try {
            Map<String, Object> template = IndexTemplateUtils.fromFile(templateName + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(IndexTemplateUtils.get(template, "mappings"))
                            .settings(IndexTemplateUtils.get(template, "settings"))
                            .name(templateName)
                            .patterns((List<String>) template.get("index_patterns"));

            this.client
                    .admin()
                    .indices()
                    .putTemplate(
                            putIndexTemplateRequest,
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                                    log.info(
                                            "Index template created successfully: {} {}",
                                            templateName,
                                            acknowledgedResponse.isAcknowledged());
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error("Error creating index template [{}]: {}", templateName, e.getMessage());
                                }
                            });

        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", templateName);
        }
    }

    /**
     * Creates an index
     *
     * @param indexName Name of the index to be created
     */
    public void putIndex(String indexName) {
        if (!indexExists(indexName)) {
            CreateIndexRequest request = new CreateIndexRequest(indexName);
            this.client
                    .admin()
                    .indices()
                    .create(
                            request,
                            new ActionListener<>() {
                                @Override
                                public void onResponse(CreateIndexResponse createIndexResponse) {
                                    log.info(
                                            "Index created successfully: {} {}",
                                            createIndexResponse.index(),
                                            createIndexResponse.isAcknowledged());
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.info("Error creating index [{}]: {}", indexName, e.getMessage());
                                }
                            });
        }
    }

    /**
     * Returns whether the index exists
     *
     * @param indexName the name of the index to check
     * @return true if the index exists on the cluster, false otherwise
     */
    public boolean indexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    /** Creates each index template and index in {@link #indexTemplates}. */
    public void initialize() {
        // 1. Read index templates from files
        // 2. Upsert index template
        // 3. Create index
        this.indexTemplates.forEach(
                (template, indices) -> {
                    this.putTemplate(template);
                    indices.forEach(this::putIndex);
                });
    }
}
