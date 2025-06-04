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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.utils.IndexTemplateUtils;

/**
 * This class contains the logic to create the index templates and the indices required by Wazuh.
 */
public class WazuhIndices implements ClusterStateListener {
    private static final Logger log = LogManager.getLogger(WazuhIndices.class);

    private final Client client;
    private ClusterState clusterState;

    /**
     * Constructor
     *
     * @param client Client
     */
    public WazuhIndices(Client client) {
        this.client = client;
    }

    /**
     * Inserts an index template
     *
     * @param templateName: The name if the index template to load
     */
    @SuppressWarnings("unchecked")
    public void putTemplate(String templateName) {
        try {
            Map<String, Object> template = IndexTemplateUtils.fromFile(templateName);

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(IndexTemplateUtils.get(template, "mappings"))
                            .settings(IndexTemplateUtils.get(template, "settings"))
                            .name(templateName.replace(".json", ""))
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
                                    log.info("Error creating index template {}: {}", templateName, e.getMessage());
                                }
                            });

        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", templateName);
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", templateName);
        }
    }

    /**
     * Creates an index
     *
     * @param index the index to create
     */
    public void putIndex(Index index) {
        try {
            if (!indexExists(index.getIndexName())) {
                CreateIndexRequest request = new CreateIndexRequest(index.getIndexName());
                if (index.getAlias().isPresent()) {
                    request.alias(new Alias(index.getAlias().get()).writeIndex(true));
                }
                this.client
                        .admin()
                        .indices()
                        .create(
                                request,
                                new ActionListener<CreateIndexResponse>() {
                                    @Override
                                    public void onResponse(CreateIndexResponse createIndexResponse) {
                                        log.info(
                                                "Index created successfully: {} {}",
                                                index.getIndexName(),
                                                createIndexResponse.isAcknowledged());
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        log.error(
                                                "Failed to create index {}: {}", index.getIndexName(), e.getMessage());
                                    }
                                });
            }
        } catch (ResourceAlreadyExistsException e) {
            log.error("Index {} already exists. Skipping.", index.getIndexName());
        }
    }

    /**
     * Returns whether the index exists
     *
     * @param indexName the name of the index to check
     * @return true if the index exists on the cluster, false otherwise
     */
    public boolean indexExists(String indexName) {
        return this.clusterState.getRoutingTable().hasIndex(indexName);
    }

    /**
     * Initializes the Wazuh indices by creating the necessary index templates and indices. This
     * method should be called when the plugin is started.
     */
    public void initialize() {
        // 1. Read index templates from files
        // 2. Upsert index template
        // 3. Create index
        IsmIndex ismIndex = new IsmIndex(this.client, this.clusterState);
        ismIndex.indexPolicy();
        for (IndexTemplate value : IndexTemplate.values()) {
            this.putTemplate(value.getTemplateName());
        }
        for (Index value : Index.values()) {
            this.putIndex(value);
        }
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        setState(event.state());
        if (event.localNodeClusterManager()) {
            this.initialize();
        }
    }

    private void setState(ClusterState clusterState) {
        this.clusterState = clusterState;
    }
}
