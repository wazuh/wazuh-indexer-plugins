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
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

/** Class to manage Wazuh indices and index templates. */
public final class WazuhIndicesInitializer implements IndexInitializer {

    private static final Logger log = LogManager.getLogger(WazuhIndicesInitializer.class);
    private Client client;
    private ClusterService clusterService;
    private IndexUtils indexUtils;
    private static WazuhIndicesInitializer INSTANCE;

    private WazuhIndicesInitializer() {}

    /**
     * Default Singleton instance access method.
     *
     * @return the singleton instance.
     */
    public static WazuhIndicesInitializer getInstance() {
        if (WazuhIndicesInitializer.INSTANCE == null) {
            INSTANCE = new WazuhIndicesInitializer();
        }
        return INSTANCE;
    }

    /**
     * Sets the OpenSearch client.
     *
     * @param client OpenSearch client.
     * @return this instance for method chaining.
     */
    public WazuhIndicesInitializer setClient(Client client) {
        this.client = client;
        return this;
    }

    /**
     * Sets the ClusterService object.
     *
     * @param clusterService OpenSearch ClusterService.
     * @return this instance for method chaining.
     */
    public WazuhIndicesInitializer setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
        return this;
    }

    /**
     * Sets the IndexUtils instance.
     *
     * @param indexUtils IndexUtils instance.
     * @return this instance for method chaining.
     */
    public WazuhIndicesInitializer setIndexUtils(IndexUtils indexUtils) {
        this.indexUtils = indexUtils;
        return this;
    }

    /**
     * Inserts an indexStrategySelector template
     *
     * @param indexStrategySelector: The IndexStrategySelector object to load
     */
    private void putTemplate(IndexStrategySelector indexStrategySelector) {
        try {
            Map<String, Object> template =
                    this.indexUtils.fromFile(indexStrategySelector.getTemplateFileName());

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(this.indexUtils.get(template, "mappings"))
                            .settings(this.indexUtils.get(template, "settings"))
                            .name(indexStrategySelector.getTemplateFileName().replace(".json", ""))
                            .patterns((List<String>) template.get("index_patterns"));

            this.client
                    .admin()
                    .indices()
                    .putTemplate(putIndexTemplateRequest)
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info(
                    "IndexStrategySelector template {} created successfully",
                    indexStrategySelector.getTemplateFileName());
        } catch (NullPointerException e) {
            log.error("Error reading template file {}.", indexStrategySelector.getTemplateFileName());
        } catch (IOException e) {
            log.error(
                    "Error reading indexStrategySelector template from filesystem {}",
                    indexStrategySelector.getTemplateFileName());
        } catch (ResourceAlreadyExistsException e) {
            log.info(
                    "Index template {} already exists. Skipping.",
                    indexStrategySelector.getTemplateFileName());
        }
    }

    /**
     * Creates an indexStrategySelector
     *
     * @param indexStrategySelector the indexStrategySelector to create
     */
    private void putIndex(IndexStrategySelector indexStrategySelector) {
        if (indexExists(indexStrategySelector.getIndexName())) {
            log.info("Index {} already exists. Skipping.", indexStrategySelector.getIndexName());
            return;
        }
        CreateIndexRequest request = new CreateIndexRequest(indexStrategySelector.getIndexName());
        if (indexStrategySelector.getAlias().isPresent()) {
            request.alias(new Alias(indexStrategySelector.getAlias().get()).writeIndex(true));
        }
        this.client.admin().indices().create(request).actionGet(SetupPlugin.TIMEOUT);
        log.info("Index {} created successfully", indexStrategySelector.getIndexName());
    }

    /**
     * Initializes the indexStrategySelector by creating the indexStrategySelector template and the
     * indexStrategySelector itself.
     *
     * @param indexStrategySelector the indexStrategySelector to initialize
     */
    @Override
    public void initIndex(IndexStrategySelector indexStrategySelector) {
        putTemplate(indexStrategySelector);
        putIndex(indexStrategySelector);
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
}
