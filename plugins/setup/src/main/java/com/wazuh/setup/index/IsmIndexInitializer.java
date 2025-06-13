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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

/** Class to manage the Command Manager index and index template. */
public final class IsmIndexInitializer implements IndexInitializer {

    private static final Logger log = LogManager.getLogger(IsmIndexInitializer.class);

    private Client client;
    private ClusterService clusterService;
    private static IsmIndexInitializer INSTANCE;
    private IndexUtils indexUtils;

    private IsmIndexInitializer() {}

    /**
     * Default Singleton instance access method.
     *
     * @return the singleton instance.
     */
    public static IsmIndexInitializer getInstance() {
        if (IsmIndexInitializer.INSTANCE == null) {
            INSTANCE = new IsmIndexInitializer();
        }
        return INSTANCE;
    }

    /**
     * Sets the OpenSearch client.
     *
     * @param client OpenSearch client.
     * @return this instance for method chaining.
     */
    public IsmIndexInitializer setClient(Client client) {
        this.client = client;
        return this;
    }

    /**
     * Sets the ClusterService.
     *
     * @param clusterService OpenSearch ClusterService.
     * @return this instance for method chaining.
     */
    public IsmIndexInitializer setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
        return this;
    }

    /**
     * Sets the IndexUtils instance.
     *
     * @param indexUtils the IndexUtils instance to set.
     * @return this instance for method chaining.
     */
    public IsmIndexInitializer setIndexUtils(IndexUtils indexUtils) {
        this.indexUtils = indexUtils;
        return this;
    }

    /**
     * Checks if the command index exists.
     *
     * @param indexName the name of the index to check.
     * @return whether the internal Command Manager's index exists.
     */
    public boolean ismIndexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    /**
     * Creates the .opendistro-ism-config along with its mappings and settings and indexes the Wazuh
     * rollover policy.
     *
     * @param indexStrategySelector the index to initialize.
     */
    @Override
    public void initIndex(IndexStrategySelector indexStrategySelector) {
        this.createIsmIndex(indexStrategySelector);
        this.indexPolicy(indexStrategySelector);
    }

    private void indexPolicy(IndexStrategySelector indexStrategySelector) {
        try {
            Map<String, Object> policy;
            policy = this.indexUtils.fromFile(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID + ".json");

            IndexRequest indexRequest =
                    new IndexRequest(indexStrategySelector.getIndexName())
                            .index(indexStrategySelector.getIndexName())
                            .id(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID)
                            .source(policy, MediaTypeRegistry.JSON);

            client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT);
            log.info("Indexed Wazuh rollover policy into {} index", indexStrategySelector.getIndexName());
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Policy already exists, skipping creation: {}", e.getMessage());
        }
    }

    /**
     * Puts the .opendistro-ism-config template into the cluster and creates the index
     *
     * @param indexStrategySelector the indexStrategySelector to create
     */
    private void createIsmIndex(IndexStrategySelector indexStrategySelector) {
        if (this.ismIndexExists(indexStrategySelector.getIndexName())) {
            log.info("{} index exists, skipping", indexStrategySelector.getIndexName());
            return;
        }
        Map<String, Object> template;
        log.info("Attempting to create {} index", indexStrategySelector.getIndexName());
        try {
            template = this.indexUtils.fromFile(indexStrategySelector.getTemplateFileName());
            this.client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(indexStrategySelector.getIndexName())
                                    .mapping(this.indexUtils.get(template, "mappings"))
                                    .settings(this.indexUtils.get(template, "settings")))
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("Successfully created {} index", indexStrategySelector.getIndexName());
        } catch (IOException e) {
            log.error("Failed loading ISM index from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Index already exists, skipping creation: {}", e.getMessage());
        }
    }
}
