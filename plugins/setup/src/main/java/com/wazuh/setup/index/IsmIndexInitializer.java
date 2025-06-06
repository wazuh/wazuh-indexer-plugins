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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexTemplateUtils;

/** Class to manage the Command Manager index and index template. */
public final class IsmIndexInitializer implements IndexInitializer {

    private static final Logger log = LogManager.getLogger(IsmIndexInitializer.class);

    private Client client;
    private RoutingTable routingTable;
    private static IsmIndexInitializer INSTANCE;

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
     * Sets the routing table.
     *
     * @param routingTable OpenSearch routing table.
     * @return this instance for method chaining.
     */
    public IsmIndexInitializer setRoutingTable(RoutingTable routingTable) {
        this.routingTable = routingTable;
        return this;
    }

    /**
     * Checks if the command indexStrategySelector exists.
     *
     * @param indexStrategySelector the indexStrategySelector to check.
     * @return whether the internal Command Manager's indexStrategySelector exists.
     */
    public boolean ismIndexExists(IndexStrategySelector indexStrategySelector) {
        return this.routingTable.hasIndex(indexStrategySelector.getIndexName());
    }

    /**
     * Creates the .opendistro-ism-config along with its mappings and settings and indexes the Wazuh
     * rollover policy.
     *
     * @param indexStrategySelector the indexStrategySelector to initialize.
     */
    @Override
    public void initIndex(IndexStrategySelector indexStrategySelector) {
        this.createIsmIndex(indexStrategySelector);

        Map<String, Object> template;
        try {
            template = IndexTemplateUtils.fromFile(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID + ".json");
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
            return;
        }

        IndexRequest indexRequest =
                new IndexRequest(indexStrategySelector.getIndexName())
                        .index(indexStrategySelector.getIndexName())
                        .id(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID)
                        .source(template, MediaTypeRegistry.JSON);

        client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT);
        log.info(
                "Indexed Wazuh rollover policy into {} indexStrategySelector",
                indexStrategySelector.getIndexName());
    }

    /**
     * Puts the .opendistro-ism-config template into the cluster and creates the indexStrategySelector
     *
     * @param indexStrategySelector the indexStrategySelector to create
     */
    public void createIsmIndex(IndexStrategySelector indexStrategySelector) {
        if (ismIndexExists(indexStrategySelector)) {
            log.info("{} IndexStrategySelector exists, skipping", indexStrategySelector.getIndexName());
            return;
        }
        Map<String, Object> template;
        log.info("Attempting to create {} indexStrategySelector", indexStrategySelector.getIndexName());
        try {
            template = IndexTemplateUtils.fromFile(indexStrategySelector.getTemplate());
            client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(indexStrategySelector.getIndexName())
                                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                                    .settings(IndexTemplateUtils.get(template, "settings")))
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info(
                    "Successfully created {} indexStrategySelector", indexStrategySelector.getIndexName());
        } catch (IOException e) {
            log.error("Failed loading ISM indexStrategySelector template from file: {}", e.getMessage());
        }
    }
}
