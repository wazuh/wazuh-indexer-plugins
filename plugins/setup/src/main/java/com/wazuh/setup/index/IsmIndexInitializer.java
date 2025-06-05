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
    public static Map<String, Object> POLICY;
    private static IsmIndexInitializer INSTANCE;

    private IsmIndexInitializer() {}

    public static IsmIndexInitializer getInstance() {
        if (IsmIndexInitializer.INSTANCE == null) {
            INSTANCE = new IsmIndexInitializer();
        }
        return INSTANCE;
    }

    public IsmIndexInitializer setClient(Client client) {
        this.client = client;
        return this;
    }

    public IsmIndexInitializer setRoutingTable(RoutingTable routingTable) {
        this.routingTable = routingTable;
        return this;
    }

    /**
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean ismIndexExists(Index index) {
        return this.routingTable.hasIndex(index.getIndexName());
    }

    /**
     * Indexes the Wazuh rollover policy into the .opendistro-ism-config index. If the index does not
     * exist, it will create it.
     */
    @Override
    public void initIndex(Index index) {
        this.createIsmIndex(index);

        try {
            POLICY = IndexTemplateUtils.fromFile(SetupPlugin.POLICY_ID + ".json");
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
            return;
        }

        IndexRequest indexRequest =
                new IndexRequest(index.getIndexName())
                        .index(index.getIndexName())
                        .id(SetupPlugin.POLICY_ID)
                        .source(POLICY, MediaTypeRegistry.JSON);

        client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT);
        log.info("Indexed Wazuh rollover policy into {} index", index.getIndexName());
    }

    /** Puts the .opendistro-ism-config template into the cluster and creates the index */
    public void createIsmIndex(Index index) {
        if (ismIndexExists(index)) {
            log.info("{} Index exists, skipping", index.getIndexName());
            return;
        }
        Map<String, Object> template;
        log.info("Attempting to create {} index", index.getIndexName());
        try {
            template = IndexTemplateUtils.fromFile(index.getTemplate());
            client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(index.getIndexName())
                                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                                    .settings(IndexTemplateUtils.get(template, "settings")))
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("Successfully created {} index", index.getIndexName());
        } catch (IOException e) {
            log.error("Failed loading ISM index template from file: {}", e.getMessage());
        }
    }
}
