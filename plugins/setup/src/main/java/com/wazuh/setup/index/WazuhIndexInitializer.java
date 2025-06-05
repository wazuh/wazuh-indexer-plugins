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
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexTemplateUtils;

public final class WazuhIndexInitializer implements IndexInitializer {

    private static final Logger log = LogManager.getLogger(WazuhIndexInitializer.class);
    private Client client;
    private RoutingTable routingTable;
    private static WazuhIndexInitializer INSTANCE;

    private WazuhIndexInitializer() {}

    public static WazuhIndexInitializer getInstance() {
        if (WazuhIndexInitializer.INSTANCE == null) {
            INSTANCE = new WazuhIndexInitializer();
        }
        return INSTANCE;
    }

    public WazuhIndexInitializer setClient(Client client) {
        this.client = client;
        return this;
    }

    public WazuhIndexInitializer setRoutingTable(RoutingTable routingTable) {
        this.routingTable = routingTable;
        return this;
    }

    /**
     * Inserts an index template
     *
     * @param index: The Index object to load
     */
    @SuppressWarnings("unchecked")
    private void putTemplate(Index index) {
        try {
            Map<String, Object> template = IndexTemplateUtils.fromFile(index.getTemplate());

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(IndexTemplateUtils.get(template, "mappings"))
                            .settings(IndexTemplateUtils.get(template, "settings"))
                            .name(index.getTemplate().replace(".json", ""))
                            .patterns((List<String>) template.get("index_patterns"));

            this.client
                    .admin()
                    .indices()
                    .putTemplate(putIndexTemplateRequest)
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("Index template {} created successfully", index.getTemplate());
        } catch (NullPointerException e) {
            log.error("Error reading template file {}.", index.getTemplate());
        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", index.getTemplate());
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", index.getTemplate());
        }
    }

    /**
     * Creates an index
     *
     * @param index the index to create
     */
    private void putIndex(Index index) {
        if (indexExists(index.getIndexName())) {
            log.error("Index {} already exists. Skipping.", index.getIndexName());
            return;
        }
        CreateIndexRequest request = new CreateIndexRequest(index.getIndexName());
        if (index.getAlias().isPresent()) {
            request.alias(new Alias(index.getAlias().get()).writeIndex(true));
        }
        this.client.admin().indices().create(request).actionGet(SetupPlugin.TIMEOUT);
        log.info("Index {} created successfully", index.getIndexName());
    }

    @Override
    public void initIndex(Index index) {
        putTemplate(index);
        putIndex(index);
    }

    /**
     * Returns whether the index exists
     *
     * @param indexName the name of the index to check
     * @return true if the index exists on the cluster, false otherwise
     */
    public boolean indexExists(String indexName) {
        return this.routingTable.hasIndex(indexName);
    }
}
