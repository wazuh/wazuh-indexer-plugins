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
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

public abstract class Index implements IndexInitializer {

    protected Client client;
    protected ClusterService clusterService;
    protected IndexUtils indexUtils;
    protected String index;
    protected String template;

    private static final Logger log = LogManager.getLogger(Index.class);

    Index(String index, String template) {}

    public IndexInitializer setClient(Client client) {
        this.client = client;
        return this;
    }

    public IndexInitializer setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
        return this;
    }

    public IndexInitializer setIndexUtils(IndexUtils indexUtils) {
        this.indexUtils = indexUtils;
        return this;
    }

    public boolean indexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    public void initialize() {}

    @Override
    public void createIndex(String index) {
        if (indexExists(index)) {
            log.info("Index {} already exists. Skipping.", index);
            return;
        }
        CreateIndexRequest request = new CreateIndexRequest(index);
        this.client.admin().indices().create(request).actionGet(SetupPlugin.TIMEOUT);
        log.info("Index {} created successfully", index);
    }

    @Override
    public void createTemplate(String templateName) {
        try {
            Map<String, Object> template = this.indexUtils.fromFile(templateName + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(this.indexUtils.get(template, "mappings"))
                            .settings(this.indexUtils.get(template, "settings"))
                            .name(templateName)
                            .patterns((List<String>) template.get("index_patterns"));

            this.client
                    .admin()
                    .indices()
                    .putTemplate(putIndexTemplateRequest)
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("IndexStrategySelector template {} created successfully", templateName);
        } catch (NullPointerException e) {
            log.error("Error reading template file {}.", templateName);
        } catch (IOException e) {
            log.error("Error reading indexStrategySelector template from filesystem {}", templateName);
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", templateName);
        }
    }
}
