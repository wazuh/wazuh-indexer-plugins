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
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

/**
 * Abstract class with the required logic to create indices. In our context, an index always require
 * an index template describing the index schema (mappings) and settings.
 *
 * @see IndexInitializer
 */
public abstract class Index implements IndexInitializer {
    private static final Logger log = LogManager.getLogger(Index.class);

    // Dependencies.
    Client client;
    ClusterService clusterService;
    IndexUtils indexUtils;

    // Properties.
    String index;
    String template;

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    Index(String index, String template) {
        this.index = index;
        this.template = template;
    }

    /**
     * Sets the OpenSearch client.
     *
     * @param client OpenSearch client.
     */
    public void setClient(Client client) {
        this.client = client;
    }

    /**
     * Sets the ClusterService.
     *
     * @param clusterService OpenSearch ClusterService.
     */
    public void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    /**
     * Sets the IndexUtils instance.
     *
     * @param indexUtils the IndexUtils instance to set.
     */
    public void setIndexUtils(IndexUtils indexUtils) {
        this.indexUtils = indexUtils;
    }

    /**
     * Returns whether the index exists.
     *
     * @param indexName the name of the index to check.
     * @return true if the index exists on the cluster, false otherwise.
     */
    public boolean indexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    /**
     * Creates an index.
     *
     * @param index Name of the index to create.
     * @return true if the index was correctly created or already existed, and false otherwise.
     */
    public boolean createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                CreateIndexRequest request = new CreateIndexRequest(index);
                CreateIndexResponse createIndexResponse =
                        this.client.admin().indices().create(request).actionGet(SetupPlugin.TIMEOUT);
                log.info(
                        "Index created successfully: {} {}",
                        createIndexResponse.index(),
                        createIndexResponse.isAcknowledged());
                return true;
            }
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index {} already exists. Skipping.", index);
            return true;
        }
        return false;
    }

    /**
     * Creates an index template.
     *
     * @param template name of the index template to create.
     * @return true if the template was correctly created or already existed, and false otherwise.
     */
    public boolean createTemplate(String template) {
        try {
            Map<String, Object> templateFile = this.indexUtils.fromFile(template + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(this.indexUtils.get(templateFile, "mappings"))
                            .settings(this.indexUtils.get(templateFile, "settings"))
                            .name(template)
                            .patterns((List<String>) templateFile.get("index_patterns"));

            AcknowledgedResponse createIndexTemplateResponse =
                    this.client
                            .admin()
                            .indices()
                            .putTemplate(putIndexTemplateRequest)
                            .actionGet(SetupPlugin.TIMEOUT);

            log.info(
                    "Index template created successfully: {} {}",
                    template,
                    createIndexTemplateResponse.isAcknowledged());
        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", template);
            return false;
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", template);
        }
        return true;
    }

    /**
     * Initializes the index. Usually implies invoking {@link #createTemplate(String)} and {@link
     * #createIndex(String)}, in that order.
     *
     * @return true if the index and the template are correctly created, and false otherwise.
     */
    public boolean initialize() {
        boolean templateCreated = this.createTemplate(this.template);
        boolean indexCreated = this.createIndex(this.index);

        return templateCreated && indexCreated;
    }

    /**
     * Retrieves the current value of the index.
     *
     * @return the index as a {@link String}
     */
    public String getIndex() {
        return index;
    }
}
