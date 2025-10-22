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

import com.wazuh.setup.settings.PluginSettings;
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

    boolean retry_index_creation;
    boolean retry_template_creation;

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    Index(String index, String template) {
        this.index = index;
        this.template = template;

        this.retry_index_creation = true;
        this.retry_template_creation = true;
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
     */
    public void createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                CreateIndexRequest request = new CreateIndexRequest(index);
                CreateIndexResponse createIndexResponse =
                        this.client
                                .admin()
                                .indices()
                                .create(request)
                                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
                log.info(
                        "Index created successfully: {} {}",
                        createIndexResponse.index(),
                        createIndexResponse.isAcknowledged());
            }
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index {} already exists. Skipping.", index);
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (!this.retry_index_creation) {
                log.error("Initialization of index [{}] finally failed. The node will shut down.", index);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", index);
            this.retry_index_creation = false;
            this.indexUtils.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /**
     * Creates an index template.
     *
     * @param template name of the index template to create.
     */
    public void createTemplate(String template) {
        try {
            Map<String, Object> templateFile = this.indexUtils.fromFile(template + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(this.indexUtils.get(templateFile, "mappings"))
                            .settings(this.indexUtils.get(templateFile, "settings"))
                            .order((int) templateFile.get("order"))
                            .name(template)
                            .patterns((List<String>) templateFile.get("index_patterns"));

            AcknowledgedResponse createIndexTemplateResponse =
                    this.client
                            .admin()
                            .indices()
                            .putTemplate(putIndexTemplateRequest)
                            .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));

            log.info(
                    "Index template created successfully: {} {}",
                    template,
                    createIndexTemplateResponse.isAcknowledged());

        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", template);
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", template);
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index template also failed. Original exception is
            // rethrown.
            if (!this.retry_template_creation) {
                log.error(
                        "Initialization of index template [{}] finally failed. The node will shut down.",
                        template);
                throw e;
            }
            log.warn("Operation to create the index template [{}] timed out. Retrying...", template);
            this.retry_template_creation = false;
            this.indexUtils.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createTemplate(template);
        }
    }

    /**
     * Initializes the index. Usually implies invoking {@link #createTemplate(String)} and {@link
     * #createIndex(String)}, in that order.
     */
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
    }
}
