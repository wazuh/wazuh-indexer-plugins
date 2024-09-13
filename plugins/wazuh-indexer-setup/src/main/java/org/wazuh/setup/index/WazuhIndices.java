/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;

import org.wazuh.setup.utils.IndexTemplateUtils;

import java.io.IOException;
import java.util.*;

/**
 * This class contains the logic to create the index templates and the indices
 * required by Wazuh.
 */
public class WazuhIndices {
    private static final Logger log = LogManager.getLogger(WazuhIndices.class);

    private final Client client;
    private final ClusterService clusterService;

    /**
     * | Key                 | value      |
     * | ------------------- | ---------- |
     * | Index template name | index name |
     */
    public final Map<String, String> indexTemplates = new HashMap<>();

    /**
     * Constructor
     *
     * @param client         Client
     * @param clusterService ClusterService
     */
    public WazuhIndices(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;

        // Create Index Templates - Indices map
        this.indexTemplates.put("index-template-agent", ".agents");
        this.indexTemplates.put("index-template-alerts", "wazuh-alerts-5.x-0001");
        this.indexTemplates.put("index-template-processes", "wazuh-states-inventory-processes");
        this.indexTemplates.put("index-template-packages", "wazuh-states-inventory-packages");
    }

    /**
     * Inserts an index template
     *
     * @param templateName: The name if the index template to load
     */
    public void putTemplate(String templateName) {
        try {
            // @throws IOException
            Map<String, Object> template = IndexTemplateUtils.fromFile(templateName + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest = new PutIndexTemplateRequest()
                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                    .settings(IndexTemplateUtils.get(template, "settings"))
                    .name(templateName)
                    .patterns((List<String>) template.get("index_patterns"));

            AcknowledgedResponse createIndexTemplateResponse = this.client
                    .admin()
                    .indices()
                    .putTemplate(putIndexTemplateRequest)
                    .actionGet();

            log.info(
                    "Index template created successfully: {} {}",
                    templateName,
                    createIndexTemplateResponse.isAcknowledged()
            );

        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", templateName);
        }
    }

    /**
     * Creates an index
     *
     * @param indexName: Name of the index to be created
     */
    public void putIndex(String indexName) {
        if (!indexExists(indexName)) {
            CreateIndexRequest request = new CreateIndexRequest(indexName);
            CreateIndexResponse createIndexResponse = this.client
                    .admin()
                    .indices()
                    .create(request)
                    .actionGet();
            log.info(
                    "Index created successfully: {} {}",
                    createIndexResponse.index(),
                    createIndexResponse.isAcknowledged()
            );
        }
    }

    /**
     * Returns whether the index exists
     *
     * @param indexName the name of the index to check
     * @return true of the index exists on the cluster, false otherwise
     */
    public boolean indexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    /**
     * Creates each index template and index in {@link #indexTemplates}.
     */
    public void initialize() {
        // 1. Read index templates from files
        // 2. Upsert index template
        // 3. Create index
        this.indexTemplates.forEach((k, v) -> {
            this.putTemplate(k);
            this.putIndex(v);
        });
    }
}
