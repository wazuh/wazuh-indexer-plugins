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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.shard.IndexingOperationListener;

import java.io.IOException;

/** Class to manage the Command Manager index and index template. */
public class PolicyIndex implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(PolicyIndex.class);

    private final Client client;
    private final ClusterService clusterService;

    private final String ISM_INDEX = ".opendistro-ism-config";

    private final String POLICY_ID = "wazuh_rollover_policy";
    public final String POLICY =
            String.format(
                    // TO TEST
                    "{\"policy\":{\"policy_id\":\"wazuh_rollover_policy\",\"description\":\"Wazuh rollover and alias policy\",\"last_updated_time\":1738255639727,\"schema_version\":21,\"error_notification\":null,\"default_state\":\"active\",\"states\":[{\"name\":\"active\",\"actions\":[{\"retry\":{\"count\":3,\"backoff\":\"exponential\",\"delay\":\"1m\"},\"rollover\":{\"min_doc_count\":2,\"min_index_age\":\"1m\",\"min_primary_shard_size\":\"25gb\",\"copy_alias\":false}}],\"transitions\":[]}],\"ism_template\":[{\"index_patterns\":[\"wazuh-commands*\",\"wazuh-alerts*\"],\"priority\":50,\"last_updated_time\":1738255639727}],\"user\":{\"name\":\"admin\",\"backend_roles\":[\"admin\"],\"roles\":[\"own_index\",\"all_access\"],\"custom_attribute_names\":[],\"user_requested_tenant\":null}}}",
                    // OF DEVOPS
                    //    "{\"policy\":{\"policy_id\":\"wazuh_rollover_policy\",\"description\":\"Wazuh
                    // rollover and alias
                    // policy\",\"last_updated_time\":1738255639727,\"schema_version\":21,\"error_notification\":null,\"default_state\":\"active\",\"states\":[{\"name\":\"active\",\"actions\":[{\"retry\":{\"count\":3,\"backoff\":\"exponential\",\"delay\":\"1m\"},\"rollover\":{\"min_doc_count\":200000000,\"min_index_age\":\"7d\",\"min_primary_shard_size\":\"25gb\",\"copy_alias\":false}}],\"transitions\":[]}],\"ism_template\":[{\"index_patterns\":[\"wazuh-commands*\",\"wazuh-alerts*\"],\"priority\":50,\"last_updated_time\":1738255639727}],\"user\":{\"name\":\"admin\",\"backend_roles\":[\"admin\"],\"roles\":[\"own_index\",\"all_access\"],\"custom_attribute_names\":[],\"user_requested_tenant\":null}}}",
                    POLICY_ID);

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     */
    public PolicyIndex(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /**
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(ISM_INDEX);
    }

    /** Indexes an array of documents asynchronously. */
    public void indexPolicy() {
        try {
            log.info("Previous insert policy ");
            final IndexResponse indexResponse =
                    this.client.index(createIndexRequest("wazuh_rollover_policy", POLICY)).actionGet();
            // future.complete(indexResponse);
            log.info("Successfully indexing policy: {}", indexResponse.status().getStatus());
        } catch (Exception e) {
            log.error("Error indexing policy {}", e.getMessage());
        }
    }

    /**
     * Create an IndexRequest object from a Document object.
     *
     * @param document the document to create the IndexRequest for COMMAND_MANAGER_INDEX
     * @return an IndexRequest object
     * @throws IOException thrown by XContentFactory.jsonBuilder()
     */
    private IndexRequest createIndexRequest(String id, String document) throws IOException {
        return new IndexRequest()
                .index(ISM_INDEX)
                .source(document, MediaTypeRegistry.JSON)
                .id(id)
                .create(true);
    }
}
