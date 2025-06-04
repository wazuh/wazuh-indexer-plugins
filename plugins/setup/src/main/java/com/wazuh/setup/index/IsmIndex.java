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
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexTemplateUtils;

/** Class to manage the Command Manager index and index template. */
public class IsmIndex {

    private static final Logger log = LogManager.getLogger(IsmIndex.class);

    private final Client client;
    private final ClusterState clusterState;
    public static Map<String, Object> POLICY;
    public static final String ISM_INDEX = ".opendistro-ism-config";
    public static final String ISM_TEMPLATE = "opendistro-ism-config.json";

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterState OpenSearch cluster state.
     */
    public IsmIndex(Client client, ClusterState clusterState) {
        this.client = client;
        this.clusterState = clusterState;
    }

    /**
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean ismIndexExists() {
        return this.clusterState.routingTable().hasIndex(ISM_INDEX);
    }

    /**
     * Indexes the Wazuh rollover policy into the .opendistro-ism-config index. If the index does not
     * exist, it will create it.
     */
    public void indexPolicy() {
        this.createIsmIndex();

        try {
            POLICY = IndexTemplateUtils.fromFile(SetupPlugin.POLICY_ID + ".json");
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
            return;
        }

        IndexRequest indexRequest =
                new IndexRequest(ISM_INDEX)
                        .index(ISM_INDEX)
                        .id(SetupPlugin.POLICY_ID)
                        .source(POLICY, MediaTypeRegistry.JSON);

        client.index(
                indexRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        if (indexResponse.getResult() == Result.CREATED
                                || indexResponse.getResult() == Result.UPDATED) {
                            log.info("Successfully indexed Wazuh rollover policy into {} index", ISM_INDEX);
                        } else {
                            log.error(
                                    "Failed to index Wazuh rollover policy into {} index: {}",
                                    ISM_INDEX,
                                    indexResponse.getResult());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                "Failed to index Wazuh rollover policy into {} index: {}",
                                ISM_INDEX,
                                e.getMessage());
                    }
                });
    }

    /** Puts the .opendistro-ism-config template into the cluster and creates the index */
    public void createIsmIndex() {
        if (ismIndexExists()) {
            log.info("{} Index exists, skipping", ISM_INDEX);
            return;
        }
        Map<String, Object> template;
        log.info("Attempting to create {} index", ISM_INDEX);
        try {
            template = IndexTemplateUtils.fromFile(ISM_TEMPLATE);
            client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(ISM_INDEX)
                                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                                    .settings(IndexTemplateUtils.get(template, "settings")),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(CreateIndexResponse createIndexResponse) {
                                    if (createIndexResponse.isAcknowledged()) {
                                        log.info("Successfully created {} index", ISM_INDEX);
                                    } else {
                                        log.error("Failed to create {} index", ISM_INDEX);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error("Failed to create {} index: {}", ISM_INDEX, e.getMessage());
                                }
                            });
            log.info("Successfully created {} index", ISM_INDEX);
        } catch (IOException e) {
            log.error("Failed loading ISM index template from file: {}", e.getMessage());
        }
    }
}
