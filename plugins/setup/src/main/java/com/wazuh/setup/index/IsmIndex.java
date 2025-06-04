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

import com.wazuh.setup.SetupPlugin;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

import com.wazuh.setup.utils.IndexTemplateUtils;

/** Class to manage the Command Manager index and index template. */
public class ISMIndex {

    private static final Logger log = LogManager.getLogger(ISMIndex.class);

    private final Client client;
    private final ClusterService clusterService;
    public static BytesArray POLICY;
    public static final String ISM_INDEX = ".opendistro-ism-config";
    public static final String ISM_TEMPLATE = "opendistro-ism-config.json";

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     */
    public ISMIndex(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        try {
            POLICY =
                    new BytesArray(
                            Objects.requireNonNull(
                                            ISMIndex.class.getClassLoader().getResourceAsStream(
                                                SetupPlugin.POLICY_ID + ".json"))
                                    .readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean iSMIndexExists() {
        return this.clusterService.state().routingTable().hasIndex(ISM_INDEX);
    }

    /**
     * Indexes the Wazuh rollover policy into the .opendistro-ism-config index. If the index does not
     * exist, it will create it.
     */
    public void indexPolicy() {
        IndexRequest indexRequest =
                new IndexRequest(ISM_INDEX)
                        .index(ISM_INDEX)
                        .id(SetupPlugin.POLICY_ID)
                        .source(POLICY, MediaTypeRegistry.JSON);

        if (!(client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT).getResult()
                == Result.CREATED)) {
            log.error("Failed to index the Wazuh rollover policy into the {} index", ISM_INDEX);
        }
    }

    /** Puts the .opendistro-ism-config template into the cluster and creates the index */
    public void putISMTemplate() {
        if (iSMIndexExists()) {
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
                                    .settings(IndexTemplateUtils.get(template, "settings"))
                    )
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("Successfully created {} index", ISM_INDEX);
        } catch (IOException e) {
            log.error("Failed loading ISM index template from file: {}", e.getMessage());
        }
    }
}
