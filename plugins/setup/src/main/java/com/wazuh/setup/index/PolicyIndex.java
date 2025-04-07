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
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.shard.IndexingOperationListener;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

/** Class to manage the Command Manager index and index template. */
public class PolicyIndex implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(PolicyIndex.class);

    private final Client client;
    private final ClusterService clusterService;
    private final String POLICY_ID = "wazuh_rollover_policy";

    private final String ISM_INDEX = ".opendistro-ism-config";

    public final BytesArray POLICY;

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     */
    public PolicyIndex(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        try {
            POLICY =
                    new BytesArray(
                            Objects.requireNonNull(
                                            PolicyIndex.class.getClassLoader().getResourceAsStream(POLICY_ID + ".json"))
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
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(ISM_INDEX);
    }

    private void updateCreatedAt() {
        long timestamp = Instant.now().toEpochMilli();
        try (XContentBuilder xContentBuilder = XContentFactory.jsonBuilder()) {
            client.update(
                    new UpdateRequest(ISM_INDEX, POLICY_ID)
                            .doc(
                                    xContentBuilder
                                            .startObject()
                                            .startObject("policy")
                                            .startArray("ism_template")
                                            .startObject()
                                            .timeField("last_updated_time", timestamp)
                                            .endObject()
                                            .endArray()
                                            .timeField("last_updated_time", timestamp)
                                            .endObject()
                                            .endObject()),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(UpdateResponse updateResponse) {
                            log.info("Successfully updated created_at field");
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(
                                    "Failed to update created_at field for user id {}: {}",
                                    POLICY_ID,
                                    e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to create JSON object: {}", e.getMessage());
        }
    }

    /** Indexes an array of documents asynchronously. */
    public void indexPolicy() {

        IndexRequest indexRequest =
                new IndexRequest(ISM_INDEX)
                        .index(ISM_INDEX)
                        .id(POLICY_ID)
                        .source(POLICY, MediaTypeRegistry.JSON)
                        .create(true);

        client.index(
                indexRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Successfully indexed Wazuh Rollover Policy");
                        updateCreatedAt();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to index Wazuh Rollover Policy: {}", e.getMessage());
                    }
                });
    }
}
